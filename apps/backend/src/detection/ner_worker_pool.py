"""Bounded, persistent NER workers with process-level cancellation.

Each slot owns one spawn process and runs one request at a time. Successful
requests reuse the slot's tokenizer and ONNX session. Timeout, cancellation,
worker failure and a configurable task-count limit retire the process. No
replacement starts until the old process has been joined. Queue wait and
cold initialization consume the original submit-time deadline.
"""

from __future__ import annotations

import math
import multiprocessing
from multiprocessing.util import Finalize
import threading
import time
import weakref
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from detection.inference_executor import _JOIN_TIMEOUT, _POLL_SLICE
from detection.ner_model import model_manifest_digest
from detection.ner_runtime import NerBatchResult, create_ner_runtime
from detection.ner_snapshot import SealedNerSnapshot
from detection.ner_windowing import DEFAULT_STRIDE, DEFAULT_WINDOW_LENGTH
from infra.errors import SafetyCode, SafetyError

_LIVE_POOLS = weakref.WeakSet()
_POOL_REGISTRY_LOCK = threading.Lock()


def _close_live_pools():
    with _POOL_REGISTRY_LOCK:
        pools = tuple(_LIVE_POOLS)
    for pool in pools:
        try:
            pool.close()
        except RuntimeError:
            # Continue releasing other pools even if one cleanup fails.
            pass


# Run before multiprocessing joins children: an idle persistent worker waits
# for another request indefinitely unless its owning pool is closed first.
Finalize(None, _close_live_pools, exitpriority=50)


def _error_frame(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, SafetyError):
        return "safety_error", exc.code.value
    return "error", type(exc).__name__


def _worker_loop(conn, factory: Callable, factory_args: tuple, sealed: bool) -> None:
    """Only sanitized error codes/types cross the pipe; never tracebacks."""
    snapshot = None
    try:
        try:
            if sealed:
                snapshot = SealedNerSnapshot.receive(conn, factory_args[3])
                factory_args = (snapshot, *factory_args[1:])
            runtime = factory(*factory_args)
            warmup = getattr(runtime, 'warmup', None)
            if warmup is not None:
                warmup()
            conn.send(("ready", runtime.initialization_metrics))
        except BaseException as exc:
            conn.send(_error_frame(exc))
            return
        while True:
            try:
                job_id, texts, digest, profile = conn.recv()
            except (EOFError, OSError):
                return
            try:
                result = runtime.run(texts, digest, profile)
            except BaseException as exc:
                conn.send((job_id, *_error_frame(exc)))
                return  # failed native/runtime state is never reused
            else:
                conn.send((job_id, "ok", result))
            finally:
                # Release request objects before waiting for the next job.
                texts = None
                result = None
    except (EOFError, OSError):
        pass
    finally:
        conn.close()
        if snapshot is not None:
            snapshot.close()


@dataclass(eq=False)
class _Job:
    job_id: int
    texts: tuple[str, ...]
    digest: str
    submitted_at: float
    deadline: float
    cancel: Any
    profile: bool
    warmup: bool = False
    done: threading.Event = field(default_factory=threading.Event)
    result: NerBatchResult | None = None
    error: BaseException | None = None

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline or (self.cancel is not None and self.cancel.is_set())


@dataclass
class _Slot:
    job: _Job | None = None
    proc: Any = None
    conn: Any = None
    generation: int = 0
    completed: int = 0
    started_at: float = 0.0
    batch: tuple = ()
    reap_lock: threading.Lock = field(default_factory=threading.Lock)


class NerWorkerPool:
    """One artifact version, bounded active slots and bounded waiting jobs.

    Workers initialize lazily on first use, within the job budget. A pool is
    pinned to its first submitted manifest; release changes require a new
    pool. ``max_tasks_per_worker`` bounds the lifetime of native allocations.
    ``runtime_factory`` is an explicit spawn-safe test seam, not user input.
    """

    def __init__(self, package_dir: str, *, max_workers: int = 1, max_pending: int = 4,
                 window_length: int = DEFAULT_WINDOW_LENGTH, stride: int = DEFAULT_STRIDE,
                 max_tasks_per_worker: int = 8192, intra_op_threads: int | None = None,
                 max_age_seconds: int = 3600, max_rss_kib: int = 0,
                 batch_wait_ms: int = 2, max_batch_jobs: int = 8,
                 max_batch_chars: int = 2048, batch_tokens: int = 4096,
                 sentence_boundaries: bool = False,
                 mp_context=None, runtime_factory: Callable = create_ner_runtime) -> None:
        for name, value, minimum in (("max_workers", max_workers, 1), ("max_pending", max_pending, 0),
                                   ("max_tasks_per_worker", max_tasks_per_worker, 1),
                                   ('max_age_seconds', max_age_seconds, 1), ('max_rss_kib', max_rss_kib, 0),
                                   ('batch_wait_ms', batch_wait_ms, 0), ('max_batch_jobs', max_batch_jobs, 1),
                                   ('max_batch_chars', max_batch_chars, 1), ('batch_tokens', batch_tokens, 1)):
            if type(value) is not int:
                raise TypeError(f"{name} must be an int")
            if value < minimum:
                raise ValueError(f"{name} must be >= {minimum}")
        if intra_op_threads is not None and (type(intra_op_threads) is not int or intra_op_threads < 1):
            raise ValueError("intra_op_threads must be a positive int")
        if type(window_length) is not int or type(stride) is not int:
            raise TypeError("window_length and stride must be ints")
        if not callable(runtime_factory):
            raise TypeError("runtime_factory must be callable")
        capacity = window_length - 2
        if capacity < 1 or not 1 <= stride <= capacity or (capacity - stride) % 2:
            raise ValueError("invalid window geometry")
        if batch_tokens < window_length or type(sentence_boundaries) is not bool:
            raise ValueError('invalid batch/window options')
        self._max_workers = max_workers
        self._max_pending = max_pending
        self._max_tasks_per_worker = max_tasks_per_worker
        self._factory = runtime_factory
        self._factory_args = (str(package_dir), window_length, stride)
        self._intra_op_threads = intra_op_threads
        self._max_age_seconds, self._max_rss_kib = max_age_seconds, max_rss_kib
        self._batch_wait_ms, self._max_batch_jobs = batch_wait_ms, max_batch_jobs
        self._max_batch_chars = max_batch_chars
        self._runtime_options = {'batch_tokens': batch_tokens, 'sentence_boundaries': sentence_boundaries}
        self._sealed = runtime_factory is create_ner_runtime
        self._artifact = None
        self._artifact_lock = threading.Lock()
        self._package_dir = str(package_dir)
        self._digest: str | None = None
        self._mp = mp_context or multiprocessing.get_context("spawn")
        self._condition = threading.Condition()
        self._pending: deque[_Job] = deque()
        self._slots = [_Slot() for _ in range(max_workers)]
        self._closed = False
        self._sequence = 0
        self._threads = [threading.Thread(target=self._slot_loop, args=(slot,),
                        name=f"ner-worker-slot-{index}", daemon=True)
                         for index, slot in enumerate(self._slots)]
        for thread in self._threads:
            thread.start()
        with _POOL_REGISTRY_LOCK:
            _LIVE_POOLS.add(self)

    @property
    def max_workers(self) -> int:
        return self._max_workers

    @property
    def max_pending(self) -> int:
        return self._max_pending

    def snapshot(self) -> tuple[int, int]:
        with self._condition:
            return sum(slot.job is not None for slot in self._slots), len(self._pending)

    def worker_pids(self) -> tuple[int, ...]:
        """Local diagnostics only; include idle persistent workers."""
        with self._condition:
            pids = []
            for slot in self._slots:
                if slot.proc is not None:
                    try:
                        pids.append(slot.proc.pid)
                    except ValueError:
                        pass
            return tuple(pids)

    def _artifact_snapshot(self, deadline, cancel=None):
        def check():
            if self._closed or time.monotonic() >= deadline or (cancel is not None and cancel.is_set()):
                raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        while not self._artifact_lock.acquire(timeout=_POLL_SLICE):
            check()
        try:
            check()
            if self._artifact is None:
                self._artifact = SealedNerSnapshot.create(self._package_dir, check=check)
                self._digest = self._artifact.digest
            return self._artifact
        finally:
            self._artifact_lock.release()

    def artifact_fingerprint(self):
        return self._artifact_snapshot(time.monotonic() + 120).fingerprint()

    def warmup(self, *, timeout=120):
        """Initialize and forward-warm every slot, including idle slots."""
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('invalid warmup timeout')
        deadline = time.monotonic() + timeout
        digest = (self._artifact_snapshot(deadline).digest if self._sealed
                  else model_manifest_digest(self._package_dir))
        jobs = []
        with self._condition:
            if self._closed:
                raise TypeError('executor is closed')
            if any(slot.job is not None for slot in self._slots):
                raise RuntimeError('warmup requires idle slots')
            self._digest = digest
            for slot in self._slots:
                if slot.proc is None or not slot.proc.is_alive():
                    self._sequence += 1
                    job = _Job(self._sequence, (), digest, time.monotonic(), deadline, None, True, warmup=True)
                    slot.job = job
                    jobs.append(job)
            self._condition.notify_all()
        for job in jobs:
            job.done.wait(max(0, deadline - time.monotonic()) + _JOIN_TIMEOUT * 2 + 1)
            if not job.done.is_set():
                raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
            if job.error is not None:
                raise job.error
        return tuple(job.result.metrics for job in jobs)

    def infer(self, texts: tuple[str, ...], *, timeout: float, cancel=None):
        return self.infer_profiled(texts, timeout=timeout, cancel=cancel, profile=False).results

    def infer_profiled(self, texts: tuple[str, ...], *, timeout: float, cancel=None,
                       profile: bool = True) -> NerBatchResult:
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        if not isinstance(texts, tuple) or any(not isinstance(text, str) for text in texts):
            raise SafetyError(SafetyCode.INVALID_TEXT)
        submitted_at = time.monotonic()
        with self._condition:
            if self._closed:
                raise TypeError("executor is closed")
        digest = (self._artifact_snapshot(submitted_at + timeout, cancel).digest if self._sealed
                  else model_manifest_digest(self._package_dir))
        with self._condition:
            if self._closed:
                raise TypeError("executor is closed")
            if self._digest is not None and self._digest != digest:
                raise SafetyError(SafetyCode.NER_MODEL_INVALID, "manifest_version_changed")
            self._sequence += 1
            job = _Job(self._sequence, texts, digest, submitted_at, submitted_at + timeout, cancel, profile)
            if job.expired():
                raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
            idle = next((slot for slot in self._slots if slot.job is None), None)
            admitted = len(self._pending) + sum(len(slot.batch) if slot.batch else int(slot.job is not None)
                                               for slot in self._slots)
            if admitted >= self._max_workers + self._max_pending:
                raise SafetyError(SafetyCode.INFERENCE_QUEUE_FULL)
            if idle is None:
                if len(self._pending) >= self._max_pending:
                    raise SafetyError(SafetyCode.INFERENCE_QUEUE_FULL)
                self._pending.append(job)
            else:
                idle.job = job
            self._digest = digest
            self._condition.notify_all()
        while not job.done.wait(_POLL_SLICE):
            if job.expired():
                with self._condition:
                    if job in self._pending:
                        self._pending.remove(job)
                        self._finish(job, error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
                # Running jobs return only after the slot confirms process exit.
        if job.error is not None:
            raise job.error
        assert job.result is not None
        return job.result

    @staticmethod
    def _finish(job: _Job, *, result=None, error=None) -> None:
        job.result, job.error = result, error
        job.done.set()

    def _slot_loop(self, slot: _Slot) -> None:
        try:
            while True:
                with self._condition:
                    self._condition.wait_for(lambda: slot.job is not None or self._closed)
                    if slot.job is None:
                        return
                    job = slot.job
                result = error = None
                try:
                    result = self._run(slot, job)
                except BaseException as exc:
                    try:
                        self._retire(slot)
                    except BaseException:
                        # A failed reap cannot release the slot for a new
                        # process: stop admission and fail every waiter.
                        with self._condition:
                            self._closed = True
                            while self._pending:
                                self._finish(self._pending.popleft(), error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
                            self._condition.notify_all()
                    # Reconstruct, rather than retain a traceback containing texts.
                    if self._closed or job.expired():
                        error = SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                    else:
                        error = SafetyError(exc.code) if isinstance(exc, SafetyError) else RuntimeError("NER worker failed")
                finally:
                    # A deadline may expire after receipt while waiting for
                    # delivery. Reap before making that late outcome observable.
                    if error is None and (self._closed or job.expired()):
                        try:
                            self._retire(slot)
                        except BaseException:
                            with self._condition:
                                self._closed = True
                                while self._pending:
                                    self._finish(self._pending.popleft(), error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
                                self._condition.notify_all()
                            error = RuntimeError('NER worker did not terminate')
                        else:
                            error = SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                    with self._condition:
                        slot.job = None
                        while self._pending and not self._closed:
                            candidate = self._pending.popleft()
                            if candidate.expired():
                                self._finish(candidate, error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
                            else:
                                slot.job = candidate
                                break
                        if self._closed and error is None:
                            error = SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                        self._finish(job, result=result if error is None else None, error=error)
                        self._condition.notify_all()
                job = None
                result = None
        finally:
            self._retire(slot)

    def _await(self, slot: _Slot, job: _Job):
        conn = slot.conn
        while not self._closed and not job.expired():
            remaining = job.deadline - time.monotonic()
            try:
                if conn.poll(min(_POLL_SLICE, max(0, remaining))):
                    frame = conn.recv()
                    if self._closed or job.expired():
                        break
                    return frame
            except (EOFError, OSError, ValueError):
                break
        raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)

    @staticmethod
    def _raise_frame(status: str, payload) -> None:
        if status == "safety_error":
            try:
                code = SafetyCode(payload)
            except (ValueError, TypeError):
                code = SafetyCode.DETECTION_FAILED
            raise SafetyError(code)
        # Error payloads are deliberately not interpolated into parent errors.
        raise RuntimeError("NER worker task failed")

    def _start(self, slot: _Slot, job: _Job) -> dict[str, float]:
        parent_conn, child_conn = self._mp.Pipe(duplex=True)
        proc = self._mp.Process(target=_worker_loop,
                    args=(child_conn, self._factory, (*self._factory_args, job.digest,
                          self._intra_op_threads, self._runtime_options), self._sealed))
        try:
            # close() cannot miss a process which is still being started.
            with self._condition:
                if self._closed or job.expired():
                    raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                proc.start()
                slot.proc, slot.conn = proc, parent_conn
                slot.generation += 1
                slot.completed = 0
                slot.started_at = time.monotonic()
                if self._sealed:
                    self._artifact.send(parent_conn, proc.pid)
            child_conn.close()
        except BaseException:
            child_conn.close()
            parent_conn.close()
            if proc.pid is not None:
                self._reap_process(proc)
            else:
                proc.close()
            raise
        frame = self._await(slot, job)
        if not isinstance(frame, tuple) or len(frame) != 2:
            raise RuntimeError("invalid NER initialization frame")
        if frame[0] != "ready":
            self._raise_frame(*frame)
        return frame[1]

    def _run(self, slot: _Slot, job: _Job) -> NerBatchResult:
        started = time.monotonic()
        if self._closed or job.expired():
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        initialization = {}
        startup_ms = 0.0
        if slot.proc is not None and not slot.proc.is_alive():
            self._retire(slot)
        if slot.proc is None:
            initialization = self._start(slot, job)
            startup_ms = (time.monotonic() - started) * 1000
        slot.conn.send((job.job_id, job.texts, job.digest, job.profile))
        frame = self._await(slot, job)
        if not isinstance(frame, tuple) or len(frame) != 3 or frame[0] != job.job_id:
            raise RuntimeError("invalid NER task frame")
        if frame[1] != "ok":
            self._raise_frame(frame[1], frame[2])
        result = frame[2]
        if not isinstance(result, NerBatchResult) or len(result.results) != len(job.texts):
            raise RuntimeError("invalid NER task result")
        if job.expired() or self._closed:
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        metrics = dict(result.metrics)
        for key, value in initialization.items():
            metrics[key] = metrics.get(key, 0.0) + value
        metrics["queue_ms"] = (started - job.submitted_at) * 1000
        metrics["worker_startup_ms"] = startup_ms
        metrics["worker_generation"] = slot.generation
        metrics["ipc_ms"] = max(0.0, (time.monotonic() - started) * 1000 - startup_ms - metrics["worker_task_ms"])
        slot.completed += 0 if job.warmup else 1
        recycle_started = time.monotonic()
        index = self._slots.index(slot)
        task_limit = max(1, self._max_tasks_per_worker - index * self._max_tasks_per_worker // (20 * self._max_workers))
        if (slot.completed >= task_limit or time.monotonic() - slot.started_at >= self._max_age_seconds
                or (self._max_rss_kib and metrics.get('worker_peak_rss_kib', 0) >= self._max_rss_kib)):
            self._retire(slot)
        metrics["recycle_ms"] = (time.monotonic() - recycle_started) * 1000
        metrics["total_ms"] = (time.monotonic() - job.submitted_at) * 1000
        if job.expired() or self._closed:
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        return replace(result, metrics=metrics)

    def _retire(self, slot: _Slot) -> None:
        with slot.reap_lock:
            proc, conn = slot.proc, slot.conn
            if proc is not None:
                self._reap_process(proc)
            if conn is not None:
                conn.close()
            with self._condition:
                slot.proc = slot.conn = None

    @staticmethod
    def _reap_process(proc) -> None:
        if proc.is_alive():
            proc.terminate()
        proc.join(timeout=_JOIN_TIMEOUT)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=_JOIN_TIMEOUT)
        if proc.is_alive():
            raise RuntimeError("NER worker did not terminate")
        proc.close()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            while self._pending:
                self._finish(self._pending.popleft(), error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
            self._condition.notify_all()
        failure = None
        for slot in self._slots:
            try:
                self._retire(slot)
            except BaseException:
                failure = RuntimeError("NER worker did not terminate")
        for thread in self._threads:
            thread.join(timeout=_JOIN_TIMEOUT * 2 + 1)
        if failure is not None:
            raise failure
        if any(thread.is_alive() for thread in self._threads):
            raise RuntimeError("NER slot threads did not stop")
        with self._artifact_lock:
            if self._artifact is not None:
                self._artifact.close()
        with _POOL_REGISTRY_LOCK:
            _LIVE_POOLS.discard(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
