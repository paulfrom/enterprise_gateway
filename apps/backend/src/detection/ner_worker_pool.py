"""Bounded, persistent NER workers with process-level cancellation.

Each slot owns one spawn process and runs one bounded request batch at a time.
Requests reuse sealed model assets and the slot's tokenizer/ONNX session.
Timeout, cancellation, worker failure and lifetime limits retire the process. No
replacement starts until the old process has been joined. Queue wait and
cold initialization consume the original submit-time deadline.
"""

from __future__ import annotations

import math
import multiprocessing
from multiprocessing.util import Finalize
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from detection.inference_executor import _JOIN_TIMEOUT, _POLL_SLICE
from detection.ner_model import model_manifest_digest
from detection.ner_runtime import NerBatchResult, create_ner_runtime
from detection.ner_snapshot import SealedNerSnapshot
from detection.ner_windowing import DEFAULT_STRIDE, DEFAULT_WINDOW_LENGTH
from infra.errors import SafetyCode, SafetyError


def cpu_thread_budget():
    """Count visible physical cores, also honoring a cgroup-v2 CPU quota."""
    from pathlib import Path
    allowed = os.sched_getaffinity(0) if hasattr(os, 'sched_getaffinity') else None
    budget = len(allowed) if allowed else (os.cpu_count() or 1)
    try:
        cores = set()
        for block in Path('/proc/cpuinfo').read_text().split('\n\n'):
            fields = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
            fields = {name.strip(): value.strip() for name, value in fields.items()}
            processor = int(fields.get('processor', '-1'))
            if processor >= 0 and (allowed is None or processor in allowed):
                cores.add((fields.get('physical id', '0'), fields.get('core id', str(processor))))
        if cores:
            budget = len(cores)
        quota, period = Path('/sys/fs/cgroup/cpu.max').read_text().split()
        if quota != 'max':
            budget = min(budget, max(1, int(quota) // int(period)))
    except (OSError, ValueError):
        pass
    return max(1, budget)


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
    ready: bool = False
    next_warm_at: float = 0.0
    reap_lock: threading.Lock = field(default_factory=threading.Lock)


class _BatchCancellation:
    def __init__(self, jobs):
        self.jobs = jobs

    def is_set(self):
        return any(job.expired() for job in self.jobs)


class NerWorkerPool:
    """One artifact version, bounded active slots and bounded waiting jobs.

    The pool owns one kernel-sealed artifact version. Explicit startup warmup
    loads every slot; direct users can still initialize within a job budget.
    Lifetime limits bound native allocations. Short jobs can share a batch.
    ``runtime_factory`` is an explicit spawn-safe test seam, not user input.
    """

    def __init__(self, package_dir: str, *, max_workers: int = 1, max_pending: int = 4,
                 window_length: int = DEFAULT_WINDOW_LENGTH, stride: int = DEFAULT_STRIDE,
                 max_tasks_per_worker: int = 8192, intra_op_threads: int | None = None,
                 max_age_seconds: int = 3600, max_rss_kib: int = 2097152,
                 batch_wait_ms: int = 0, max_batch_jobs: int = 1,
                 max_batch_chars: int = 512, batch_tokens: int = 4096,
                 sentence_boundaries: bool = False,
                 sealed_snapshot: bool = True,
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
        if batch_tokens < window_length or type(sentence_boundaries) is not bool or type(sealed_snapshot) is not bool:
            raise ValueError('invalid batch/window options')
        self._max_workers = max_workers
        self._max_pending = max_pending
        self._max_tasks_per_worker = max_tasks_per_worker
        self._factory = runtime_factory
        self._factory_args = (str(package_dir), window_length, stride)
        self._intra_op_threads = (intra_op_threads if intra_op_threads is not None else
                                 max(1, cpu_thread_budget() // max_workers))
        self._max_age_seconds, self._max_rss_kib = max_age_seconds, max_rss_kib
        self._batch_wait_ms, self._max_batch_jobs = batch_wait_ms, max_batch_jobs
        self._max_batch_chars = max_batch_chars
        self._runtime_options = {'batch_tokens': batch_tokens, 'sentence_boundaries': sentence_boundaries}
        self._sealed = runtime_factory is create_ner_runtime and sealed_snapshot
        self._artifact = None
        self._artifact_creation_ms = 0.0
        self._artifact_creation_reported = False
        self._artifact_lock = threading.Lock()
        self._maintain = False
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
        # Run before multiprocessing's join of non-daemon children. This also
        # closes resources for embedded callers which omit explicit shutdown.
        self._exit_finalizer = Finalize(None, self.close, exitpriority=10)

    @property
    def max_workers(self) -> int:
        return self._max_workers

    @property
    def max_pending(self) -> int:
        return self._max_pending

    @property
    def ready(self):
        with self._condition:
            try:
                return not self._closed and all(slot.ready and slot.proc is not None
                                               and slot.proc.is_alive() for slot in self._slots)
            except ValueError:
                return False

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
                error = None
                started = time.perf_counter()
                try:
                    self._artifact = SealedNerSnapshot.create(self._package_dir, expected_digest=self._digest, check=check)
                except Exception as exc:
                    error = exc.code if isinstance(exc, SafetyError) else SafetyCode.NER_MODEL_INVALID
                if error is not None:
                    raise SafetyError(error, 'snapshot_creation_failed')
                self._artifact_creation_ms = (time.perf_counter() - started) * 1000
                self._digest = self._artifact.digest
            return self._artifact
        finally:
            self._artifact_lock.release()

    def artifact_fingerprint(self):
        if not self._sealed:
            from pathlib import Path
            import hashlib
            directory = Path(self._package_dir)
            return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in sorted(directory.rglob('*')) if path.is_file()}
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
        with self._condition:
            self._maintain = True
            self._condition.notify_all()
        if not self.ready:
            raise SafetyError(SafetyCode.DETECTION_FAILED)
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
        digest = (self._artifact.digest if self._sealed and self._artifact is not None
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
            if not self._can_run(job):
                idle = None
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

    def _short(self, job):
        return sum(map(len, job.texts)) <= self._max_batch_chars

    def _can_run(self, job):
        # With multiple workers, long requests can occupy at most W-1 slots.
        # A single worker cannot preempt a native forward pass.
        return (job.warmup or self._short(job) or self._max_workers == 1
                or sum(slot.job is not None and not slot.job.warmup and not self._short(slot.job)
                       for slot in self._slots) < self._max_workers - 1)

    def _take_pending(self):
        for job in tuple(self._pending):
            if job.expired():
                self._pending.remove(job)
                self._finish(job, error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
        eligible = [job for job in self._pending if self._can_run(job)]
        if not eligible:
            return None
        oldest = eligible[0]
        selected = (oldest if time.monotonic() - oldest.submitted_at >= 0.1 else
                    next((job for job in eligible if self._short(job)), oldest))
        self._pending.remove(selected)
        return selected

    def _task_limit(self, slot):
        index = self._slots.index(slot)
        return max(1, self._max_tasks_per_worker - index * self._max_tasks_per_worker // (20 * self._max_workers))

    def _collect_batch(self, slot, primary):
        jobs = [primary]
        chars = sum(map(len, primary.texts))
        until = min(primary.deadline, time.monotonic() + self._batch_wait_ms / 1000)
        with self._condition:
            limit = min(self._max_batch_jobs, self._task_limit(slot) - slot.completed)
            while not primary.warmup and self._short(primary) and not primary.expired() and not self._closed:
                for candidate in tuple(self._pending):
                    if candidate.expired():
                        self._pending.remove(candidate)
                        self._finish(candidate, error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
                        continue
                    length = sum(map(len, candidate.texts))
                    if len(jobs) < limit and chars + length <= self._max_batch_chars:
                        self._pending.remove(candidate)
                        jobs.append(candidate)
                        chars += length
                        until = min(until, candidate.deadline)
                slot.batch = tuple(jobs)
                remaining = until - time.monotonic()
                if remaining <= 0 or len(jobs) >= limit:
                    break
                self._condition.wait(remaining)
            slot.batch = tuple(jobs)
        return tuple(jobs)

    def _run_batch(self, slot, jobs):
        primary = jobs[0]
        combined = replace(primary, texts=tuple(text for job in jobs for text in job.texts),
                           deadline=min(job.deadline for job in jobs), cancel=_BatchCancellation(jobs),
                           profile=any(job.profile for job in jobs))
        result = self._run(slot, combined, task_count=len(jobs))
        cursor = 0
        results = []
        for job in jobs:
            metrics = dict(result.metrics)
            metrics['queue_ms'] += primary.submitted_at - job.submitted_at
            metrics['total_ms'] = (time.monotonic() - job.submitted_at) * 1000
            metrics['batch_requests'] = len(jobs)
            metrics['batch_fragments'] = len(combined.texts)
            results.append(replace(result, results=result.results[cursor:cursor + len(job.texts)], metrics=metrics))
            cursor += len(job.texts)
        return results

    def _slot_loop(self, slot: _Slot) -> None:
        try:
            while True:
                with self._condition:
                    while slot.job is None and not self._closed:
                        slot.job = self._take_pending()
                        now = time.monotonic()
                        needs_warm = (slot.proc is None or not slot.proc.is_alive()
                                      or now - slot.started_at >= self._max_age_seconds)
                        if slot.job is None and self._maintain and needs_warm and now >= slot.next_warm_at:
                            self._sequence += 1
                            slot.job = _Job(self._sequence, (), self._digest, now, now + 120,
                                            None, True, warmup=True)
                        if slot.job is None:
                            self._condition.wait(timeout=1)
                    if self._closed:
                        if slot.job is not None:
                            self._finish(slot.job, error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
                            slot.job = None
                        return
                    primary = slot.job
                jobs = self._collect_batch(slot, primary)
                results = error = None
                try:
                    results = self._run_batch(slot, jobs)
                except BaseException as exc:
                    try:
                        self._retire(slot)
                    except BaseException:
                        with self._condition:
                            self._closed = True
                            while self._pending:
                                self._finish(self._pending.popleft(), error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
                            self._condition.notify_all()
                    # Never retain exception messages/tracebacks containing text.
                    error = (SafetyError(SafetyCode.INFERENCE_TIMEOUT) if self._closed or any(j.expired() for j in jobs)
                             else SafetyError(exc.code) if isinstance(exc, SafetyError)
                             else RuntimeError('NER worker failed'))
                    slot.next_warm_at = time.monotonic() + 5
                finally:
                    if error is None and (self._closed or any(j.expired() for j in jobs)):
                        try:
                            self._retire(slot)
                        except BaseException:
                            with self._condition:
                                self._closed = True
                                while self._pending:
                                    self._finish(self._pending.popleft(), error=SafetyError(SafetyCode.INFERENCE_TIMEOUT))
                        error = SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                    # Commit under the reap lock: close/deadline races cannot
                    # expose a failed result before process exit is confirmed.
                    with slot.reap_lock:
                        with self._condition:
                            if error is None and (self._closed or any(j.expired() for j in jobs)):
                                try:
                                    self._retire_locked(slot)
                                except BaseException:
                                    self._closed = True
                                error = SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                            slot.job = None
                            slot.batch = ()
                            for index, job in enumerate(jobs):
                                self._finish(job, result=results[index] if error is None else None,
                                             error=(SafetyError(error.code) if isinstance(error, SafetyError)
                                                    else RuntimeError('NER worker failed') if error is not None else None))
                            self._condition.notify_all()
                jobs = primary = results = job = error = None
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
        if self._sealed:
            self._artifact_snapshot(job.deadline, job.cancel)
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
            with slot.reap_lock:
                if slot.proc is proc:
                    self._retire_locked(slot)
                else:
                    parent_conn.close()
                    # close() may already have reaped a registered process.
                    if not getattr(proc, '_closed', False):
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
        slot.ready = True
        return frame[1]

    def _run(self, slot: _Slot, job: _Job, *, task_count=1) -> NerBatchResult:
        started = time.monotonic()
        if self._closed or job.expired():
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        initialization = {}
        startup_ms = 0.0
        if slot.proc is not None and (not slot.proc.is_alive() or time.monotonic() - slot.started_at >= self._max_age_seconds):
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
        with self._condition:
            if startup_ms and not self._artifact_creation_reported:
                metrics['artifact_snapshot_ms'] = self._artifact_creation_ms
                self._artifact_creation_reported = True
        metrics["worker_generation"] = slot.generation
        metrics['batch_id'] = job.job_id
        metrics['artifact_snapshot_bytes'] = self._artifact.allocated_bytes if self._artifact is not None else 0
        metrics["ipc_ms"] = max(0.0, (time.monotonic() - started) * 1000 - startup_ms - metrics["worker_task_ms"])
        slot.completed += 0 if job.warmup else task_count
        recycle_started = time.monotonic()
        if (slot.completed >= self._task_limit(slot) or time.monotonic() - slot.started_at >= self._max_age_seconds
                or (self._max_rss_kib and metrics.get('worker_peak_rss_kib', 0) >= self._max_rss_kib)):
            self._retire(slot)
        metrics["recycle_ms"] = (time.monotonic() - recycle_started) * 1000
        metrics["total_ms"] = (time.monotonic() - job.submitted_at) * 1000
        if job.expired() or self._closed:
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        return replace(result, metrics=metrics)

    def _retire(self, slot: _Slot) -> None:
        with slot.reap_lock:
            self._retire_locked(slot)

    def _retire_locked(self, slot):
        proc, conn = slot.proc, slot.conn
        if proc is not None:
            self._reap_process(proc)
        if conn is not None:
            conn.close()
        with self._condition:
            slot.proc = slot.conn = None
            slot.ready = False
            slot.completed = 0
            slot.started_at = 0.0

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
        self._exit_finalizer.cancel()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
