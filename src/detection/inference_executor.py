"""D-10 bounded inference executor: process-isolated, time-budgeted execution.

Native inference runtimes (e.g. onnxruntime ``session.run``) cannot be
reliably interrupted from a thread, so the unit of compute isolation is a
dedicated worker *process* per call. The caller-facing contract is:

- Bounded concurrency: at most ``max_workers`` worker processes exist at any
  moment (default 1), each driven by one slot thread.
- Bounded pending queue: at most ``max_pending`` accepted calls wait for a
  slot. A ``submit`` that would exceed the queue raises
  ``SafetyError(INFERENCE_QUEUE_FULL)`` immediately — calls never pile up.
- Per-call time budget: ``submit(func, *args, timeout=...)`` blocks until the
  result arrives or the budget expires. The budget covers queue wait, worker
  startup, and execution. On expiry the worker process is actually
  terminated (compute slot reclaimed) and the next call spawns a fresh
  worker.
- Bounded background resources: ``max_workers`` slot threads plus at most
  ``max_workers`` worker processes. ``close()`` terminates every live
  worker, rejects all queued/running waiters with
  ``SafetyError(INFERENCE_TIMEOUT)``, joins the slot threads, and leaves no
  residual process or thread — every worker is ``join``-confirmed exited and
  every handle held by the executor is released. (On Windows a reaped
  worker's pid can stay openable to ``OpenProcess`` for a while; that is OS
  teardown outside user-mode control, not a live worker — poll the pid to
  observe disappearance.) ``submit`` after ``close()`` raises
  ``TypeError("executor is closed")``.
- Controlled failure propagation: an exception raised inside the worker
  comes back with the exception chain broken and no business text. A
  ``SafetyError`` keeps only its registered ``SafetyCode`` (detail is
  dropped); any other exception surfaces as ``RuntimeError("inference task
  failed: <exception type name>")``.

Portability: the multiprocessing **spawn** context is used on every platform
(Windows and Linux semantics stay identical). Spawn requires the work
function and its arguments to be picklable — i.e. defined at module top
level, not closures or lambdas. Tasks are rejected in two distinct ways:

- Not picklable at all: caught by a pre-spawn ``pickle.dumps`` check —
  ``submit`` raises ``TypeError`` and **no worker process is created**.
- Picklable but not reconstructible in the child (e.g. the function's
  module is not importable in the worker): the worker dies during spawn
  bootstrap, sends no outcome frame, and the failure surfaces as
  ``SafetyError(INFERENCE_TIMEOUT)`` — from the parent's pipe it is
  indistinguishable from a hang. The bootstrap traceback is only visible on
  the child's stderr.

This executor is generic: it is not bound to NER or any other detector.
"""

from __future__ import annotations

import multiprocessing
import pickle
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from infra.errors import SafetyCode, SafetyError

__all__ = ["InferenceExecutor"]

_OK = "ok"
_ERROR = "error"
_SAFETY_ERROR = "safety_error"
_POLL_SLICE = 0.05
_JOIN_TIMEOUT = 5.0

_SENTINEL = object()


def _worker_entry(conn, func: Callable[..., Any], args: tuple, kwargs: dict) -> None:
    """Child-side entry: run one task, report a sanitized outcome frame.

    Only the exception *type name* or the SafetyError *code value* crosses
    the process boundary — never the exception message, never a traceback.
    """
    frame: tuple | None = None
    try:
        result = func(*args, **kwargs)
    except SafetyError as exc:
        frame = (_SAFETY_ERROR, exc.code.value)
    except BaseException as exc:  # noqa: BLE001
        frame = (_ERROR, type(exc).__name__)
    else:
        try:
            conn.send((_OK, result))
        except Exception:
            frame = (_ERROR, "UnpicklableResult")
    if frame is not None:
        try:
            conn.send(frame)
        except Exception:
            pass
    try:
        conn.close()
    except Exception:
        pass


def _alive(proc: multiprocessing.Process) -> bool:
    try:
        return proc.is_alive()
    except (ValueError, OSError):
        return False  # handle already released => the worker is already dead


def _reap(proc: multiprocessing.Process) -> None:
    """Ensure a worker is dead and its OS handle released.

    Idempotent and race-safe: the close() sweep and the owning slot thread
    may reap the same process concurrently; on Windows, ``Process`` methods
    raise ``ValueError`` ("process object is closed") or ``OSError``
    (WinError 6, handle invalid) once the handle is gone — in all those
    cases the worker is already dead, which is the goal. An unreleased
    handle keeps a dead pid openable on Windows, which would look like a
    leak.
    """
    try:
        if proc.is_alive():
            proc.terminate()
        proc.join(timeout=_JOIN_TIMEOUT)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=_JOIN_TIMEOUT)
    except (ValueError, OSError):
        pass  # handle already invalid => the worker is already dead
    try:
        proc.close()
    except (ValueError, OSError, AttributeError):
        # ValueError/OSError: handle already invalid. AttributeError:
        # Process.close() is not idempotent on CPython 3.11 (its final
        # ``del self._sentinel`` re-raises on a second call). The handle is
        # gone in every case — the sweep and the owning slot may reap the
        # same worker concurrently.
        pass


@dataclass
class _Job:
    func: Callable[..., Any]
    args: tuple
    kwargs: dict
    deadline: float
    result_q: queue.Queue
    cancel: Any = None


class InferenceExecutor:
    """Bounded, process-isolated call executor with per-call time budgets.

    Parameters
    ----------
    max_workers:
        Maximum concurrent worker processes (default 1).
    max_pending:
        Maximum accepted calls waiting for a slot (default 4). A submit that
        would exceed this raises ``SafetyError(INFERENCE_QUEUE_FULL)``
        immediately.
    mp_context:
        Multiprocessing context (default: ``spawn`` on every platform).
    """

    def __init__(
        self,
        max_workers: int = 1,
        max_pending: int = 4,
        *,
        mp_context: Any = None,
    ) -> None:
        if not isinstance(max_workers, int) or isinstance(max_workers, bool):
            raise TypeError("max_workers must be an int")
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        if not isinstance(max_pending, int) or isinstance(max_pending, bool):
            raise TypeError("max_pending must be an int")
        if max_pending < 0:
            raise ValueError("max_pending must be >= 0")
        self._max_workers = max_workers
        self._max_pending = max_pending
        self._mp = mp_context if mp_context is not None else multiprocessing.get_context("spawn")
        # Internally unbounded; ``_queued`` (guarded by ``_state_lock``)
        # enforces the pending bound so that ``max_pending=0`` truly means
        # "no waiting calls allowed" (queue.Queue(maxsize=0) would be
        # unbounded).
        self._pending: queue.Queue = queue.Queue()
        self._submit_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._live: set[Any] = set()
        self._running = 0
        self._queued = 0
        self._closed = False
        self._slot_threads = [
            threading.Thread(
                target=self._slot_loop,
                name=f"inference-executor-slot-{i}",
                daemon=True,
            )
            for i in range(max_workers)
        ]
        for thread in self._slot_threads:
            thread.start()

    @property
    def max_workers(self) -> int:
        return self._max_workers

    @property
    def max_pending(self) -> int:
        return self._max_pending

    def snapshot(self) -> tuple[int, int]:
        """Return ``(running, pending)`` worker counts (test hook)."""
        with self._state_lock:
            return (self._running, self._queued)

    def submit(
        self,
        func: Callable[..., Any],
        *args: Any,
        timeout: float,
        cancel=None,
        **kwargs: Any,
    ) -> Any:
        """Run ``func(*args, **kwargs)`` in a worker process under a time budget.

        ``timeout`` is keyword-only and mandatory; it covers queue wait,
        worker startup, and execution, in seconds. Returns the function's
        result.

        Raises
        ------
        SafetyError(INFERENCE_QUEUE_FULL)
            Immediately, if the pending queue is full.
        SafetyError(INFERENCE_TIMEOUT)
            If the budget expires (worker terminated) or the executor is
            closed while the call is queued or running. A task that pickles
            but cannot be reconstructed in the worker also dies without an
            outcome frame and is reported this way (see module docstring).
        SafetyError(<original code>)
            If the worker task raised a ``SafetyError`` (detail dropped).
        RuntimeError
            If the worker task raised any other exception (type name only).
        TypeError
            If the task fails the pre-spawn picklability check (no worker
            process is created), or if the executor is closed.
        """
        if not callable(func):
            raise TypeError("func must be callable")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise TypeError("timeout must be a number")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        job = _Job(
            func=func,
            args=args,
            kwargs=kwargs,
            deadline=time.monotonic() + timeout,
            result_q=queue.Queue(maxsize=1),
            cancel=cancel if cancel is not None else threading.Event(),
        )
        with self._submit_lock:
            if self._closed:
                raise TypeError("executor is closed")
            with self._state_lock:
                if self._queued >= self._max_pending:
                    raise SafetyError(SafetyCode.INFERENCE_QUEUE_FULL) from None
                self._queued += 1
            # Cannot block: the queue is internally unbounded and ``_queued``
            # carries the backpressure accounting.
            self._pending.put_nowait(job)
        try:
            status, payload = job.result_q.get(timeout=timeout + _JOIN_TIMEOUT * 2 + 1)
        except queue.Empty:
            job.cancel.set()
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT) from None
        if status == "return":
            return payload
        raise payload

    def close(self) -> None:
        """Terminate all live workers, reject queued/running waiters, join threads.

        Idempotent. After ``close()`` returns: every worker process has
        exited (``join`` observed termination), every handle held by this
        executor is released, no slot thread remains, and ``submit`` raises
        ``TypeError``. Note that "exited + handle released" is the strongest
        guarantee available in user mode: on Windows the pid of a reaped
        worker can stay *openable* (``OpenProcess`` succeeds) for an
        unbounded period while the kernel process object is still referenced
        by other components (console host, security tooling). Detecting
        worker disappearance therefore requires polling the pid, never a
        synchronous one-shot check.
        """
        with self._submit_lock:
            if self._closed:
                return
            self._closed = True
        # Abort in-flight work first: slots then free up and keep draining
        # the queue, so the sentinel puts below cannot deadlock even when
        # every slot is occupied by a hung task.
        with self._state_lock:
            live = list(self._live)
        for proc in live:
            _reap(proc)
        # Submissions are locked out, so the queue tail becomes exactly one
        # sentinel per slot thread; every queued job ahead of them is still
        # dequeued and rejected by the slot loops.
        for _ in self._slot_threads:
            self._pending.put(_SENTINEL)
        for thread in self._slot_threads:
            thread.join(timeout=_JOIN_TIMEOUT)
        alive = [t.name for t in self._slot_threads if t.is_alive()]
        if alive:
            raise RuntimeError(f"inference slot threads did not stop: {alive}")
        with self._state_lock:
            live = list(self._live)
        for proc in live:
            _reap(proc)
        # Post-condition of a successful close(): every worker has exited
        # (join observed termination) and every handle WE held is released.
        # What close() cannot guarantee is the OS forgetting the pid: on
        # Windows the kernel process object can stay referenced (console
        # host, security tooling) for an unbounded time after exit, keeping
        # the pid openable via OpenProcess. Callers must therefore check
        # worker disappearance by polling, not synchronously.
        leftover = [proc.pid for proc in live if _alive(proc)]
        if leftover:
            raise RuntimeError(f"worker processes did not terminate: {leftover}")

    def __enter__(self) -> "InferenceExecutor":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # -- slot side ---------------------------------------------------------

    def _slot_loop(self) -> None:
        while True:
            job = self._pending.get()
            if job is _SENTINEL:
                return
            with self._state_lock:
                self._queued -= 1
            try:
                if self._closed:
                    self._reject(job, SafetyError(SafetyCode.INFERENCE_TIMEOUT))
                    continue
                self._run_job(job)
            except Exception:
                # A slot must never lose a submitted job.
                self._reject(job, RuntimeError("inference slot failure"))

    def _run_job(self, job: _Job) -> None:
        # The budget is anchored once at submit (``job.deadline``) and is
        # never re-anchored: queue wait, the pickle pre-check, pipe setup,
        # and spawn all consume it, exactly as the submit() docstring states.
        if job.deadline - time.monotonic() <= 0 or job.cancel.is_set():
            self._reject(job, SafetyError(SafetyCode.INFERENCE_TIMEOUT))
            return
        # Verify picklability before spawning: a spawn-time pickling failure
        # would create (and race) a real child process.
        try:
            pickle.dumps((job.func, job.args, job.kwargs))
        except Exception:
            self._reject(job, TypeError("inference task is not picklable"))
            return
        parent_conn, child_conn = self._mp.Pipe(duplex=False)
        try:
            proc = self._mp.Process(
                target=_worker_entry,
                args=(child_conn, job.func, job.args, job.kwargs),
            )
            proc.start()
        except Exception:
            parent_conn.close()
            child_conn.close()
            self._reject(job, TypeError("failed to start inference worker process"))
            return
        child_conn.close()
        with self._state_lock:
            self._live.add(proc)
            self._running += 1
        try:
            frame = self._await_frame(parent_conn, proc, job.deadline, job.cancel)
            # Every outcome below (ok/error/timeout/dead/close) ends this
            # worker; it is never reused. Reap before delivering so a
            # returned result implies the worker has exited and its handle
            # has been released.
            _reap(proc)
            if frame is not None and frame[0] == _OK:
                self._deliver(job, "return", frame[1])
                return
            if frame is None:
                self._reject(job, SafetyError(SafetyCode.INFERENCE_TIMEOUT))
            elif frame[0] == _SAFETY_ERROR:
                self._reject(job, SafetyError(SafetyCode(frame[1])))
            elif frame[0] == _ERROR:
                self._reject(job, RuntimeError(f"inference task failed: {frame[1]}"))
            else:
                self._reject(job, RuntimeError("inference task returned invalid frame"))
        finally:
            # Safety net: on ANY exit path from this block — including an
            # unexpected connection exception not covered by the handlers in
            # _await_frame — the worker process is always reaped here
            # (_reap is idempotent, so the explicit reap above is unaffected).
            _reap(proc)
            parent_conn.close()
            with self._state_lock:
                self._live.discard(proc)
                self._running -= 1

    def _await_frame(self, conn: Any, proc: Any, deadline: float, cancel=None) -> tuple | None:
        """Poll for the worker's outcome frame; ``None`` means timed out/died.

        ``deadline`` is the submit-time budget anchor; it is never
        re-anchored here, so worker startup time consumes budget.
        """
        while True:
            if self._closed or (cancel is not None and cancel.is_set()):
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                ready = conn.poll(min(_POLL_SLICE, remaining))
            except (OSError, EOFError):
                return None
            if ready:
                try:
                    return conn.recv()
                except (EOFError, OSError):
                    return None

    def _deliver(self, job: _Job, status: str, payload: Any) -> None:
        job.result_q.put((status, payload))

    def _reject(self, job: _Job, error: BaseException) -> None:
        job.result_q.put(("raise", error))
