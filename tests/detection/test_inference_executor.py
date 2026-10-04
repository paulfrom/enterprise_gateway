"""Bounded inference executor tests: worker process isolation, timeout controls, and backpressure.

Real processes only: timeout/reclaim paths are exercised with genuinely
hanging work functions (infinite sleep loops), never with fake timeout
stubs. All work functions are module-level so they pickle under the
multiprocessing spawn context.

Windows pid-reclamation semantics (measured, see D-10 evidence): after a
worker exits and its handle is released, ``os.kill(pid, 0)`` may keep
succeeding for an unbounded period — the kernel process object can stay
referenced by other components (console host, security tooling). Tests
therefore separate two claims: "the worker has terminated" (deterministic,
read from the process exit code via ``_pid_exited``) and "the pid became
unopenable" (OS teardown schedule, polled via ``_pid_exists``).
"""

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from infra.errors import SafetyCode, SafetyError
from detection.inference_executor import InferenceExecutor

if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes

    _STILL_ACTIVE = 259  # Windows GetExitCodeProcess marker for a running process
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    _kernel32 = ctypes.windll.kernel32
    _kernel32.OpenProcess.restype = ctypes.c_void_p
    _kernel32.OpenProcess.argtypes = [
        ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
    ]
    _kernel32.GetExitCodeProcess.restype = ctypes.wintypes.BOOL
    _kernel32.GetExitCodeProcess.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.DWORD),
    ]
    _kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

CANARY = "d10-canary-9f3a2b1c"  # synthetic marker; must never appear in public messages


# -- work functions (child side, must be picklable) ----------------------


def _add_one(x):
    return x + 1


def _pid_add_one(x):
    return (os.getpid(), x + 1)


def _sleep_seconds(seconds):
    time.sleep(seconds)
    return "awake"


def _write_pid_then_hang(pid_path):
    Path(pid_path).write_text(str(os.getpid()), encoding="ascii")
    while True:
        time.sleep(0.2)


def _raise_with_canary():
    raise ValueError(f"boom {CANARY}")


def _raise_safety():
    raise SafetyError(SafetyCode.INVALID_TEXT, "static-field-name")


# -- helpers --------------------------------------------------------------


def _pid_exists(pid):
    if pid <= 0:
        return False
    if sys.platform == "win32":
        handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        code = ctypes.wintypes.DWORD(0)
        try:
            _kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        finally:
            _kernel32.CloseHandle(handle)
        return code.value == _STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _pid_exited(pid):
    """True once the process behind ``pid`` has terminated.

    This is the deterministic reclaim guarantee: close() and timeout reaping
    join the worker, so by the time they return the process has exited. On
    Windows the exit code is read directly because ``os.kill(pid, 0)`` can
    succeed on a dead-but-still-referenced process object. On POSIX a
    killable pid means alive — executor children are joined, never zombies.
    """
    if pid <= 0:
        return True
    if sys.platform == "win32":
        handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return True  # process object already destroyed
        code = ctypes.wintypes.DWORD(0)
        try:
            _kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        finally:
            _kernel32.CloseHandle(handle)
        return code.value != _STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except OSError:
        return True
    return False


# Widely observed disappearance deadline for a reaped Windows pid (see
# module docstring); generous on purpose — teardown is OS-scheduled.
_PID_GONE_TIMEOUT = 15.0


def _wait_for(predicate, timeout=15.0, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class _CallThread(threading.Thread):
    """Run one blocking submit on a side thread and capture its outcome."""

    def __init__(self, executor, func, *args, timeout, **kwargs):
        super().__init__(daemon=True)
        self._executor = executor
        self._func = func
        self._args = args
        self._kwargs = kwargs
        self._timeout = timeout
        self.outcome = None

    def run(self):
        try:
            result = self._executor.submit(
                self._func, *self._args, timeout=self._timeout, **self._kwargs
            )
        except BaseException as exc:  # noqa: BLE001
            self.outcome = ("raise", exc)
        else:
            self.outcome = ("return", result)


# -- tests -----------------------------------------------------------------


class ExecutorLifecycleTests(unittest.TestCase):
    def test_submit_returns_result_and_close_clears_worker_process(self):
        with InferenceExecutor() as executor:
            pid, result = executor.submit(_pid_add_one, 41, timeout=20)
            self.assertEqual(result, 42)
            # The work really ran in a separate worker process, not here.
            self.assertNotEqual(pid, os.getpid())
        # Deterministic reclaim guarantee: close() joins the worker, so it
        # has exited. The pid then becomes unopenable — but on Windows that
        # teardown is OS-scheduled (dead pid can stay referenced), so the
        # disappearance is polled rather than asserted one-shot.
        self.assertTrue(_pid_exited(pid), f"worker pid {pid} still running after close()")
        self.assertTrue(
            _wait_for(lambda: not _pid_exists(pid), timeout=_PID_GONE_TIMEOUT),
            f"worker pid {pid} still openable after close()",
        )
        # close() is idempotent.
        executor.close()
        # submit after close is rejected with the documented TypeError.
        with self.assertRaises(TypeError):
            executor.submit(_add_one, 1, timeout=1)

    def test_repeated_calls_return_correct_results(self):
        with InferenceExecutor() as executor:
            for i in range(3):
                self.assertEqual(executor.submit(_add_one, i, timeout=20), i + 1)

    def test_constructor_and_submit_argument_validation(self):
        with self.assertRaises(ValueError):
            InferenceExecutor(max_workers=0)
        with self.assertRaises(ValueError):
            InferenceExecutor(max_pending=-1)
        with self.assertRaises(TypeError):
            InferenceExecutor(max_workers="1")
        executor = InferenceExecutor()
        try:
            with self.assertRaises(ValueError):
                executor.submit(_add_one, 1, timeout=0)
            with self.assertRaises(TypeError):
                executor.submit(_add_one, 1, timeout="5")
        finally:
            executor.close()


class TimeoutReclaimTests(unittest.TestCase):
    def test_hung_task_times_out_and_worker_is_terminated_then_rebuilt(self):
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / "hung-worker.pid"
            with InferenceExecutor() as executor:
                with self.assertRaises(SafetyError) as caught:
                    executor.submit(_write_pid_then_hang, str(pid_file), timeout=5.0)
                self.assertEqual(caught.exception.code, SafetyCode.INFERENCE_TIMEOUT)
                # Controlled message: bare code, no detail, no business text.
                self.assertEqual(str(caught.exception), SafetyCode.INFERENCE_TIMEOUT.value)
                # The child really started (pid written from inside the worker).
                self.assertTrue(_wait_for(pid_file.exists, timeout=4.0))
                old_pid = int(pid_file.read_text(encoding="ascii"))
                # The timed-out worker has actually terminated (reaping runs
                # before the timeout is reported); its pid then disappears
                # from the OS on Windows' own schedule.
                self.assertTrue(_pid_exited(old_pid), f"hung worker pid {old_pid} still running")
                self.assertTrue(
                    _wait_for(lambda: not _pid_exists(old_pid), timeout=_PID_GONE_TIMEOUT),
                    f"hung worker pid {old_pid} still openable after timeout",
                )
                # The executor still serves later calls on a fresh worker.
                new_pid, result = executor.submit(_pid_add_one, 1, timeout=20)
                self.assertEqual(result, 2)
                self.assertNotEqual(new_pid, old_pid)
                self.assertNotEqual(new_pid, os.getpid())

    def test_concurrent_slots_execute_in_parallel(self):
        with InferenceExecutor(max_workers=2, max_pending=2) as executor:
            started = time.monotonic()
            t1 = _CallThread(executor, _sleep_seconds, 2.0, timeout=30)
            t2 = _CallThread(executor, _sleep_seconds, 2.0, timeout=30)
            t1.start()
            t2.start()
            t1.join(timeout=40)
            t2.join(timeout=40)
            self.assertFalse(t1.is_alive())
            self.assertFalse(t2.is_alive())
            self.assertEqual(t1.outcome, ("return", "awake"))
            self.assertEqual(t2.outcome, ("return", "awake"))
            # Both ran concurrently on two slots: wall time stays close to
            # one task's duration; serial execution would need two full
            # spawn+sleep rounds (measured ~3.8s for 1.2s sleeps here).
            self.assertLess(time.monotonic() - started, 5.0)


class QueueBackpressureTests(unittest.TestCase):
    def test_queue_full_rejects_immediately_and_running_task_unaffected(self):
        with InferenceExecutor(max_workers=1, max_pending=1) as executor:
            slow = _CallThread(executor, _sleep_seconds, 2.0, timeout=30)
            slow.start()
            self.assertTrue(
                _wait_for(lambda: executor.snapshot()[0] == 1, timeout=20),
                "slow task did not start executing",
            )
            queued = _CallThread(executor, _add_one, 7, timeout=30)
            queued.start()
            self.assertTrue(
                _wait_for(lambda: executor.snapshot()[1] == 1, timeout=20),
                "second call did not land in the pending queue",
            )
            # Queue is full (1 running + 1 pending): immediate rejection.
            with self.assertRaises(SafetyError) as caught:
                executor.submit(_add_one, 0, timeout=30)
            self.assertEqual(caught.exception.code, SafetyCode.INFERENCE_QUEUE_FULL)
            self.assertEqual(str(caught.exception), SafetyCode.INFERENCE_QUEUE_FULL.value)
            queued.join(timeout=40)
            slow.join(timeout=40)
            self.assertFalse(queued.is_alive())
            self.assertFalse(slow.is_alive())
            # The queued and running tasks were not disrupted by the rejection.
            self.assertEqual(queued.outcome, ("return", 8))
            self.assertEqual(slow.outcome, ("return", "awake"))


class CloseSemanticsTests(unittest.TestCase):
    def test_close_terminates_running_worker_and_rejects_later_submits(self):
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / "running-worker.pid"
            executor = InferenceExecutor()
            hung = _CallThread(executor, _write_pid_then_hang, str(pid_file), timeout=60)
            hung.start()
            self.assertTrue(_wait_for(pid_file.exists, timeout=20))
            running_pid = int(pid_file.read_text(encoding="ascii"))
            executor.close()
            hung.join(timeout=30)
            self.assertFalse(hung.is_alive())
            # The in-flight call got a controlled timeout, no hang, no leak.
            status, error = hung.outcome
            self.assertEqual(status, "raise")
            self.assertIsInstance(error, SafetyError)
            self.assertEqual(error.code, SafetyCode.INFERENCE_TIMEOUT)
            self.assertTrue(
                _pid_exited(running_pid),
                f"worker pid {running_pid} still running after close()",
            )
            self.assertTrue(
                _wait_for(lambda: not _pid_exists(running_pid), timeout=_PID_GONE_TIMEOUT),
                f"worker pid {running_pid} still openable after close()",
            )
            self.assertEqual(executor.snapshot(), (0, 0))
            with self.assertRaises(TypeError):
                executor.submit(_add_one, 1, timeout=1)
            executor.close()


class FailurePropagationTests(unittest.TestCase):
    def test_worker_exception_is_sanitized_and_chain_free(self):
        with InferenceExecutor() as executor:
            with self.assertRaises(RuntimeError) as caught:
                executor.submit(_raise_with_canary, timeout=20)
            error = caught.exception
            # Only the exception type name crosses the boundary.
            self.assertIn("ValueError", str(error))
            # No business text, no SafetyError masquerade, no exception chain.
            self.assertNotIn(CANARY, str(error))
            self.assertNotIsInstance(error, SafetyError)
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)

    def test_worker_safety_error_keeps_code_and_drops_detail(self):
        with InferenceExecutor() as executor:
            with self.assertRaises(SafetyError) as caught:
                executor.submit(_raise_safety, timeout=20)
            error = caught.exception
            self.assertEqual(error.code, SafetyCode.INVALID_TEXT)
            self.assertEqual(str(error), SafetyCode.INVALID_TEXT.value)
            self.assertNotIn("static-field-name", str(error))
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)

    def test_unpicklable_task_is_rejected_before_any_worker_starts(self):
        def closure(x):  # nested function: unpicklable under spawn
            return x

        with InferenceExecutor() as executor:
            with self.assertRaises(TypeError):
                executor.submit(closure, 1, timeout=20)
            self.assertEqual(executor.snapshot(), (0, 0))
            # The executor remains fully usable afterwards.
            self.assertEqual(executor.submit(_add_one, 1, timeout=20), 2)


if __name__ == "__main__":
    unittest.main()
