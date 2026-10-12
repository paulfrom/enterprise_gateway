"""Real spawn-process tests for persistent sessions and actual reclamation."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from detection.ner_runtime import NerBatchResult
from detection.ner_worker_pool import NerWorkerPool
from infra.errors import SafetyCode, SafetyError

MINI = Path(__file__).parent / 'fixtures/ner/mini-valid-package'
CANARY = 'synthetic-private-canary-never-in-errors'


class FakeRuntime:
    def __init__(self):
        self.initialization_metrics = {'session_load_ms': 1.0}
        self.calls = 0

    def run(self, texts, digest, profile):
        self.calls += 1
        for text in texts:
            if text.startswith(('hang:', 'wait:')):
                mode, path = text.split(':', 1)
                marker = Path(path)
                marker.write_text(str(os.getpid()))
                while mode == 'hang' or not marker.with_suffix('.release').exists():
                    time.sleep(0.01)
            if text == 'crash':
                os._exit(7)
            if text == 'error':
                raise ValueError(CANARY)
            if text == 'safety':
                raise SafetyError(SafetyCode.INVALID_TEXT, CANARY)
        return NerBatchResult(tuple(((), ('synthetic', '2026-10-11', 'ab' * 32)) for _ in texts),
                              {'worker_task_ms': 0.0, 'calls': self.calls}, os.getpid())


def fake_factory(*args):
    return FakeRuntime()


def hanging_factory(package_dir, *args):
    Path(package_dir, 'initializing.pid').write_text(str(os.getpid()))
    while True:
        time.sleep(0.01)


def wait_for(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def exited(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


class Call(threading.Thread):
    def __init__(self, pool, texts, *, timeout=20, cancel=None):
        super().__init__(daemon=True)
        self.pool, self.texts, self.timeout, self.cancel = pool, texts, timeout, cancel
        self.result = self.error = None

    def run(self):
        try:
            self.result = self.pool.infer_profiled(self.texts, timeout=self.timeout, cancel=self.cancel)
        except BaseException as exc:
            self.error = exc


class NerWorkerPoolTests(unittest.TestCase):
    def test_interpreter_exit_reaps_idle_workers_after_success_or_failure(self):
        script = """import sys
from detection.ner_worker_pool import NerWorkerPool
if __name__ == '__main__':
    pool = NerWorkerPool(sys.argv[1], intra_op_threads=1)
    result = pool.infer_profiled(('aa',), timeout=20)
    print(result.worker_pid, flush=True)
    if sys.argv[2] == 'failure':
        raise RuntimeError('synthetic CLI failure')
"""
        with tempfile.TemporaryDirectory() as directory:
            entry = Path(directory, 'idle_pool.py')
            entry.write_text(script)
            for outcome in ('success', 'failure'):
                with self.subTest(outcome=outcome):
                    try:
                        result = subprocess.run([sys.executable, str(entry), str(MINI.resolve()), outcome],
                                                capture_output=True, text=True, timeout=30)
                    except subprocess.TimeoutExpired as exc:
                        output = exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout
                        if output and output.strip().isdigit():
                            try:
                                os.kill(int(output.strip()), signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                        raise
                    self.assertEqual(result.returncode, 0 if outcome == 'success' else 1, result.stderr)
                    self.assertTrue(exited(int(result.stdout.strip())))

    def pool(self, directory=MINI, **kwargs):
        pool = NerWorkerPool(str(directory), runtime_factory=fake_factory, **kwargs)
        self.addCleanup(pool.close)
        return pool

    def assert_timeout(self, call):
        call.join(10)
        self.assertFalse(call.is_alive())
        self.assertIsInstance(call.error, SafetyError)
        self.assertEqual(call.error.code, SafetyCode.INFERENCE_TIMEOUT)

    def test_real_model_session_reused_and_idle_process_closed(self):
        with NerWorkerPool(str(MINI), intra_op_threads=1) as pool:
            first = pool.infer_profiled(('aa bb',), timeout=20)
            second = pool.infer_profiled(('cc dd',), timeout=20)
            self.assertEqual(first.worker_pid, second.worker_pid)
            self.assertNotEqual(first.worker_pid, os.getpid())
            self.assertGreater(first.metrics['session_load_ms'], 0)
            self.assertNotIn('session_load_ms', second.metrics)
            self.assertEqual(second.metrics['worker_startup_ms'], 0)
            self.assertEqual(len(second.results), 1)
            self.assertEqual(pool.snapshot(), (0, 0))
        self.assertTrue(exited(first.worker_pid))

    def test_zero_pending_allows_idle_slot_and_rejects_waiter(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = self.pool(max_pending=0)
            for _ in range(3):
                pool.infer(('ordinary',), timeout=20)
            marker = Path(directory, 'running.pid')
            active = Call(pool, (f'wait:{marker}',))
            active.start()
            self.assertTrue(wait_for(marker.exists))
            with self.assertRaises(SafetyError) as caught:
                pool.infer(('extra',), timeout=20)
            self.assertEqual(caught.exception.code, SafetyCode.INFERENCE_QUEUE_FULL)
            marker.with_suffix('.release').touch()
            active.join(10)
            self.assertIsNone(active.error)

    def test_task_count_recycling_joins_old_process_before_replacement(self):
        pool = self.pool(max_tasks_per_worker=2)
        first = pool.infer_profiled(('one',), timeout=20)
        second = pool.infer_profiled(('two',), timeout=20)
        self.assertEqual(first.worker_pid, second.worker_pid)
        self.assertEqual(second.metrics['calls'], 2)
        self.assertTrue(exited(first.worker_pid))
        third = pool.infer_profiled(('three',), timeout=20)
        self.assertNotEqual(first.worker_pid, third.worker_pid)
        self.assertEqual(third.metrics['calls'], 1)

    def test_idle_process_death_is_reaped_and_replaced_on_next_task(self):
        import signal
        pool = self.pool()
        first = pool.infer_profiled(('warm',), timeout=20)
        os.kill(first.worker_pid, signal.SIGKILL)
        self.assertTrue(wait_for(lambda: all(not slot.proc.is_alive() for slot in pool._slots)))
        second = pool.infer_profiled(('after',), timeout=20)
        self.assertTrue(exited(first.worker_pid))
        self.assertNotEqual(first.worker_pid, second.worker_pid)

    def test_running_cancellation_reaps_then_rebuilds(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = self.pool()
            first = pool.infer_profiled(('warm',), timeout=20)
            marker = Path(directory, 'hung.pid')
            cancel = threading.Event()
            call = Call(pool, (f'hang:{marker}',), cancel=cancel)
            call.start()
            self.assertTrue(wait_for(marker.exists))
            cancel.set()
            self.assert_timeout(call)
            self.assertTrue(exited(first.worker_pid))
            replacement = pool.infer_profiled(('after',), timeout=20)
            self.assertNotEqual(first.worker_pid, replacement.worker_pid)

    def test_running_deadline_reaps_hung_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = self.pool()
            first = pool.infer_profiled(('warm',), timeout=20)
            marker = Path(directory, 'hung.pid')
            call = Call(pool, (f'hang:{marker}',), timeout=0.3)
            call.start()
            self.assertTrue(wait_for(marker.exists))
            self.assert_timeout(call)
            self.assertTrue(exited(first.worker_pid))
            self.assertEqual(pool.snapshot(), (0, 0))

    def test_queue_full_and_queue_deadline_never_execute_expired_text(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = self.pool(max_pending=1)
            first = pool.infer_profiled(('warm',), timeout=20)
            active_marker = Path(directory, 'active.pid')
            expired_marker = Path(directory, 'expired.pid')
            active = Call(pool, (f'wait:{active_marker}',))
            active.start()
            self.assertTrue(wait_for(active_marker.exists))
            queued = Call(pool, (f'hang:{expired_marker}',), timeout=0.3)
            queued.start()
            self.assertTrue(wait_for(lambda: pool.snapshot() == (1, 1)))
            with self.assertRaises(SafetyError) as caught:
                pool.infer(('overflow',), timeout=20)
            self.assertEqual(caught.exception.code, SafetyCode.INFERENCE_QUEUE_FULL)
            self.assert_timeout(queued)
            self.assertEqual(pool.snapshot(), (1, 0))
            active_marker.with_suffix('.release').touch()
            active.join(10)
            self.assertIsNone(active.error)
            self.assertFalse(expired_marker.exists())
            self.assertEqual(active.result.worker_pid, first.worker_pid)

    def test_queued_cancellation_preserves_running_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = self.pool()
            pool.infer(('warm',), timeout=20)
            marker = Path(directory, 'active.pid')
            active = Call(pool, (f'wait:{marker}',))
            active.start()
            self.assertTrue(wait_for(marker.exists))
            cancel = threading.Event()
            queued = Call(pool, ('ordinary',), cancel=cancel)
            queued.start()
            self.assertTrue(wait_for(lambda: pool.snapshot()[1] == 1))
            cancel.set()
            self.assert_timeout(queued)
            marker.with_suffix('.release').touch()
            active.join(10)
            self.assertIsNone(active.error)

    def test_initialization_deadline_is_bounded_and_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            shutil.copy(MINI / 'manifest.json', Path(directory, 'manifest.json'))
            pool = NerWorkerPool(directory, runtime_factory=hanging_factory)
            self.addCleanup(pool.close)
            marker = Path(directory, 'initializing.pid')
            call = Call(pool, ('ordinary',), timeout=2)
            call.start()
            self.assertTrue(wait_for(marker.exists))
            self.assert_timeout(call)
            self.assertTrue(exited(int(marker.read_text())))

    def test_close_rejects_active_and_queued_calls_and_clears_all_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = self.pool()
            first = pool.infer_profiled(('warm',), timeout=20)
            marker = Path(directory, 'active.pid')
            active = Call(pool, (f'hang:{marker}',))
            active.start()
            self.assertTrue(wait_for(marker.exists))
            queued = Call(pool, ('ordinary',))
            queued.start()
            self.assertTrue(wait_for(lambda: pool.snapshot()[1] == 1))
            pool.close()
            self.assert_timeout(active)
            self.assert_timeout(queued)
            self.assertTrue(exited(first.worker_pid))
            self.assertEqual(pool.snapshot(), (0, 0))
            self.assertEqual(pool.worker_pids(), ())
            self.assertTrue(all(not thread.is_alive() for thread in pool._threads))
            with self.assertRaises(TypeError):
                pool.infer(('later',), timeout=1)
            pool.close()

    def test_crash_and_sanitized_errors_do_not_poison_future_workers(self):
        pool = self.pool()
        for text, error_type, code in (('crash', SafetyError, SafetyCode.INFERENCE_TIMEOUT),
                                        ('error', RuntimeError, None),
                                        ('safety', SafetyError, SafetyCode.INVALID_TEXT)):
            previous = pool.infer_profiled(('warm',), timeout=20)
            with self.assertRaises(error_type) as caught:
                pool.infer((text,), timeout=20)
            self.assertNotIn(CANARY, str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)
            if code:
                self.assertEqual(caught.exception.code, code)
            self.assertTrue(exited(previous.worker_pid))
        self.assertEqual(len(pool.infer(('after',), timeout=20)), 1)

    def test_concurrent_slots_are_bounded_and_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = self.pool(max_workers=2, max_pending=0)
            markers = [Path(directory, f'worker-{index}.pid') for index in range(2)]
            calls = [Call(pool, (f'wait:{marker}',)) for marker in markers]
            for call in calls:
                call.start()
            self.assertTrue(wait_for(lambda: all(marker.exists() for marker in markers)))
            self.assertEqual(pool.snapshot(), (2, 0))
            self.assertEqual(len(set(pool.worker_pids())), 2)
            for marker in markers:
                marker.with_suffix('.release').touch()
            for call in calls:
                call.join(10)
                self.assertIsNone(call.error)

    def test_cached_session_still_rejects_payload_tampering_and_new_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            shutil.copytree(MINI, directory, dirs_exist_ok=True)
            with NerWorkerPool(directory, intra_op_threads=1) as pool:
                first = pool.infer_profiled(('aa bb',), timeout=20)
                model = Path(directory, 'model.onnx')
                before = model.stat()
                payload = model.read_bytes()
                model.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
                os.utime(model, ns=(before.st_atime_ns, before.st_mtime_ns))
                with self.assertRaises(SafetyError) as caught:
                    pool.infer(('aa',), timeout=20)
                self.assertEqual(caught.exception.code, SafetyCode.NER_MODEL_INVALID)
                self.assertTrue(exited(first.worker_pid))
                model.write_bytes(payload)
                pool.infer(('aa',), timeout=20)
                manifest = Path(directory, 'manifest.json')
                manifest.write_bytes(manifest.read_bytes() + b'\n')
                with self.assertRaises(SafetyError) as caught:
                    pool.infer(('aa',), timeout=20)
                self.assertEqual(caught.exception.code, SafetyCode.NER_MODEL_INVALID)

    def test_argument_validation_and_pre_cancel_create_no_process(self):
        for kwargs in ({'max_workers': 0}, {'max_pending': -1}, {'max_tasks_per_worker': 0},
                        {'max_workers': True}, {'intra_op_threads': 0}):
            with self.assertRaises((TypeError, ValueError)):
                NerWorkerPool(str(MINI), **kwargs)
        pool = self.pool()
        for timeout in (0, float('nan'), float('inf'), True):
            with self.assertRaises(ValueError):
                pool.infer(('ordinary',), timeout=timeout)
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(SafetyError):
            pool.infer(('ordinary',), timeout=20, cancel=cancel)
        self.assertEqual(pool.worker_pids(), ())


if __name__ == '__main__':
    unittest.main()
