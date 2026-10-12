"""Real spawn-process tests for persistent sessions and actual reclamation."""

from __future__ import annotations

import os
import subprocess
import sys
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
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

    def test_sealed_snapshot_survives_source_changes_and_new_pool_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            shutil.copytree(MINI, directory, dirs_exist_ok=True)
            with NerWorkerPool(directory, intra_op_threads=1) as pool:
                first = pool.infer_profiled(('aa bb',), timeout=20)
                model = Path(directory, 'model.onnx')
                before = model.stat()
                payload = model.read_bytes()
                model.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
                os.utime(model, ns=(before.st_atime_ns, before.st_mtime_ns))
                second = pool.infer_profiled(('aa bb',), timeout=20)
                self.assertEqual(first.results, second.results)
                self.assertEqual(first.worker_pid, second.worker_pid)
                with NerWorkerPool(directory, intra_op_threads=1) as new_pool:
                    with self.assertRaises(SafetyError) as caught:
                        new_pool.infer(('aa',), timeout=20)
                    self.assertEqual(caught.exception.code, SafetyCode.NER_MODEL_INVALID)
                manifest = Path(directory, 'manifest.json')
                manifest.write_bytes(manifest.read_bytes() + b'\n')
                third = pool.infer_profiled(('aa bb',), timeout=20)
                self.assertEqual(first.results, third.results)

    def test_mutable_baseline_retains_per_task_integrity_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            shutil.copytree(MINI, directory, dirs_exist_ok=True)
            with NerWorkerPool(directory, sealed_snapshot=False, intra_op_threads=1) as pool:
                first = pool.infer_profiled(('aa bb',), timeout=20)
                model = Path(directory, 'model.onnx')
                model.write_bytes(b'x' * model.stat().st_size)
                with self.assertRaises(SafetyError) as caught:
                    pool.infer(('aa',), timeout=20)
                self.assertEqual(caught.exception.code, SafetyCode.NER_MODEL_INVALID)
                self.assertTrue(exited(first.worker_pid))

    def test_all_slots_are_forward_warmed_and_shutdown_releases_snapshot(self):
        pool = NerWorkerPool(str(MINI), max_workers=2, intra_op_threads=1)
        self.addCleanup(pool.close)
        cold = pool.warmup(timeout=20)
        self.assertEqual(len(cold), 2)
        self.assertTrue(pool.ready)
        self.assertTrue(all(item['warmup_ms'] > 0 for item in cold))
        self.assertTrue(all(slot.completed == 0 for slot in pool._slots))
        pids = pool.worker_pids()
        pool.close()
        self.assertTrue(all(exited(pid) for pid in pids))
        self.assertTrue(pool._artifact._closed)

    def test_auto_threads_share_visible_cpu_budget_and_explicit_threads_are_preserved(self):
        with patch('detection.ner_worker_pool.cpu_thread_budget', return_value=6):
            automatic = self.pool(max_workers=2)
            explicit = self.pool(max_workers=2, intra_op_threads=5)
        self.assertEqual(automatic._intra_op_threads, 3)
        self.assertEqual(explicit._intra_op_threads, 5)

    def test_snapshot_creation_consumes_bounded_slot_not_an_unbounded_pre_admission_wait(self):
        from detection.ner_snapshot import SealedNerSnapshot
        started, release = threading.Event(), threading.Event()
        original = SealedNerSnapshot.create
        def slow_snapshot(*args, **kwargs):
            started.set()
            release.wait(10)
            return original(*args, **kwargs)
        with patch.object(SealedNerSnapshot, 'create', side_effect=slow_snapshot):
            with NerWorkerPool(str(MINI), max_pending=1, intra_op_threads=1) as pool:
                first, second = Call(pool, ('aa',)), Call(pool, ('bb',))
                first.start()
                self.assertTrue(started.wait(5))
                second.start()
                self.assertTrue(wait_for(lambda: pool.snapshot() == (1, 1)))
                try:
                    with self.assertRaises(SafetyError) as caught:
                        pool.infer(('overflow',), timeout=20)
                    self.assertEqual(caught.exception.code, SafetyCode.INFERENCE_QUEUE_FULL)
                finally:
                    release.set()
                for call in (first, second):
                    call.join(10)
                    self.assertIsNone(call.error)

    def test_failed_descriptor_transfer_reaps_child_without_poisoning_pool(self):
        from detection.ner_snapshot import SealedNerSnapshot
        with NerWorkerPool(str(MINI), intra_op_threads=1) as pool:
            with patch.object(SealedNerSnapshot, 'send', side_effect=OSError(CANARY)):
                with self.assertRaises(RuntimeError) as caught:
                    pool.infer(('aa',), timeout=20)
            self.assertNotIn(CANARY, str(caught.exception))
            self.assertIsNone(caught.exception.__context__)
            self.assertFalse(pool._closed)
            self.assertEqual(pool.worker_pids(), ())
            self.assertEqual(len(pool.infer(('bb',), timeout=20)), 1)

    def test_interpreter_exit_reaps_idle_workers_even_without_explicit_close(self):
        program = '''
from detection.ner_worker_pool import NerWorkerPool
from test_ner_worker_pool import fake_factory, MINI
pool = NerWorkerPool(str(MINI), runtime_factory=fake_factory)
result = pool.infer_profiled(('ordinary',), timeout=20)
print(result.worker_pid, flush=True)
'''
        environment = {**os.environ, 'PYTHONPATH': os.pathsep.join(
            [str(Path(__file__).parent), os.environ.get('PYTHONPATH', '')])}
        result = subprocess.run([sys.executable, '-c', program], env=environment,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(exited(int(result.stdout.strip())))

    def test_window_exceeding_model_positions_is_rejected(self):
        import json
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            shutil.copytree(MINI, directory, dirs_exist_ok=True)
            config_path = Path(directory, 'config.json')
            config = json.loads(config_path.read_text())
            config['max_position_embeddings'] = 64
            config_path.write_text(json.dumps(config))
            manifest_path = Path(directory, 'manifest.json')
            manifest = json.loads(manifest_path.read_text())
            manifest['files']['config.json'] = {'sha256': hashlib.sha256(config_path.read_bytes()).hexdigest(),
                                              'bytes': config_path.stat().st_size}
            manifest_path.write_text(json.dumps(manifest))
            with NerWorkerPool(directory, intra_op_threads=1) as pool:
                with self.assertRaises(SafetyError) as caught:
                    pool.infer(('aa',), timeout=20)
                self.assertEqual(caught.exception.code, SafetyCode.NER_MODEL_INVALID)

    def test_microbatch_scatter_and_total_admission_bound(self):
        pool = self.pool(batch_wait_ms=100, max_pending=2, max_batch_jobs=8)
        pool.infer(('warm',), timeout=20)
        calls = [Call(pool, (f'fragment-{index}',)) for index in range(3)]
        for call in calls:
            call.start()
        for call in calls:
            call.join(10)
            self.assertIsNone(call.error)
            self.assertEqual(len(call.result.results), 1)
            self.assertEqual(call.result.metrics['batch_requests'], 3)
        self.assertEqual(len({call.result.metrics['calls'] for call in calls}), 1)

    def test_short_worker_reservation_serves_short_while_long_worker_hangs(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = self.pool(max_workers=2, max_pending=2, max_batch_chars=10)
            markers = [Path(directory, f'long-{index}.pid') for index in range(2)]
            first = Call(pool, (f'wait:{markers[0]}',))
            first.start()
            self.assertTrue(wait_for(markers[0].exists))
            second = Call(pool, (f'wait:{markers[1]}',))
            second.start()
            self.assertTrue(wait_for(lambda: pool.snapshot()[1] == 1))
            short = pool.infer_profiled(('short',), timeout=20)
            self.assertNotEqual(short.worker_pid, int(markers[0].read_text()))
            self.assertFalse(markers[1].exists())
            markers[0].with_suffix('.release').touch()
            self.assertTrue(wait_for(markers[1].exists))
            markers[1].with_suffix('.release').touch()
            for call in (first, second):
                call.join(10)
                self.assertIsNone(call.error)

    def test_microbatch_members_consume_capacity_and_cancel_reaps_whole_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = self.pool(batch_wait_ms=100, max_pending=2, max_batch_jobs=8)
            previous = pool.infer_profiled(('warm',), timeout=20)
            marker = Path(directory, 'batch.pid')
            cancel = threading.Event()
            calls = [Call(pool, (f'wait:{marker}',), cancel=cancel),
                     Call(pool, ('second',)), Call(pool, ('third',))]
            for call in calls:
                call.start()
            self.assertTrue(wait_for(marker.exists))
            self.assertEqual(pool.snapshot(), (1, 0))
            with self.assertRaises(SafetyError) as caught:
                pool.infer(('overflow',), timeout=20)
            self.assertEqual(caught.exception.code, SafetyCode.INFERENCE_QUEUE_FULL)
            cancel.set()
            for call in calls:
                self.assert_timeout(call)
                self.assertIsNone(call.result)
            self.assertEqual(len({id(call.error) for call in calls}), len(calls))
            self.assertTrue(exited(previous.worker_pid))

    def test_age_and_rss_retire_workers_and_maintenance_rewarms_replacements(self):
        pool = self.pool(max_age_seconds=1, batch_wait_ms=0)
        pool.warmup(timeout=20)
        first = pool.worker_pids()[0]
        self.assertTrue(wait_for(lambda: pool.ready and first not in pool.worker_pids()))
        self.assertTrue(exited(first))
        # A deliberately low cap demonstrates real worker RSS-based retirement.
        with NerWorkerPool(str(MINI), max_rss_kib=1, intra_op_threads=1) as real:
            result = real.infer_profiled(('aa',), timeout=20)
            self.assertTrue(exited(result.worker_pid))

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
