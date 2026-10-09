"""Wire snapshots at protected SSE release boundaries; explicit storage spy."""
import asyncio
import time
import unittest

from gateway.streaming import ProtectedStream, iter_protected_stream
from infra.errors import SafetyError
from masking.mapping import MappingContext
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL as CHAT
from request_history.models import HistoryUnavailable
from tests.gateway.history_fixture import RecorderSpy
from tests.protocol.test_stream_events import KEY, chat, choice


class RequestHistoryStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_single_byte_input_commits_atomic_complete_snapshots_before_release(self):
        raw = chat([choice(delta={'content': '合成响应'})]) + chat([choice(finish='stop')]) + b'data: [DONE]\n\n'
        recorder = RecorderSpy()
        closed = []
        async def source():
            for value in raw:
                yield bytes([value])
        async def close():
            closed.append(True)
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context)
            frames = []
            async for frame in iter_protected_stream(source(), stream, close=close, history_recorder=recorder):
                self.assertEqual('completed', recorder.status)
                self.assertEqual([True], closed)
                frames.append(frame)
            self.assertEqual(raw, recorder.stages['upstream']['body'])
            self.assertEqual(b''.join(frames), recorder.stages['restored']['body'])
            self.assertEqual('complete', recorder.stages['upstream']['state'])
            self.assertEqual(1, len(recorder.transactions))
            self.assertEqual({'upstream', 'restored'}, {item['stage'] for item in recorder.transactions[0]})

    async def test_history_write_failure_releases_no_business_and_still_closes_transport(self):
        recorder = RecorderSpy(fail_stage='restored')
        closed = []
        async def source():
            yield chat([choice(delta={'content': 'CNRY-BUSINESS'})])
            yield chat([choice(finish='stop')]) + b'data: [DONE]\n\n'
        async def close():
            closed.append(True)
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context)
            frames = []
            with self.assertRaises(HistoryUnavailable):
                async for frame in iter_protected_stream(source(), stream, close=close, history_recorder=recorder):
                    frames.append(frame)
            self.assertEqual([], frames)
            self.assertEqual([True], closed)
            self.assertEqual('processing', recorder.status)
            self.assertEqual('partial', recorder.stages['upstream']['state'])
            self.assertIn(b'CNRY-BUSINESS', recorder.stages['upstream']['body'])
            self.assertTrue(stream._history_write_failed)

    async def test_terminal_failure_releases_no_business(self):
        recorder = RecorderSpy(fail_finish=True)
        async def source():
            yield chat([choice(delta={'content': 'CNRY-BUSINESS'})])
            yield chat([choice(finish='stop')]) + b'data: [DONE]\n\n'
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context)
            frames = []
            with self.assertRaises(HistoryUnavailable):
                async for frame in iter_protected_stream(source(), stream, history_recorder=recorder):
                    frames.append(frame)
            self.assertEqual([], frames)
            self.assertEqual('processing', recorder.status)
            self.assertTrue(stream._history_write_failed)

    async def test_protocol_failure_retains_exact_partial_raw_without_business(self):
        raw = chat([choice(delta={'content': 'CNRY-BUSINESS'})]) + b'data: malformed\n\n'
        recorder = RecorderSpy()
        async def source():
            yield raw
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context)
            frames = []
            with self.assertRaises(SafetyError):
                async for frame in iter_protected_stream(source(), stream, history_recorder=recorder):
                    frames.append(frame)
            self.assertEqual([], frames)
            self.assertEqual(raw, recorder.stages['upstream']['body'])
            self.assertEqual('partial', recorder.stages['upstream']['state'])
            self.assertNotIn('restored', recorder.stages)
            self.assertEqual('partial', stream._history_status)
            self.assertTrue(stream._history_cleanup_succeeded)

    async def test_disconnect_retains_raw_partial_and_no_completion(self):
        raw = chat([choice(delta={'content': 'CNRY-BUSINESS'})])
        recorder = RecorderSpy()
        seen = []
        async def source():
            yield raw
            seen.append(True)
            await asyncio.sleep(1)
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context)
            frames = [frame async for frame in iter_protected_stream(source(), stream,
                disconnected=lambda: bool(seen), history_recorder=recorder)]
            self.assertEqual([], frames)
            self.assertEqual(raw, recorder.stages['upstream']['body'])
            self.assertEqual('processing', recorder.status)
            self.assertEqual('partial', stream._history_status)
            self.assertFalse(stream._history_success_committed)

    async def test_cleanup_failure_never_commits_success_or_releases_business(self):
        recorder = RecorderSpy()
        async def source():
            yield chat([choice(delta={'content': 'CNRY-BUSINESS'})])
            yield chat([choice(finish='stop')]) + b'data: [DONE]\n\n'
        async def close():
            raise RuntimeError('synthetic cleanup failure')
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context)
            frames = []
            with self.assertRaises(RuntimeError):
                async for frame in iter_protected_stream(source(), stream, close=close, history_recorder=recorder):
                    frames.append(frame)
            self.assertEqual([], frames)
            self.assertEqual('processing', recorder.status)
            self.assertFalse(stream._history_cleanup_succeeded)

    async def test_history_raw_budget_is_bounded(self):
        recorder = RecorderSpy()
        recorder.max_stage_bytes = 10
        async def source():
            yield b'x' * 11
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context)
            with self.assertRaises(HistoryUnavailable):
                _ = [frame async for frame in iter_protected_stream(source(), stream, history_recorder=recorder)]
            self.assertNotIn('upstream', recorder.stages)

    async def test_cancellation_after_received_bytes_flushes_partial_and_marks_cleanup(self):
        raw = chat([choice(delta={'content': 'CNRY-BUSINESS'})])
        recorder = RecorderSpy()
        read_started = asyncio.Event()
        async def source():
            yield raw
            read_started.set()
            await asyncio.sleep(5)
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context)
            async def consume():
                return [frame async for frame in iter_protected_stream(source(), stream, history_recorder=recorder)]
            task = asyncio.create_task(consume())
            await read_started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(raw, recorder.stages['upstream']['body'])
            self.assertTrue(stream._history_cleanup_succeeded)
            self.assertEqual('partial', stream._history_status)
            self.assertEqual('processing', recorder.status)

    async def test_deadline_expiring_during_history_commit_withholds_business(self):
        recorder = RecorderSpy()
        real_write_many = recorder.write_many
        def slow_write(updates):
            time.sleep(0.04)
            real_write_many(updates)
        recorder.write_many = slow_write
        async def source():
            yield chat([choice(delta={'content': 'CNRY-BUSINESS'})])
            yield chat([choice(finish='stop')]) + b'data: [DONE]\n\n'
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context, deadline_at=time.monotonic() + 0.03)
            frames = []
            with self.assertRaises(SafetyError):
                async for frame in iter_protected_stream(source(), stream, history_recorder=recorder):
                    frames.append(frame)
            self.assertEqual([], frames)
            self.assertEqual('processing', recorder.status)

    async def test_finalization_with_no_new_frames_completes_previously_emitted_stage(self):
        recorder = RecorderSpy()
        class HeartbeatStream:
            deadline_at = time.monotonic() + 10
            max_stream_bytes = 100
            _done = False
            def _check(self):
                pass
            def feed(self, _chunk):
                return [b': keep-alive\n\n']
            def finalize(self):
                return []
            def cancel(self):
                pass
        async def source():
            yield b': heartbeat\n\n'
        stream = HeartbeatStream()
        frames = [frame async for frame in iter_protected_stream(source(), stream, history_recorder=recorder)]
        self.assertEqual(b''.join(frames), recorder.stages['restored']['body'])
        self.assertEqual('complete', recorder.stages['restored']['state'])
        self.assertEqual('completed', recorder.status)

    async def test_keepalive_history_commit_rechecks_deadline_before_release(self):
        recorder = RecorderSpy()
        real_write_many = recorder.write_many
        def slow_write(updates):
            time.sleep(0.04)
            real_write_many(updates)
        recorder.write_many = slow_write
        async def source():
            await asyncio.sleep(5)
            yield b''
        with MappingContext('corp.test', 'v1', KEY) as context:
            stream = ProtectedStream(CHAT, 'synthetic-model', context, deadline_at=time.monotonic() + 0.03)
            frames = []
            with self.assertRaises(SafetyError):
                async for frame in iter_protected_stream(source(), stream,
                        history_recorder=recorder, keepalive_seconds=0.005):
                    frames.append(frame)
            self.assertEqual([], frames)
            self.assertEqual('processing', recorder.status)
