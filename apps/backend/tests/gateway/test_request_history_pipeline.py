"""History boundary tests using real protection and a deliberately explicit spy.

The spy proves ordering and release refusal, not PostgreSQL durability. Database
encryption, scope and transaction evidence live in request_history tests.
"""
import json
import unittest
import time
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from starlette.testclient import TestClient

from gateway.app import create_app
from gateway.provider_router import ProviderRouter
from protocol.identity import ByokAuthenticator
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL as CHAT
from request_history.models import HistoryUnavailable
from tests.integration import test_integration_roundtrip as roundtrip_fixture
from tests.gateway.history_fixture import RecorderSpy, StoreSpy


class RequestHistoryPipelineTests(unittest.TestCase):
    def setUp(self):
        roundtrip_fixture.IntegrationRoundtripTests.setUp(self)
        self.addCleanup(lambda: roundtrip_fixture.IntegrationRoundtripTests.tearDown(self))
        self.recorder = RecorderSpy()
        self.store = StoreSpy(self.recorder)
        self.supplier_response = None
        self.transport = roundtrip_fixture.UpstreamSpyTransport(self.upstream)
        self.pipeline = roundtrip_fixture.IntegrationRoundtripTests._create_pipeline(self, CHAT, self.transport)
        self.addCleanup(self.pipeline.egress_client.close)
        self.app = create_app(router=ProviderRouter({'deepseek-flash': self.pipeline}),
            authenticator=ByokAuthenticator(domain=self.domain, tenant_id='test', correlation_key=b'c'*32),
            classifier=lambda _: 'STANDARD', hmac_key=b'h'*32, history_store=self.store)
        self.raw = json.dumps({'model': 'deepseek-flash', 'messages': [
            {'role': 'user', 'content': '张三在阿尔法科技工作。'}]}, ensure_ascii=False).encode()

    def upstream(self, request):
        self.assertEqual(request.content, self.recorder.stages['redacted']['body'])
        value = json.loads(request.content)
        response = httpx.Response(200, json={'id': 'test', 'object': 'chat.completion',
            'created': 1, 'model': value['model'], 'choices': [{'index': 0,
                'message': {'role': 'assistant', 'content': value['messages'][0]['content']},
                'finish_reason': 'stop'}]})
        self.supplier_response = response.content
        return response

    def post(self):
        with TestClient(self.app) as client:
            return client.post('/v1/chat/completions', content=self.raw,
                headers={'Authorization': 'Bearer synthetic-provider-key', 'Content-Type': 'application/json'})

    def test_four_stages_match_real_wire_bytes_and_no_credential(self):
        response = self.post()
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual(self.raw, self.recorder.stages['input']['body'])
        self.assertEqual(self.supplier_response, self.recorder.stages['upstream']['body'])
        self.assertEqual(response.content, self.recorder.stages['restored']['body'])
        self.assertEqual('completed', self.recorder.status)
        self.assertEqual(self.recorder.request_id, response.headers['x-request-id'])
        self.assertIn('张三', response.text)
        self.assertNotIn('张三', self.transport.calls[0].content.decode())
        self.assertNotIn('synthetic-provider-key', repr(self.recorder.stages))

    def test_redacted_commit_failure_prevents_supplier_call(self):
        self.recorder.fail_stage = 'redacted'
        response = self.post()
        self.assertEqual(503, response.status_code)
        self.assertEqual([], self.transport.calls)
        self.assertEqual('HISTORY_UNAVAILABLE', response.json()['error']['code'])
        self.assertNotIn('张三', response.text)

    def test_deadline_expiring_during_redacted_commit_prevents_supplier_call(self):
        elapsed = []
        real_write = self.recorder.write
        def write(stage, body, **options):
            real_write(stage, body, **options)
            if stage == 'redacted':
                elapsed.append(True)
        self.recorder.write = write
        clock = SimpleNamespace(monotonic=lambda: time.monotonic() + (1000 if elapsed else 0),
                                strftime=time.strftime, localtime=time.localtime)
        with patch('gateway.pipeline.time', clock):
            response = self.post()
        self.assertEqual(504, response.status_code, response.text)
        self.assertEqual([], self.transport.calls)
        self.assertIn('redacted', self.recorder.stages)

    def test_upstream_commit_failure_prevents_restoration_and_release(self):
        self.recorder.fail_stage = 'upstream'
        with patch('gateway.pipeline.restore_response') as restore:
            response = self.post()
        restore.assert_not_called()
        self.assertEqual(503, response.status_code)
        self.assertEqual(1, len(self.transport.calls))
        self.assertNotIn('张三', response.text)

    def test_response_commit_failure_prevents_plaintext_release(self):
        self.recorder.fail_stage = 'restored'
        response = self.post()
        self.assertEqual(503, response.status_code)
        self.assertNotIn('张三', response.text)
        self.assertEqual('processing', self.recorder.status)

    def test_final_commit_failure_prevents_success_response(self):
        self.recorder.fail_finish = True
        response = self.post()
        self.assertEqual(503, response.status_code)
        self.assertEqual('processing', self.recorder.status)
        self.assertNotIn('张三', response.text)

    def test_deadline_after_final_commit_returns_no_unrecorded_body(self):
        elapsed = []
        real_finish = self.recorder.finish
        def finish(status, error_code=None):
            real_finish(status, error_code)
            elapsed.append(True)
        self.recorder.finish = finish
        clock = SimpleNamespace(monotonic=lambda: time.monotonic() + (1000 if elapsed else 0),
                                strftime=time.strftime, localtime=time.localtime)
        with patch('gateway.app.time', clock):
            response = self.post()
        self.assertEqual(504, response.status_code)
        self.assertEqual(b'', response.content)
        self.assertEqual('completed', self.recorder.status)
        self.assertEqual(self.recorder.request_id, response.headers['x-request-id'])
        prepared = json.loads(self.recorder.stages['restored']['body'])
        self.assertIn('张三', prepared['choices'][0]['message']['content'])

    def test_unavailable_required_history_prevents_supplier_call(self):
        self.store.fail_ready = True
        response = self.post()
        self.assertEqual(503, response.status_code)
        self.assertEqual([], self.transport.calls)

    def test_policy_block_is_retained_with_fixed_error(self):
        self.app.state.classifier = lambda _: 'FORBIDDEN'
        response = self.post()
        self.assertEqual(403, response.status_code, response.text)
        self.assertEqual('blocked', self.recorder.status)
        self.assertEqual([], self.transport.calls)
        self.assertEqual(self.raw, self.recorder.stages['input']['body'])
        self.assertNotIn('redacted', self.recorder.stages)
        self.assertEqual(response.content, self.recorder.stages['restored']['body'])
        self.assertEqual(self.recorder.request_id, response.headers['x-request-id'])

    def test_upstream_error_retains_body_but_releases_only_sanitized_error(self):
        self.transport.response_factory = lambda _: httpx.Response(500, content=b'CNRY-UPSTREAM-SECRET')
        response = self.post()
        self.assertEqual(500, response.status_code)
        self.assertEqual(b'CNRY-UPSTREAM-SECRET', self.recorder.stages['upstream']['body'])
        self.assertNotIn('CNRY-UPSTREAM-SECRET', response.text)
        self.assertEqual('failed', self.recorder.status)

    def stream_request(self, *, malformed=False):
        payload = json.loads(self.raw)
        payload['stream'] = True
        self.raw = json.dumps(payload, ensure_ascii=False).encode()
        def upstream(request):
            value = json.loads(request.content)
            def frame(delta, finish=None):
                return ('data: ' + json.dumps({'id': 'synthetic-stream', 'object': 'chat.completion.chunk',
                    'created': 1, 'model': value['model'], 'choices': [{'index': 0,
                        'delta': delta, 'finish_reason': finish}]}, ensure_ascii=False) + '\n\n').encode()
            self.supplier_response = frame({'content': value['messages'][0]['content']})
            self.supplier_response += (b'data: malformed\n\n' if malformed
                else frame({}, 'stop') + b'data: [DONE]\n\n')
            return httpx.Response(200, content=self.supplier_response, headers={'Content-Type': 'text/event-stream'})
        self.transport.response_factory = upstream

    def test_http_stream_records_exact_received_and_released_wire_bytes(self):
        self.stream_request()
        response = self.post()
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual(self.supplier_response, self.recorder.stages['upstream']['body'])
        self.assertEqual(response.content, self.recorder.stages['restored']['body'])
        self.assertEqual('completed', self.recorder.status)
        self.assertIn('张三', response.text)
        self.assertEqual(self.recorder.request_id, response.headers['x-request-id'])

    def test_http_stream_protocol_error_records_gateway_error_as_restored_only(self):
        self.stream_request(malformed=True)
        response = self.post()
        self.assertEqual(self.supplier_response, self.recorder.stages['upstream']['body'])
        self.assertEqual(response.content, self.recorder.stages['restored']['body'])
        self.assertNotIn('张三', response.text)
        self.assertIn('STREAM_PROTECTION_FAILED', response.text)
        self.assertEqual('partial', self.recorder.status)
        self.assertEqual('partial', self.recorder.stages['upstream']['state'])

    def test_http_stream_history_failure_does_not_release_business_or_unrecorded_error(self):
        self.stream_request()
        self.recorder.fail_stage = 'restored'
        response = self.post()
        self.assertEqual(b'', response.content)
        self.assertEqual('processing', self.recorder.status)
        self.assertEqual(self.supplier_response, self.recorder.stages['upstream']['body'])
        self.assertEqual('partial', self.recorder.stages['upstream']['state'])

    def test_stream_http_error_captures_supplier_error_without_releasing_it(self):
        self.stream_request()
        self.transport.response_factory = lambda _: httpx.Response(500, content=b'CNRY-STREAM-ERROR')
        response = self.post()
        self.assertEqual(500, response.status_code)
        self.assertEqual(b'CNRY-STREAM-ERROR', self.recorder.stages['upstream']['body'])
        self.assertNotIn('CNRY-STREAM-ERROR', response.text)
        self.assertEqual('failed', self.recorder.status)

    def test_received_nonstream_response_is_retained_even_if_send_exceeds_deadline(self):
        elapsed = []
        def upstream(request):
            response = self.upstream(request)
            elapsed.append(True)
            return response
        self.transport.response_factory = upstream
        clock = SimpleNamespace(monotonic=lambda: time.monotonic() + (1000 if elapsed else 0),
                                strftime=time.strftime, localtime=time.localtime)
        with patch('gateway.pipeline.time', clock):
            response = self.post()
        self.assertEqual(504, response.status_code)
        self.assertEqual(self.supplier_response, self.recorder.stages['upstream']['body'])
        self.assertEqual('complete', self.recorder.stages['upstream']['state'])
        self.assertNotIn('张三', response.text)

    def test_non200_stream_read_failure_retains_received_partial_and_closes(self):
        self.stream_request()
        closed = []
        class ErrorStream(httpx.SyncByteStream):
            def __iter__(self):
                yield b'CNRY-PARTIAL-ERROR'
                raise httpx.ReadError('synthetic read failure')
            def close(self):
                closed.append(True)
        self.transport.response_factory = lambda _: httpx.Response(500, stream=ErrorStream())
        response = self.post()
        self.assertEqual(500, response.status_code)
        self.assertEqual(b'CNRY-PARTIAL-ERROR', self.recorder.stages['upstream']['body'])
        self.assertEqual('partial', self.recorder.stages['upstream']['state'])
        self.assertNotIn('CNRY-PARTIAL-ERROR', response.text)
        self.assertEqual([True], closed)

    def test_non200_stream_chunk_received_after_deadline_is_saved_partial(self):
        self.stream_request()
        elapsed, closed = [], []
        class LateChunkStream(httpx.SyncByteStream):
            def __iter__(self):
                elapsed.append(True)
                yield b'CNRY-LATE-ERROR'
            def close(self):
                closed.append(True)
        self.transport.response_factory = lambda _: httpx.Response(500, stream=LateChunkStream())
        clock = SimpleNamespace(monotonic=lambda: time.monotonic() + (1000 if elapsed else 0),
                                strftime=time.strftime, localtime=time.localtime)
        with patch('gateway.pipeline.time', clock):
            response = self.post()
        self.assertEqual(504, response.status_code)
        self.assertEqual(b'CNRY-LATE-ERROR', self.recorder.stages['upstream']['body'])
        self.assertEqual('partial', self.recorder.stages['upstream']['state'])
        self.assertNotIn('CNRY-LATE-ERROR', response.text)
        self.assertEqual([True], closed)
