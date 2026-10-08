"""M3 HTTP lifecycle assertions with trained NER and synthetic provider bytes.

The direct ASGI harness sends an actual http.disconnect into the public app;
it does not bypass authentication, inference, audit, spool or stream protection.
"""
import asyncio
import json
import threading
import unittest
from unittest.mock import patch

import httpx

from gateway.app import create_app
from gateway.provider_router import ProviderRouter
from protocol.identity import ByokAuthenticator
from gateway.streaming import ProtectedStream
from masking.mapping import MappingContext
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL
from tests.integration import test_protocol_matrix as matrix
from tests.integration.test_integration_roundtrip import UpstreamSpyTransport, TEST_HMAC_KEY


PROTOCOLS = (DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL)


def frame(value, event=None):
    return ((f"event: {event}\n" if event else "") + "data: " +
            json.dumps(value, ensure_ascii=False) + "\n\n").encode()


def payloads(raw):
    return [json.loads(line[6:]) for line in raw.splitlines()
            if line.startswith('data: ') and line != 'data: [DONE]']


class BlockingProviderStream(httpx.SyncByteStream):
    """Yield partial tool arguments, then block until the app closes upstream."""
    def __init__(self, first):
        self.first = first
        self.read_started = threading.Event()
        self.closed = threading.Event()
        self.read_finished = threading.Event()

    def __iter__(self):
        yield self.first
        self.read_started.set()
        try:
            if not self.closed.wait(8):
                raise RuntimeError('upstream read was not interrupted by close')
        finally:
            self.read_finished.set()

    def close(self):
        self.closed.set()


class ProtocolLifecycleHttpTests(unittest.IsolatedAsyncioTestCase):
    setUp = matrix.ProtocolHttpMatrix.setUp
    tearDown = matrix.ProtocolHttpMatrix.tearDown
    request = matrix.ProtocolHttpMatrix.request
    response = matrix.ProtocolHttpMatrix.response
    call = matrix.ProtocolHttpMatrix.call

    async def test_http_disconnect_before_stream_delivery_closes_abandoned_response(self):
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                entered=threading.Event();release=threading.Event();disconnected=asyncio.Event()
                providers=[];sent=[];received=False
                def respond(req):
                    entered.set()
                    if not release.wait(8):raise RuntimeError('test release deadline')
                    provider=BlockingProviderStream(b'')
                    providers.append(provider)
                    return httpx.Response(200,headers={'content-type':'text/event-stream'},stream=provider)
                spy=UpstreamSpyTransport(respond)
                pipeline=self.fixture._create_pipeline(protocol,spy)
                app=create_app(router=ProviderRouter({model: pipeline for model in pipeline.allowed_models}), authenticator=ByokAuthenticator(domain=self.fixture.identity.domain, tenant_id=self.fixture.identity.tenant_id, correlation_key=TEST_HMAC_KEY), classifier=lambda raw: "STANDARD", hmac_key=TEST_HMAC_KEY)
                async def receive():
                    nonlocal received
                    if not received:
                        received=True
                        return {'type':'http.request','body':json.dumps(self.request(protocol,True)).encode(),'more_body':False}
                    await disconnected.wait()
                    return {'type':'http.disconnect'}
                async def send(message):sent.append(message)
                scope={'type':'http','asgi':{'version':'3.0','spec_version':'2.3'},'http_version':'1.1',
                       'method':'POST','scheme':'http','path':pipeline.path,'raw_path':pipeline.path.encode(),
                       'query_string':b'','root_path':'','headers':[(b'host',b'gateway'),(b'content-type',b'application/json'),
                       (b'authorization',b'Bearer enterprise-token')],'client':('127.0.0.1',12345),'server':('gateway',80)}
                task=asyncio.create_task(app(scope,receive,send))
                try:
                    self.assertTrue(await asyncio.to_thread(entered.wait,60))
                    disconnected.set()
                    await asyncio.sleep(0.1)
                    release.set()
                    await asyncio.wait_for(task,10)
                    app_closed=providers[0].closed.is_set()
                finally:
                    release.set()
                    if not task.done():task.cancel()
                    await asyncio.gather(task,return_exceptions=True)
                    for provider in providers:provider.close()
                self.assertTrue(app_closed,'response returned after disconnect must be closed by the app')
                self.assertNotIn('阿尔法科技',str(sent))

    def parallel_frames(self, req, protocol, bad=False):
        body = json.loads(req.content)
        self.assertNotIn('阿尔法科技', req.content.decode())
        self.assertNotIn('张三', req.content.decode())
        text = body['messages'][0]['content']
        args = [json.dumps({'org': text + suffix}, ensure_ascii=False)
                for suffix in (' first', ' second')]
        if bad:
            args[1] = json.dumps({'org': 32, 'unknown': True})
        cuts = [len(value) // 2 for value in args]
        if protocol == DEEPSEEK_CHAT_PROTOCOL:
            base = {'id': 'parallel', 'object': 'chat.completion.chunk',
                    'created': 1, 'model': body['model']}
            def chat(delta, finish=None, usage=None):
                return frame({**base, 'choices': [{'index': 0, 'delta': delta,
                            'finish_reason': finish}], **({'usage': usage} if usage else {})})
            result = [chat({'role': 'assistant'})]
            for index in (0, 1):
                result.append(chat({'tool_calls': [{'index': index,
                    'id': f'call-{index}', 'type': 'function',
                    'function': {'name': 'lookup', 'arguments': args[index][:cuts[index]]}}]}))
            for index in (1, 0):
                result.append(chat({'tool_calls': [{'index': index,
                    'function': {'arguments': args[index][cuts[index]:]}}]}))
            result += [chat({}, 'tool_calls', {'prompt_tokens': 3,
                       'completion_tokens': 4, 'total_tokens': 7}), b'data: [DONE]\n\n']
        else:
            events = [{'type': 'message_start', 'message': {'id': 'parallel',
                'type': 'message', 'role': 'assistant', 'model': body['model'],
                'content': [], 'stop_reason': None, 'stop_sequence': None,
                'usage': {'input_tokens': 3, 'output_tokens': 0}}}]
            for index in (0, 1):
                events.append({'type': 'content_block_start', 'index': index,
                    'content_block': {'type': 'tool_use', 'id': f'call-{index}',
                                      'name': 'lookup', 'input': {}}})
            for part, order in ((0, (0, 1)), (1, (1, 0))):
                for index in order:
                    value = args[index][:cuts[index]] if part == 0 else args[index][cuts[index]:]
                    events.append({'type': 'content_block_delta', 'index': index,
                        'delta': {'type': 'input_json_delta', 'partial_json': value}})
            events += [{'type': 'content_block_stop', 'index': index} for index in (0, 1)]
            events += [{'type': 'message_delta', 'delta': {'stop_reason': 'tool_use',
                'stop_sequence': None}, 'usage': {'output_tokens': 4}}, {'type': 'message_stop'}]
            result = [frame(event, event['type']) for event in events]
        return result

    async def test_parallel_tool_fragments_and_atomic_rejection_both_protocols(self):
        for protocol in PROTOCOLS:
            for bad in (False, True):
                with self.subTest(protocol=protocol, bad=bad):
                    response, spy = await self.call(protocol, self.request(protocol, True, True),
                        lambda req: httpx.Response(200, headers={'content-type': 'text/event-stream'},
                            content=b''.join(self.parallel_frames(req, protocol, bad))))
                    self.assertEqual(200, response.status_code, response.text)
                    self.assertEqual(1, len(spy.calls))
                    self.assertNotIn('<<ENT', response.text)
                    events = payloads(response.text)
                    if bad:
                        self.assertIn('STREAM_PROTECTION_FAILED', response.text)
                        self.assertNotIn('call-0', response.text)
                        self.assertNotIn('call-1', response.text)
                        self.assertNotIn('tool_calls', response.text)
                        self.assertNotIn('partial_json', response.text)
                        continue
                    self.assertNotIn('error', response.text)
                    if protocol == DEEPSEEK_CHAT_PROTOCOL:
                        calls = [call for event in events for choice in event['choices']
                                 for call in choice['delta'].get('tool_calls', [])]
                        restored = {call['id']: json.loads(call['function']['arguments']) for call in calls}
                        self.assertEqual({'prompt_tokens': 3, 'completion_tokens': 4, 'total_tokens': 7}, events[-1]['usage'])
                    else:
                        starts = {event['index']: event['content_block']['id'] for event in events
                                  if event['type'] == 'content_block_start'}
                        restored = {starts[event['index']]: json.loads(event['delta']['partial_json'])
                                    for event in events if event['type'] == 'content_block_delta'}
                        self.assertEqual({'output_tokens': 4}, events[-2]['usage'])
                    self.assertEqual({'call-0': {'org': '请查询阿尔法科技的张三。 first'},
                                      'call-1': {'org': '请查询阿尔法科技的张三。 second'}}, restored)

    async def test_five_actual_http_turns_rescan_all_history_and_destroy_mappings(self):
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                contexts = []
                def new_context(*args, **kwargs):
                    context = MappingContext(*args, **kwargs)
                    contexts.append(context)
                    return context
                def respond(req):
                    self.assertNotIn('阿尔法科技', req.content.decode())
                    self.assertNotIn('张三', req.content.decode())
                    outgoing = json.loads(req.content)
                    self.assertEqual(2 * len(spy.calls) - 1, len(outgoing['messages']))
                    return self.response(req, protocol, False, False)
                spy = UpstreamSpyTransport(respond)
                pipeline = self.fixture._create_pipeline(protocol, spy)
                app = create_app(router=ProviderRouter({model: pipeline for model in pipeline.allowed_models}), authenticator=ByokAuthenticator(domain=self.fixture.identity.domain, tenant_id=self.fixture.identity.tenant_id, correlation_key=TEST_HMAC_KEY), classifier=lambda raw: "STANDARD", hmac_key=TEST_HMAC_KEY)
                body = self.request(protocol)
                with patch('gateway.app.MappingContext', side_effect=new_context):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://gateway') as client:
                        for turn in range(5):
                            result = await client.post(pipeline.path, json=body,
                                headers={'authorization': 'Bearer enterprise-token'})
                            self.assertEqual(200, result.status_code, result.text)
                            self.assertIn('阿尔法科技', result.text)
                            self.assertIn('张三', result.text)
                            self.assertNotIn('<<ENT', result.text)
                            reply = result.json()
                            assistant = reply['choices'][0]['message'] if protocol == DEEPSEEK_CHAT_PROTOCOL else {
                                'role': 'assistant', 'content': reply['content']}
                            body['messages'].extend([assistant, {'role': 'user',
                                'content': f'第{turn + 2}轮请核对阿尔法科技的张三。'}])
                self.assertEqual(5, len(spy.calls))
                self.assertEqual(5, len(contexts))
                self.assertEqual(5, len({id(context) for context in contexts}))
                for context in contexts:
                    self.assertFalse(context._active)
                    self.assertTrue(context._closed)
                    self.assertEqual(0, context.entry_count)
                    self.assertEqual(b'', context.key)

    async def test_unproven_history_and_upstream_errors_have_zero_plaintext_release(self):
        for protocol in PROTOCOLS:
            history = ([{'role': 'assistant', 'content': 'hello', 'reasoning_content': 'unproved'},
                        {'role': 'assistant', 'content': 'hello', 'compression': 'unproved'}]
                       if protocol == DEEPSEEK_CHAT_PROTOCOL else
                       [{'role': 'assistant', 'content': [{'type': 'thinking', 'thinking': 'unproved', 'signature': 'fake'}]},
                        {'role': 'assistant', 'content': [{'type': 'redacted_thinking', 'data': 'unproved'}]},
                        {'role': 'assistant', 'content': [{'type': 'thinking', 'thinking': 'unproved', 'signature': 'fake',
                            'metadata': {'scope': self.fixture.domain, 'version': 'fake', 'receipt': 'fake'}}]}])
            for message in history:
                body = self.request(protocol)
                body['messages'].insert(0, message)
                result, spy = await self.call(protocol, body, lambda req: self.fail('unproven state must not leave'))
                self.assertEqual(400, result.status_code, result.text)
                self.assertEqual(0, len(spy.calls))
            result, spy = await self.call(protocol, self.request(protocol),
                lambda req: httpx.Response(429, headers={'retry-after': '12'}, content=b'CANARY_RAW_ERROR'))
            self.assertEqual(429, result.status_code, result.text)
            self.assertEqual('12', result.headers['retry-after'])
            self.assertNotIn('CANARY_RAW_ERROR', result.text)
            self.assertEqual(1, len(spy.calls))

    async def test_missing_eof_terminal_and_late_provider_frames_release_no_business(self):
        for protocol in PROTOCOLS:
            for corruption in ('missing-terminal', 'late-frame'):
                with self.subTest(protocol=protocol, corruption=corruption):
                    def respond(req):
                        complete = self.response(req, protocol, True, False).content
                        if corruption == 'missing-terminal':
                            wire = complete.rsplit(b'\n\n', 2)[0] + b'\n\n'
                        else:
                            wire = complete + frame({'unsafe': 'CANARY_LATE_FRAME'}, 'message_delta'
                                                    if protocol == CLAUDE_MESSAGES_PROTOCOL else None)
                        return httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=wire)
                    result, spy = await self.call(protocol, self.request(protocol, True), respond)
                    self.assertEqual(200, result.status_code, result.text)
                    self.assertEqual(1, len(spy.calls))
                    self.assertIn('STREAM_PROTECTION_FAILED', result.text)
                    self.assertNotIn('阿尔法科技', result.text)
                    self.assertNotIn('张三', result.text)
                    self.assertNotIn('<<ENT', result.text)
                    self.assertNotIn('CANARY_LATE_FRAME', result.text)
                    self.assertNotIn('chat.completion.chunk', result.text)
                    self.assertNotIn('message_start', result.text)

    async def test_http_disconnect_closes_blocked_upstream_and_clears_request_state(self):
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                providers, streams = [], []
                disconnected = asyncio.Event()
                sent = []
                body = self.request(protocol, True, True)
                def respond(req):
                    frames = self.parallel_frames(req, protocol)
                    # Preserve an unfinished tool buffer while upstream read blocks.
                    first = b''.join(frames[:3] if protocol == DEEPSEEK_CHAT_PROTOCOL else frames[:4])
                    provider = BlockingProviderStream(first)
                    providers.append(provider)
                    return httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=provider)
                spy = UpstreamSpyTransport(respond)
                pipeline = self.fixture._create_pipeline(protocol, spy)
                app = create_app(router=ProviderRouter({model: pipeline for model in pipeline.allowed_models}), authenticator=ByokAuthenticator(domain=self.fixture.identity.domain, tenant_id=self.fixture.identity.tenant_id, correlation_key=TEST_HMAC_KEY), classifier=lambda raw: "STANDARD", hmac_key=TEST_HMAC_KEY)
                received_body = False
                async def receive():
                    nonlocal received_body
                    if not received_body:
                        received_body = True
                        return {'type': 'http.request', 'body': json.dumps(body).encode(), 'more_body': False}
                    await disconnected.wait()
                    return {'type': 'http.disconnect'}
                async def send(message):
                    sent.append(message)
                def new_stream(*args, **kwargs):
                    stream = ProtectedStream(*args, **kwargs)
                    streams.append(stream)
                    return stream
                scope = {'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.3'},
                    'http_version': '1.1', 'method': 'POST', 'scheme': 'http', 'path': pipeline.path,
                    'raw_path': pipeline.path.encode(), 'query_string': b'', 'root_path': '',
                    'headers': [(b'host', b'gateway'), (b'content-type', b'application/json'),
                                (b'authorization', b'Bearer enterprise-token')],
                    'client': ('127.0.0.1', 12345), 'server': ('gateway', 80)}
                with patch('gateway.streaming.ProtectedStream', side_effect=new_stream):
                    task = asyncio.create_task(app(scope, receive, send))
                    app_closed_upstream = False
                    try:
                        async with asyncio.timeout(60):
                            while not providers or not providers[0].read_started.is_set():
                                if task.done():
                                    await task
                                    self.fail(f'app exited before blocked stream: {sent}')
                                await asyncio.sleep(0.02)
                        self.assertEqual(200, sent[0]['status'])
                        self.assertGreater(streams[0].context.entry_count, 0)
                        self.assertGreater(streams[0].tools._total_bytes, 0)
                        self.assertFalse(providers[0].closed.is_set())
                        disconnected.set()
                        await asyncio.wait_for(task, timeout=3)
                        app_closed_upstream = providers[0].closed.is_set()
                    finally:
                        disconnected.set()
                        if not task.done():
                            task.cancel()
                            await asyncio.gather(task, return_exceptions=True)
                        for provider in providers:
                            provider.close()
                self.assertEqual(1, len(spy.calls))
                self.assertTrue(app_closed_upstream,
                    'public app did not close upstream on disconnect; '
                    f'protection_closed={streams[0]._closed}, '
                    f'mapping_active={streams[0].context._active}, '
                    f'mapping_entries={streams[0].context.entry_count}, '
                    f'tool_bytes={streams[0].tools._total_bytes}')
                self.assertTrue(await asyncio.to_thread(providers[0].read_finished.wait, 1))
                stream = streams[0]
                self.assertTrue(stream._closed)
                self.assertEqual([], stream._pending_frames)
                self.assertEqual(0, stream._pending_bytes)
                self.assertEqual({}, stream._blocks)
                self.assertEqual({}, stream._tool_calls)
                self.assertEqual({}, stream.tools._buffers)
                self.assertEqual({}, stream.restorer._buffers)
                self.assertEqual(0, stream.context.entry_count)
                self.assertFalse(stream.context._active)
                self.assertEqual(b'', stream.context.key)
                raw = b''.join(message.get('body', b'') for message in sent)
                self.assertNotIn(b'call-0', raw)
                self.assertNotIn(b'partial_json', raw)
                self.assertNotIn(b'tool_calls', raw)
                self.assertEqual((0, 0), self.fixture.executor.snapshot())
                # Reuse the exact app, detector and limiter after cancellation.
                spy.response_factory = lambda req: self.response(req, protocol, False, False)
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://gateway') as client:
                    result = await client.post(pipeline.path, json=self.request(protocol),
                        headers={'authorization': 'Bearer enterprise-token'})
                self.assertEqual(200, result.status_code, result.text)
                self.assertEqual(2, len(spy.calls))
