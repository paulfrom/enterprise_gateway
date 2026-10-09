"""Agent metadata never supplies authorization or bypasses text protection."""
import json
import unittest
from unittest.mock import MagicMock

from httpx import ASGITransport, AsyncClient

from detection.spans import Span
from gateway.app import create_app
from gateway.client_compatibility import compatible_payload
from gateway.ingress import IngressValidator
from gateway.provider_router import ProviderRouter
from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from masking.replacer import replace_request
from policy.policy import load_policy
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL
from protocol.identity import ByokAuthenticator, FORBIDDEN_CLIENT_IDENTITY_HEADERS


def agent_request():
    return {'model': 'test-model', 'stream': True,
            'stream_options': {'include_usage': True}, 'thinking': {'type': 'enabled'},
            'reasoning_effort': 'high',
            'messages': [{'role': 'user', 'content': [
                {'type': 'text', 'text': '合成甲公司'}, {'type': 'text', 'text': '合成乙公司'}],
                'agent': 'synthetic-agent', 'startsNewUserRequest': True,
                'conversationRequestId': 'synthetic-conversation'}],
            'tools': [{'type': 'function', 'function': {
                'name': 'synthetic_tool', 'description': 'Synthetic tool', 'strict': False,
                'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False}}}]}


class ClientCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.pipeline = MagicMock()
        self.pipeline.path = '/v1/chat/completions'
        self.pipeline.domain = 'server-domain'
        self.pipeline.request_timeout = 10
        self.pipeline.body_limit = 65536
        self.pipeline.process_request.return_value.upstream_stream = None
        self.pipeline.process_request.return_value.response.model_dump.return_value = {'id': 'controlled'}
        self.auth = ByokAuthenticator(domain='server-domain', tenant_id='server-tenant', correlation_key=b'c'*32)
        self.headers = {'Authorization': 'Bearer synthetic-key', 'x-api-key': 'synthetic-key',
                        'x-user-id': 'client-user', 'x-domain': 'client-domain'}

    def app(self, **kwargs):
        return create_app(router=ProviderRouter({'test-model': self.pipeline}),
            authenticator=self.auth, classifier=lambda raw: 'APPROVED', hmac_key=b'h'*32, **kwargs)

    async def post(self, app, payload):
        async with AsyncClient(transport=ASGITransport(app), base_url='http://test') as client:
            return await client.post('/v1/chat/completions', headers=self.headers, json=payload)

    async def test_default_accepts_agent_request_without_using_client_identity(self):
        response = await self.post(self.app(), agent_request())
        self.assertEqual(response.status_code, 200)
        args = self.pipeline.process_request.call_args.kwargs
        self.assertEqual(args['identity'].domain, 'server-domain')
        self.assertEqual(args['identity'].tenant_id, 'server-tenant')
        self.assertFalse(hasattr(args['identity'], 'roles'))
        self.assertNotIn('x-domain', args['headers'])
        self.assertNotIn('x-user-id', args['headers'])
        payload = json.loads(args['raw_body'])
        self.assertEqual(payload['messages'][0], agent_request()['messages'][0])
        policy = load_policy({'version': 'test', 'rules': [
            {'category': 'APPROVED', 'label': 'approved_external', 'scope': 'server-domain'}]})
        validated = IngressValidator.validate_request(raw_body=args['raw_body'],
            protocol=DEEPSEEK_CHAT_PROTOCOL, domain='server-domain', category='APPROVED',
            policy=policy, allowed_models=frozenset({'test-model'}))
        paths = {f.json_path: f for f in validated.fragments}
        spans = {path: () for path in paths}
        for index, text in enumerate(('合成甲公司', '合成乙公司')):
            path = f'messages[0].content[{index}].text'
            self.assertTrue(paths[path].editable)
            spans[path] = (Span(0, len(text), 'ORG', 1),)
        with MappingContext('server-domain', 'v1', b'h'*32) as context:
            redacted = replace_request(validated, spans, context).model_dump(exclude_none=True)
            for index, text in enumerate(('合成甲公司', '合成乙公司')):
                masked = redacted['messages'][0]['content'][index]['text']
                self.assertNotIn(text, masked)
                self.assertEqual(context.restore(masked), text)
        self.assertEqual(redacted['thinking'], {'type': 'enabled'})
        self.assertEqual(redacted['reasoning_effort'], 'high')
        self.assertEqual(redacted['stream_options'], {'include_usage': True})
        self.assertIs(redacted['tools'][0]['function']['strict'], False)

    async def test_history_and_classifier_receive_original_body(self):
        history = MagicMock()
        history.begin.return_value.request_id = 'synthetic-request'
        payload = agent_request()
        app = self.app(history_store=history)
        classified = []
        app.state.classifier = lambda raw: classified.append(json.loads(raw)) or 'APPROVED'
        response = await self.post(app, payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(history.begin.call_args.kwargs['raw_body']), payload)
        self.assertEqual(classified, [payload])

    async def test_followup_history_masks_assistant_reasoning_and_tool_results(self):
        payload = agent_request()
        history = {'conversationRequestId': 'synthetic-conversation', 'messageId': 'synthetic-message',
                   'model': 'client-model', 'requestModelId': 'client-model-id',
                   'requestModelName': 'client-model-name', 'traceId': 'synthetic-trace',
                   'argumentsDisplayText': 'synthetic display',
                   'rawUsage': {'prompt_tokens': 1}, 'usage': {'inputTokens': 1}}
        payload['messages'].extend([
            {**history, 'entryId': 'synthetic-entry', 'role': 'assistant',
             'content': [{'type': 'text', 'text': '合成甲公司', 'annotations': []}],
             'reasoning': '合成乙公司', 'reasoning_content': '合成乙公司',
             'tool_calls': [{'id': 'synthetic-call', 'type': 'function',
                             'function': {'name': 'synthetic_tool', 'arguments': '{}'}}]},
            {**history, 'role': 'tool', 'tool_call_id': 'synthetic-call', 'content': '合成丙公司'}])
        original = json.loads(json.dumps(payload))
        response = await self.post(self.app(), payload)
        self.assertEqual(response.status_code, 200)
        raw = self.pipeline.process_request.call_args.kwargs['raw_body']
        policy = load_policy({'version': 'test', 'rules': [
            {'category': 'APPROVED', 'label': 'approved_external', 'scope': 'server-domain'}]})
        validated = IngressValidator.validate_request(raw_body=raw, protocol=DEEPSEEK_CHAT_PROTOCOL,
            domain='server-domain', category='APPROVED', policy=policy, allowed_models=frozenset({'test-model'}))
        expected_paths = {'messages[1].content[0].text', 'messages[1].reasoning_content', 'messages[2].content'}
        self.assertTrue(expected_paths.issubset({f.json_path for f in validated.fragments}))
        self.assertEqual(payload, original)
        spans = {f.json_path: (Span(0, len(f.content), 'ORG', 1),) for f in validated.fragments}
        with MappingContext('server-domain', 'v1', b'h'*32) as context:
            redacted = replace_request(validated, spans, context).model_dump(exclude_none=True)
            assistant = redacted['messages'][1]
            for value, original_text in ((assistant['content'][0]['text'], '合成甲公司'),
                                         (assistant['reasoning_content'], '合成乙公司'),
                                         (redacted['messages'][2]['content'], '合成丙公司')):
                self.assertNotIn(original_text, value)
                self.assertEqual(context.restore(value), original_text)
            self.assertEqual(assistant['tool_calls'][0]['function']['arguments'], '{}')
            self.assertEqual(context.restore(assistant['reasoning']), '合成乙公司')
            self.assertEqual(assistant['content'][0]['annotations'], [])

    def test_history_metadata_and_annotations_are_preserved(self):
        for fields in ({'reasoning': 'one', 'reasoning_content': 'different'},
                       {'reasoning': {'text': 'unsupported'}}, {'messageId': 123},
                       {'argumentsDisplayText': {}}, {'rawUsage': 'unsupported'}, {'usage': []},
                       {'content': [{'type': 'text', 'text': 'hello', 'annotations': [{'unknown': 'secret'}]}]},
                       {'content': [{'type': 'text', 'text': 'hello', 'annotations': None}]}):
            with self.subTest(fields=fields):
                original = {'messages': [{'role': 'assistant', 'content': 'hello', **fields}]}
                self.assertEqual(compatible_payload(original), original)
        user = {'messages': [{'role': 'user', 'content': 'hello', 'reasoning': 'untrusted'}]}
        self.assertEqual(compatible_payload(user), user)
        canonical = compatible_payload({'messages': [{'role': 'assistant', 'content': 'hello', 'reasoning': 'thinking'}]})
        self.assertEqual(canonical['messages'][0]['reasoning_content'], 'thinking')

    async def test_client_claims_cannot_change_scope_roles_or_acl(self):
        self.headers.update({name: 'client-claim' for name in FORBIDDEN_CLIENT_IDENTITY_HEADERS})
        response = await self.post(self.app(), agent_request())
        self.assertEqual(response.status_code, 200)
        args = self.pipeline.process_request.call_args.kwargs
        expected = self.auth.authenticate({'Authorization': 'Bearer synthetic-key'})
        for field in ('source_id', 'tenant_id', 'domain', 'purposes', 'source_acl'):
            self.assertEqual(getattr(expected, field), getattr(args['identity'], field))
        self.assertFalse(FORBIDDEN_CLIENT_IDENTITY_HEADERS.intersection(args['headers']))

    async def test_explicit_strict_profile_still_rejects_client_identity(self):
        response = await self.post(self.app(client_profile='strict'), agent_request())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error']['code'], SafetyCode.UNTRUSTED_HEADER_REJECTED.value)
        self.pipeline.process_request.assert_not_called()

    async def test_opaque_metadata_is_preserved_without_rejection(self):
        payload = agent_request()
        payload['messages'][0]['startsNewUserRequest'] = 'true'
        response = await self.post(self.app(), payload)
        self.assertEqual(response.status_code, 200)
        sent = json.loads(self.pipeline.process_request.call_args.kwargs['raw_body'])
        self.assertEqual(sent, payload)

    def test_unknown_profile_refuses_assembly(self):
        with self.assertRaises(SafetyError):
            self.app(client_profile='unknown')
