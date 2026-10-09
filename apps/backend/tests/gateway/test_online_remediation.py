import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from dataclasses import replace
import hmac
import json
from httpx import ASGITransport, AsyncClient
from gateway.app import create_app, _render_safety_error
from infra.errors import SafetyCode, SafetyError
from protocol.identity import TrustedIdentity, ByokAuthenticator
from gateway.provider_router import ProviderRouter
from protocol.history_state import HistoricalStateAdapter, ReasoningStateValidator, ReasoningBlock, ProviderStateVerifier
from tests.integration import test_integration_roundtrip as fixture_module
from tests.integration.test_integration_roundtrip import UpstreamSpyTransport
from tests.integration.test_integration_roundtrip import TEST_HMAC_KEY
from masking.mapping import MappingContext
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL
import httpx


def synthetic_hmac_verifier(block, material):
    return hmac.compare_digest(block.signature, hmac.digest(material, block.content.encode(), 'sha256').hex())


class OnlineRegressionTests(unittest.IsolatedAsyncioTestCase):
    def test_verifier_actual_key_material_changes_complete_package_hash(self):
        fixture = fixture_module.IntegrationRoundtripTests(); fixture.setUp()
        try:
            verifiers = [ProviderStateVerifier(synthetic_hmac_verifier, key) for key in (b'a' * 32, b'b' * 32)]
            self.assertEqual(verifiers[0].algorithm.__code__, verifiers[1].algorithm.__code__)
            hashes = []
            for verify in verifiers:
                trust = HistoricalStateAdapter(ReasoningStateValidator(TEST_HMAC_KEY,
                    scope=fixture.domain, version='same-input-version', provider_verifier=verify))
                pipeline = fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL,
                    UpstreamSpyTransport(lambda req: httpx.Response(500)), history_adapter=trust)
                hashes.append(pipeline.version_handle.package_hash)
            self.assertNotEqual(hashes[0], hashes[1], 'actual verifier key material must bind the complete package')
        finally:
            fixture.tearDown()

    def test_replacing_actual_verifier_material_after_assembly_has_zero_egress(self):
        fixture = fixture_module.IntegrationRoundtripTests(); fixture.setUp()
        try:
            trust = HistoricalStateAdapter(ReasoningStateValidator(TEST_HMAC_KEY,
                scope=fixture.domain, version='same-input-version',
                provider_verifier=ProviderStateVerifier(synthetic_hmac_verifier, b'a' * 32)))
            spy = UpstreamSpyTransport(lambda req: self.fail('changed verifier material must not leave gateway'))
            pipeline = fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy, history_adapter=trust)
            from dataclasses import FrozenInstanceError
            with self.assertRaises(FrozenInstanceError):
                pipeline.history_adapter.validator._provider_verifier = ProviderStateVerifier(synthetic_hmac_verifier, b'b' * 32)
            object.__setattr__(pipeline.history_adapter.validator, '_provider_verifier', ProviderStateVerifier(synthetic_hmac_verifier, b'b' * 32))
            with MappingContext(fixture.domain, 'v1', TEST_HMAC_KEY) as context:
                with self.assertRaises(SafetyError):
                    pipeline.process_request(raw_body=json.dumps({'model': 'deepseek-flash',
                        'messages': [{'role': 'user', 'content': 'hello'}]}), headers={},
                        identity=fixture.identity, category='STANDARD', context=context)
            self.assertEqual([], spy.calls)
        finally:
            fixture.tearDown()

    def test_route_configuration_is_copied_and_immutable(self):
        fixture = fixture_module.IntegrationRoundtripTests(); fixture.setUp()
        try:
            source_models = {'deepseek-flash': 'original-provider'}
            pipeline = fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL,
                UpstreamSpyTransport(lambda req: httpx.Response(500)), model_mapping=source_models)
            source_models['deepseek-flash'] = 'unadmitted-provider'
            self.assertEqual('original-provider', pipeline.model_mapping['deepseek-flash'])
            with self.assertRaises(TypeError):
                pipeline.model_mapping['deepseek-flash'] = 'unadmitted-provider'
            for field in ('model_mapping', 'allowed_models', 'protocol', 'path', 'channel_id',
                          'domain', 'package_version', 'request_timeout', 'egress_client', 'history_adapter'):
                with self.subTest(field=field), self.assertRaises(AttributeError):
                    setattr(pipeline, field, getattr(pipeline, field))
        finally:
            fixture.tearDown()

    def test_model_route_mutation_after_gate_cannot_change_inflight_provider(self):
        fixture = fixture_module.IntegrationRoundtripTests(); fixture.setUp()
        try:
            def respond(req):
                body = json.loads(req.content)
                return httpx.Response(200, json={'id': 'route-proof', 'object': 'chat.completion',
                    'created': 1, 'model': body['model'], 'choices': [{'index': 0,
                    'message': {'role': 'assistant', 'content': body['messages'][0]['content']},
                    'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}})
            spy = UpstreamSpyTransport(respond)
            pipeline = fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)
            detect = fixture.detector.detect_many
            def mutate_after_complete_package_check(*args, **kwargs):
                try:
                    pipeline.model_mapping['deepseek-flash'] = 'unadmitted-inflight-provider'
                except TypeError:
                    pass  # Immutable route rejects the attempted shared update.
                # Simulate an illegal concurrent replacement of the private
                # assembly object. The already-bound request still uses its snapshot.
                pipeline._route = replace(pipeline._route,
                    model_mapping={'deepseek-flash': 'unadmitted-inflight-provider'})
                return detect(*args, **kwargs)
            with patch.object(fixture.detector, 'detect_many', side_effect=mutate_after_complete_package_check):
                with MappingContext(fixture.domain, 'v1', TEST_HMAC_KEY) as context:
                    pipeline.process_request(raw_body=json.dumps({'model': 'deepseek-flash',
                        'messages': [{'role': 'user', 'content': '请查询阿尔法科技的张三。'}]}),
                        headers={'authorization':'Bearer synthetic-client-key'}, identity=fixture.identity, category='STANDARD', context=context)
            self.assertEqual(1, len(spy.calls))
            self.assertEqual('deepseek-flash', json.loads(spy.calls[0].content)['model'])
            with MappingContext(fixture.domain, 'v1', TEST_HMAC_KEY) as context:
                with self.assertRaises(SafetyError):
                    pipeline.process_request(raw_body=json.dumps({'model': 'deepseek-flash',
                        'messages': [{'role': 'user', 'content': 'hello'}]}), headers={},
                        identity=fixture.identity, category='STANDARD', context=context)
            self.assertEqual(1, len(spy.calls))
        finally:
            fixture.tearDown()

    def test_receipts_bind_full_assembly_hash_across_same_named_versions(self):
        fixture=fixture_module.IntegrationRoundtripTests();fixture.setUp()
        try:
            # Synthetic proof is only a fixture; real supplier proof remains unverified.
            provider_material=b'synthetic-provider-material-32-bytes'
            trust=HistoricalStateAdapter(ReasoningStateValidator(b'fixture-verification-key-32-bytes!',
                scope=fixture.domain,version='input-version',provider_verifier=ProviderStateVerifier(synthetic_hmac_verifier,provider_material)))
            spy=UpstreamSpyTransport(lambda _:httpx.Response(500))
            first=fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL,spy,history_adapter=trust)
            second=fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL,spy,history_adapter=trust,
                model_mapping={'deepseek-flash':'different-bound-provider'})
            self.assertEqual(first.package_version,second.package_version)
            self.assertNotEqual(first.version_handle.package_hash,second.version_handle.package_hash)
            signature=hmac.digest(provider_material,b'public fixture','sha256').hex()
            proof=first.history_adapter.validator.admit_upstream_block(ReasoningBlock('thinking','public fixture',signature,{}))
            self.assertEqual(first.version_handle.package_hash,proof.metadata['version'])
            first.history_adapter.validator.verify_reasoning_block(proof)
            with self.assertRaises(SafetyError):second.history_adapter.validator.verify_reasoning_block(proof)
            self.assertEqual([],spy.calls)
        finally:fixture.tearDown()

    def test_protocol_error_is_controlled(self):
        self.assertEqual(_render_safety_error(SafetyError(SafetyCode.PROTOCOL_VIOLATION)).status_code, 400)

    async def test_byok_missing_and_malformed_credential_never_processes(self):
        pipeline = MagicMock()
        app = create_app(router=ProviderRouter({'synthetic':pipeline}),
            authenticator=ByokAuthenticator(domain='corp.test',tenant_id='test',correlation_key=b'c'*32),
            classifier=lambda _: 'STANDARD',hmac_key=b'h'*32)
        async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
            for headers in ({},{'authorization':'invalid-scheme'}):
                response = await client.post('/v1/chat/completions',json={'model':'synthetic','messages':[{'role':'user','content':'hi'}]},headers=headers)
                self.assertEqual(response.status_code,401)
        pipeline.process_request.assert_not_called()
