"""Real readiness gates keep health responsive while hashing a shared runtime."""
import asyncio
import threading
import unittest
import httpx
from gateway.app import create_app
from gateway.provider_router import ProviderRouter
from protocol.identity import ByokAuthenticator
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL
from tests.integration import test_integration_roundtrip as roundtrip

class ReadinessConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_model_aliases_do_not_duplicate_or_block_inflight_gate(self):
        fixture = roundtrip.IntegrationRoundtripTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        pipeline = fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, roundtrip.UpstreamSpyTransport(
            lambda request: self.fail('readiness must never call a supplier')),
            allowed_models=frozenset({'deepseek-flash', 'deepseek-v4-pro'}))
        entered, release = threading.Event(), threading.Event()
        original = pipeline._component_payloads
        calls = []
        def hashing():
            calls.append(True); entered.set()
            if not release.wait(5): raise RuntimeError('test gate release deadline')
            return original()
        pipeline._component_payloads = hashing
        app = create_app(router=ProviderRouter({model: pipeline for model in pipeline.allowed_models}),
                         authenticator=ByokAuthenticator(domain=fixture.domain,
                             tenant_id=fixture.identity.tenant_id, correlation_key=roundtrip.TEST_HMAC_KEY),
                         classifier=lambda body: 'STANDARD', hmac_key=roundtrip.TEST_HMAC_KEY)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://gateway') as client:
            first = asyncio.create_task(client.get('/readyz'))
            second = asyncio.create_task(client.get('/readyz'))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                health = await asyncio.wait_for(client.get('/healthz'), 2)
                self.assertEqual(200, health.status_code)
                self.assertEqual(1, len(calls))
            finally:
                release.set()
            self.assertEqual([200, 200], [response.status_code for response in await asyncio.gather(first, second)])
            self.assertEqual(200, (await client.get('/readyz')).status_code)
            self.assertEqual(2, len(calls), 'completed success must not be cached')
            pipeline._component_payloads = lambda: (_ for _ in ()).throw(RuntimeError('synthetic hash failure'))
            failure = await client.get('/readyz')
            self.assertEqual(503, failure.status_code)
            self.assertIn('validated_protection_and_durable_resources', failure.json()['missing_gates'])
