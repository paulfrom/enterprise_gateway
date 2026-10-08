import unittest
from unittest.mock import MagicMock
from httpx import ASGITransport, AsyncClient
from gateway.app import create_app
from gateway.provider_router import ProviderRouter
from protocol.identity import ByokAuthenticator, UnverifiedSourceContext


class ByokAdmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.pipeline = MagicMock()
        self.pipeline.path = '/v1/chat/completions'
        self.pipeline.domain = 'corp.test'
        self.pipeline.request_timeout = 10
        self.pipeline.body_limit = 65536
        result = self.pipeline.process_request.return_value
        result.upstream_stream = None
        result.response.model_dump.return_value = {'id': 'controlled'}
        self.router = ProviderRouter({'test-model': self.pipeline})
        self.auth = ByokAuthenticator(domain='corp.test', tenant_id='test-tenant', correlation_key=b'c'*32)

    def app(self, classifier=None, router=None):
        return create_app(router=router if router is not None else self.router,
                          authenticator=self.auth, classifier=classifier, hmac_key=b'h'*32)

    async def post(self, app, *, headers=None, content=None):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
            return await client.post('/v1/chat/completions', headers=headers or {'Authorization': 'Bearer synthetic-key'},
                                     content=content or '{"model":"test-model","messages":[{"role":"user","content":"synthetic"}]}')

    async def test_missing_classifier_rejects_without_processing(self):
        res = await self.post(self.app())
        self.assertEqual(res.status_code, 503)
        self.pipeline.process_request.assert_not_called()

    async def test_object_router_and_missing_resources_never_ready(self):
        for router in (object(), self.router):
            async with AsyncClient(transport=ASGITransport(app=self.app(lambda raw: 'TEST', router)), base_url='http://test') as client:
                self.assertEqual((await client.get('/readyz')).status_code, 503)

    async def test_controlled_classification_and_source_context_reach_pipeline(self):
        res = await self.post(self.app(lambda raw: 'TEST_APPROVED'))
        self.assertEqual(res.status_code, 200)
        kw = self.pipeline.process_request.call_args.kwargs
        self.assertEqual(kw['category'], 'TEST_APPROVED')
        self.assertIsInstance(kw['identity'], UnverifiedSourceContext)
        self.assertFalse(hasattr(kw['identity'], 'roles'))

    async def test_duplicate_model_and_credential_reject_before_processing(self):
        for content, headers in [('{"model":"test-model","model":"test-model"}', None),
                                 (None, [('authorization', 'Bearer one'), ('authorization', 'Bearer two')]),
                                 (None, {'authorization': 'Bearer one', 'x-api-key': 'two'})]:
            res = await self.post(self.app(lambda raw: 'TEST'), content=content, headers=headers)
            self.assertIn(res.status_code, (400, 401))
        self.pipeline.process_request.assert_not_called()

    async def test_unknown_classification_and_forged_source_header_rejected(self):
        res = await self.post(self.app(lambda raw: ''))
        self.assertEqual(res.status_code, 403)
        res = await self.post(self.app(lambda raw: 'TEST'), headers={'authorization': 'Bearer synthetic', 'x-domain': 'other'})
        self.assertEqual(res.status_code, 400)
        self.pipeline.process_request.assert_not_called()
