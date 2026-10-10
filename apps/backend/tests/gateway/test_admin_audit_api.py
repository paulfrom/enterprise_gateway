"""HTTP audit read contract, real durable catalog and paired access events."""
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from audit.admin_reader import AdminReviewService
from gateway.admin_audit_api import revalidate_audit_session
from gateway.app import create_app
from infra.envelope_crypto import StaticTestKmsProvider
from tests.audit.test_admin_reader import write_record, build_catalog, EVIDENCE_PURPOSE, CANARY
from tests.gateway.test_admin_knowledge_api import KnowledgeApiFixture, TestClientBridge, write_headers

ROUTES = ['/api/admin/audit/records', '/api/admin/audit/records/ev-admin', '/api/admin/audit/events']


class AdminAuditApiTests(unittest.TestCase):
    def setUp(self):
        self.fixture = KnowledgeApiFixture()
        self.addCleanup(self.fixture.cleanup)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.kms = StaticTestKmsProvider()
        write_record(self.root, self.kms, record_id='ev-admin', tenant_id='tenant-a', domain='domain-b')
        self.assertEqual(build_catalog(self.root), 1)
        self.reader = AdminReviewService(catalog_directory=self.root/'catalog', evidence_root=self.root/'evidence',
            kms=self.kms, revalidate=revalidate_audit_session, review_purpose=EVIDENCE_PURPOSE,
            access_log_directory=self.root/'access-log')
        self.app = create_app(admin_service=self.fixture.service, knowledge_governance=None,
            audit_reader=self.reader, audit_builder=None)
        self.client = TestClientBridge(self.app)
        self.addCleanup(self.client.close)
        self.headers = write_headers(self.fixture.token, None)

    def test_all_routes_unauthenticated_before_storage_and_decrypt(self):
        with patch.object(self.reader, 'list_records') as listing, patch.object(self.reader, 'read_plaintext') as plaintext, patch.object(self.reader, 'list_events') as events:
            for route in ROUTES:
                response = self.client.get(route)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), {'error': {'code': 'ADMIN_SESSION_INVALID'}})
            listing.assert_not_called(); plaintext.assert_not_called(); events.assert_not_called()

    def test_record_metadata_lists_never_decrypt_and_knowledge_is_independent(self):
        with patch('audit.admin_reader.decrypt_record', side_effect=AssertionError('must not decrypt')):
            response = self.client.get(ROUTES[0], headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['items'][0]['record_id'], 'ev-admin')
        self.assertNotIn('plaintext', response.text)
        self.assertEqual(list((self.root/'access-log').glob('*.json')), [])
        self.assertEqual(self.client.get('/api/admin/sources', headers=self.headers).status_code, 503)

    def test_plaintext_detail_and_real_access_event_pagination(self):
        response = self.client.get(ROUTES[1], headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['plaintext'], CANARY.decode())
        pages = self.client.get(ROUTES[2]+'?limit=1', headers=self.headers).json()
        self.assertEqual(len(pages['items']), 1)
        self.assertTrue(pages['next_cursor'])
        second = self.client.get(ROUTES[2]+'?limit=1&cursor='+pages['next_cursor'], headers=self.headers).json()
        events = pages['items'] + second['items']
        self.assertEqual({event['event'] for event in events}, {'AUDIT_READ_ATTEMPTED', 'AUDIT_READ_RELEASED'})
        for event in events:
            self.assertEqual(event['actor'], 'admin')
            self.assertEqual(event['session_digest'], self.fixture.digest[:16])
            self.assertEqual(event['record_sha256'], hashlib.sha256(b'ev-admin').hexdigest())
            self.assertGreater(event['at'], 0)
            self.assertNotIn(CANARY.decode(), str(event))
        self.assertIsNone(second['next_cursor'])

    def test_missing_resources_503_after_authentication(self):
        with TestClientBridge(create_app(admin_service=self.fixture.service)) as client:
            for route in ROUTES:
                self.assertEqual(client.get(route).status_code, 401)
                response = client.get(route, headers=self.headers)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json(), {'error': {'code': 'ADMIN_AUDIT_UNAVAILABLE'}})

    def test_corruption_409_no_body_and_durable_rejection(self):
        (self.root/'evidence'/'ev-admin.evidence.json').write_bytes(b'corrupt')
        response = self.client.get(ROUTES[1], headers=self.headers)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json(), {'error': {'code': 'AUDIT_EVIDENCE_CORRUPTED'}})
        self.assertNotIn(CANARY.decode(), response.text)
        events = self.client.get(ROUTES[2], headers=self.headers).json()['items']
        self.assertEqual({x['event'] for x in events}, {'AUDIT_READ_ATTEMPTED', 'AUDIT_READ_REJECTED:evidence_corrupted'})

    def test_unknown_record_404(self):
        response = self.client.get('/api/admin/audit/records/unknown', headers=self.headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {'error': {'code': 'AUDIT_RECORD_NOT_FOUND'}})

    def test_decryption_result_not_released_after_session_revocation(self):
        from audit import admin_reader
        original = admin_reader.decrypt_record
        def revoke(kms, record):
            body = original(kms, record)
            self.fixture.store.revoke_session(self.fixture.digest)
            return body
        with patch('audit.admin_reader.decrypt_record', side_effect=revoke):
            response = self.client.get(ROUTES[1], headers=self.headers)
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(response.json(), {'error': {'code': 'AUDIT_ACCESS_REJECTED'}})
        self.assertNotIn(CANARY.decode(), response.text)

    def test_scan_deadline_and_fifth_operation_are_bounded(self):
        release = threading.Event()
        entered = threading.Barrier(5)
        original = self.reader.list_records
        def blocked(**kwargs):
            entered.wait(5)
            release.wait(10)
            return original(**kwargs)
        outcomes = []
        def worker():
            outcomes.append(self.client.get(ROUTES[0], headers=self.headers).status_code)
        with patch.object(self.reader, 'list_records', side_effect=blocked):
            threads = [threading.Thread(target=worker) for _ in range(4)]
            for thread in threads:
                thread.start()
            try:
                entered.wait(5)
                response = self.client.get(ROUTES[0], headers=self.headers)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json(), {'error': {'code': 'ADMIN_AUDIT_UNAVAILABLE'}})
            finally:
                release.set()
                for thread in threads:
                    thread.join(10)
        self.assertEqual(outcomes, [200]*4)

    def test_timeout_never_releases_plaintext_and_slot_stays_occupied(self):
        entered = threading.Event(); release = threading.Event()
        def blocked(*args, **kwargs):
            entered.set(); release.wait(10); return CANARY
        with patch.object(self.reader, 'read_plaintext', side_effect=blocked), patch('gateway.admin_audit_api._AUDIT_BUDGET', 0.1):
            started = time.monotonic()
            try:
                response = self.client.get(ROUTES[1], headers=self.headers)
                self.assertTrue(entered.is_set())
                self.assertEqual(response.status_code, 503)
                self.assertLess(time.monotonic()-started, 2)
                self.assertNotIn(CANARY.decode(), response.text)
            finally:
                release.set()

    def test_final_revalidation_crossing_budget_never_releases_body(self):
        import asyncio
        original = self.fixture.service.revalidate
        calls = 0
        async def delayed(context, **kwargs):
            nonlocal calls
            calls += 1
            result = await original(context, **kwargs)
            if calls == 5:
                await asyncio.sleep(0.2)
            return result
        with patch.object(self.fixture.service, 'revalidate', side_effect=delayed), \
                patch('gateway.admin_audit_api._AUDIT_BUDGET', 0.1):
            response = self.client.get(ROUTES[1], headers=self.headers)
        self.assertEqual(calls, 5)
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(response.json(), {'error': {'code': 'AUDIT_ACCESS_REJECTED'}})
        self.assertNotIn(CANARY.decode(), response.text)

    def test_metadata_final_revalidation_also_obeys_budget(self):
        import asyncio
        original = self.fixture.service.revalidate
        calls = 0
        async def delayed(context, **kwargs):
            nonlocal calls
            calls += 1
            result = await original(context, **kwargs)
            if calls == 3:
                await asyncio.sleep(0.2)
            return result
        with patch.object(self.fixture.service, 'revalidate', side_effect=delayed), \
                patch('gateway.admin_audit_api._AUDIT_BUDGET', 0.1):
            response = self.client.get(ROUTES[0], headers=self.headers)
        self.assertEqual(calls, 3)
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(response.json(), {'error': {'code': 'AUDIT_ACCESS_REJECTED'}})
        self.assertNotIn('ev-admin', response.text)

    def test_retention_crossing_final_revalidation_never_releases_body(self):
        from unittest.mock import Mock
        original = self.fixture.service.revalidate
        calls = 0
        clock = Mock(return_value=datetime(2029, 12, 31, tzinfo=timezone.utc))
        async def expires(context, **kwargs):
            nonlocal calls
            calls += 1
            result = await original(context, **kwargs)
            if calls == 5:
                clock.return_value = datetime(2030, 1, 1, tzinfo=timezone.utc)
            return result
        with patch.object(self.fixture.service, 'revalidate', side_effect=expires), \
                patch('gateway.admin_audit_api._utcnow', clock):
            response = self.client.get(ROUTES[1], headers=self.headers)
        self.assertEqual(calls, 5)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json(), {'error': {'code': 'AUDIT_RECORD_UNAVAILABLE'}})
        self.assertNotIn(CANARY.decode(), response.text)
        # The successful reader result is held locally; no third catalog scan.
        clock.assert_called_once()

    def test_bad_pagination_is_sanitized(self):
        for query in ('limit=0', 'limit=101', 'cursor=../secret'):
            response = self.client.get(ROUTES[0]+'?'+query, headers=self.headers)
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json(), {'error': {'code': 'ADMIN_REQUEST_INVALID'}})
