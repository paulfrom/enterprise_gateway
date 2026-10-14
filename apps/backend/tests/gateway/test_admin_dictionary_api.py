"""Dictionary HTTP boundaries: authorization before input, safe errors and CAS."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock

from httpx import ASGITransport, AsyncClient

from detection.dictionary_store import DictionaryError, DictionaryPage, DictionaryState, DictionaryVersions
from gateway.admin_auth import AdminAuthService
from gateway.admin_storage import AdminStateStore
from gateway.app import create_app
from tests.gateway.test_admin_api import issue_session

ORIGIN = 'http://admin.test'
BASE = '/api/admin/dictionary'


class DictionaryApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.auth_store = AdminStateStore(Path(directory.name) / 'admin')
        self.auth_store.initialize(salt=b's' * 16, derived_key=b'd' * 32,
                                  scrypt_n=2**17, scrypt_r=8, scrypt_p=1, dklen=32)
        self.auth = AdminAuthService(self.auth_store, scope='tenant-a/domain-b')
        self.state = DictionaryState(dictionary_id='synthetic', revision=2, published_revision=1,
            published_sha256='ab' * 32, published_entries=1, updated_at=datetime.now(timezone.utc))
        self.store = Mock()
        self.store.list_entries.return_value = DictionaryPage(**self.state.model_dump(),
            items=[], total=0, offset=0, limit=50)
        self.store.edit.return_value = self.state
        self.store.delete.return_value = self.state
        self.store.versions.return_value = DictionaryVersions(items=[])
        self.service = SimpleNamespace(scope=self.auth._scope, store=self.store, publish=Mock(return_value=self.state))
        self.app = create_app(admin_service=self.auth, dictionary_service=self.service)
        self.client = AsyncClient(transport=ASGITransport(app=self.app), base_url=ORIGIN)
        self.addAsyncCleanup(self.client.aclose)
        self.token = issue_session(self.auth_store)
        cookie = {'Cookie': 'admin_session=' + self.token}
        csrf = (await self.client.get('/api/admin/session', headers=cookie)).json()['csrf_token']
        self.headers = {**cookie, 'Origin': ORIGIN, 'X-Admin-CSRF': csrf}

    async def test_auth_and_csrf_precede_body_consumption_and_store_access(self):
        consumed = False
        async def body():
            nonlocal consumed
            consumed = True
            yield b'PRIVATE_DICTIONARY_CANARY'
        for headers, status in (({}, 401), ({'Cookie': self.headers['Cookie']}, 403),
                                ({**self.headers, 'Origin': 'http://foreign.test'}, 403)):
            response = await self.client.post(BASE + '/entries', content=body(), headers=headers)
            self.assertEqual(status, response.status_code)
            self.assertFalse(consumed)
        self.store.edit.assert_not_called()
        self.assertEqual(401, (await self.client.get(BASE)).status_code)
        self.store.list_entries.assert_not_called()

    async def test_listing_accepts_only_known_unique_filters_and_returns_no_store_errors(self):
        response = await self.client.get(BASE + '?query=合成&enabled=false&offset=50&limit=25', headers=self.headers)
        self.assertEqual(200, response.status_code)
        self.store.list_entries.assert_called_once_with(query='合成', entity_type=None, enabled=False, offset=50, limit=25)
        for query in ('tenant_id=foreign', 'limit=1&limit=2', 'enabled=1', 'offset=-1', 'limit=101'):
            self.assertEqual(422, (await self.client.get(BASE + '?' + query, headers=self.headers)).status_code)
        self.store.list_entries.side_effect = RuntimeError('PRIVATE_DICTIONARY_CANARY')
        response = await self.client.get(BASE, headers=self.headers)
        self.assertEqual(503, response.status_code)
        self.assertNotIn('PRIVATE_DICTIONARY_CANARY', response.text)

    async def test_edit_passes_authenticated_actor_and_exact_text_without_ingress_logging(self):
        body = {'expected_revision': 2, 'text': ' 合成企业 ', 'entity_type': 'ORG', 'enabled': False}
        with redirect_stdout(StringIO()) as output:
            response = await self.client.post(BASE + '/entries', json=body, headers=self.headers)
        self.assertEqual(200, response.status_code)
        edit, actor, identity = self.store.edit.call_args.args
        self.assertEqual(body, edit.model_dump())
        self.assertEqual('admin', actor)
        self.assertIsNone(identity)
        self.assertEqual('', output.getvalue())
        self.assertEqual('no-store', response.headers['cache-control'])

    async def test_invalid_duplicate_and_oversized_inputs_never_edit(self):
        valid = {'expected_revision': 2, 'text': '合成企业', 'entity_type': 'ORG'}
        for body in ({**valid, 'tenant_id': 'foreign'}, {**valid, 'expected_revision': True},
                     {**valid, 'text': '<ORG_001>'}, {**valid, 'text': ' '},
                     {**valid, 'entity_type': 'org'}, {**valid, 'text': 'x' * 513}):
            response = await self.client.post(BASE + '/entries', json=body, headers=self.headers)
            self.assertEqual(422, response.status_code)
            self.assertNotIn(body['text'], response.text)
        response = await self.client.post(BASE + '/entries', content=b'{"text":"PRIVATE","text":"OTHER"}',
                                         headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(422, response.status_code)
        response = await self.client.post(BASE + '/entries', content=b'x' * 8193,
                                         headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(422, response.status_code)
        self.store.edit.assert_not_called()

    async def test_scope_and_revision_conflicts_are_explicit(self):
        self.service.scope = 'another/domain'
        self.assertEqual(403, (await self.client.get(BASE, headers=self.headers)).status_code)
        self.store.list_entries.assert_not_called()
        self.service.scope = self.auth._scope
        self.store.edit.side_effect = DictionaryError('DICTIONARY_REVISION_CONFLICT')
        response = await self.client.post(BASE + '/entries',
            json={'expected_revision': 1, 'text': '合成企业', 'entity_type': 'ORG'}, headers=self.headers)
        self.assertEqual(409, response.status_code)
        self.assertEqual({'error': {'code': 'DICTIONARY_REVISION_CONFLICT'}}, response.json())

    async def test_publish_and_delete_require_explicit_revision(self):
        self.assertEqual(200, (await self.client.post(BASE + '/publish',
            json={'expected_revision': 2}, headers=self.headers)).status_code)
        self.service.publish.assert_called_once_with(2, 'admin')
        entry_id = '00000000-0000-0000-0000-000000000001'
        self.assertEqual(200, (await self.client.post(BASE + '/entries/' + entry_id + '/delete',
            json={'expected_revision': 2}, headers=self.headers)).status_code)
        self.store.delete.assert_called_once_with(entry_id, 2, 'admin')
        self.assertEqual(422, (await self.client.post(BASE + '/publish', json={}, headers=self.headers)).status_code)

    async def test_revoked_session_after_store_read_cannot_release_terms(self):
        def revoke(**kwargs):
            import hashlib
            self.auth_store.revoke_session(hashlib.sha256(bytes.fromhex(self.token)).hexdigest())
            return self.store.list_entries.return_value
        self.store.list_entries.side_effect = revoke
        response = await self.client.get(BASE, headers=self.headers)
        self.assertEqual(401, response.status_code)
        self.assertNotIn('items', response.json())

    async def test_revocation_during_body_upload_prevents_a_late_edit(self):
        import hashlib
        async def body():
            self.auth_store.revoke_session(hashlib.sha256(bytes.fromhex(self.token)).hexdigest())
            yield b'{"expected_revision":2,"text":"SYNTHETIC_ENTRY","entity_type":"ORG"}'
        response = await self.client.post(BASE + '/entries', content=body(),
            headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(401, response.status_code)
        self.store.edit.assert_not_called()
