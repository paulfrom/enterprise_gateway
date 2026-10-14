"""Real parsers, rule/dictionary detectors and ONNX fixture through the HTTP API."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient

from detection.detection_orchestrator import DetectionOrchestrator
from detection.dictionary import DictionaryEntry, compile_dictionary, compute_dictionary_hash
from document.extract import MAX_FILE_BYTES
from document.service import FileRedactor
from gateway.app import create_app
from gateway.admin_auth import AdminAuthService
from gateway.admin_storage import AdminStateStore
from infra.errors import SafetyCode, SafetyError
from tests.gateway.test_admin_api import issue_session
from tests.document.test_extract import PHONE, docx, pdf, spreadsheet

PATH = '/api/admin/documents/redact'
ORIGIN = 'http://admin.test'
MINI_PACKAGE = Path(__file__).parents[1] / 'detection/fixtures/ner/mini-valid-package'


class FileRedactionTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        entries = (DictionaryEntry(text='星云科技', entity_type='ORG'),)
        dictionary = compile_dictionary({'dictionary_id': 'file-tests', 'version': 'v1', 'domain': 'domain-b',
            'entries': [{'text': '星云科技', 'entity_type': 'ORG'}],
            'sha256': compute_dictionary_hash('file-tests', 'v1', 'domain-b', entries)})
        cls.detector = DetectionOrchestrator(dictionary=dictionary, ner_package_dir=MINI_PACKAGE)
        cls.detector.warmup()

    @classmethod
    def tearDownClass(cls):
        cls.detector.close()

    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = AdminStateStore(Path(temporary.name) / 'admin')
        self.store.initialize(salt=b's' * 16, derived_key=b'd' * 32,
                              scrypt_n=2**17, scrypt_r=8, scrypt_p=1, dklen=32)
        self.auth = AdminAuthService(self.store, scope='tenant-a/domain-b')
        self.redactor = FileRedactor(detector=self.detector, domain='domain-b', scope='tenant-a/domain-b',
                                    verify_assets=lambda: 'ab' * 32)
        self.addCleanup(self.redactor.close)
        self.app = create_app(admin_service=self.auth, file_redactor=self.redactor)
        self.client = AsyncClient(transport=ASGITransport(app=self.app), base_url=ORIGIN)
        self.addAsyncCleanup(self.client.aclose)
        self.token = issue_session(self.store)
        cookie = {'Cookie': 'admin_session=' + self.token}
        csrf = (await self.client.get('/api/admin/session', headers=cookie)).json()['csrf_token']
        self.headers = {**cookie, 'Origin': ORIGIN, 'X-Admin-CSRF': csrf, 'Content-Type': 'application/octet-stream'}

    async def upload(self, data, fmt='txt', **kwargs):
        return await self.client.post(PATH + '?format=' + fmt, content=data,
                                      headers=kwargs.pop('headers', self.headers), **kwargs)

    async def test_all_supported_containers_redact_without_originals_or_mapping(self):
        fixtures = [('txt', f'星云科技 {PHONE} {PHONE}'.encode()),
                    ('csv', f'公司,电话\n星云科技,{PHONE}'.encode()),
                    ('docx', docx()), ('xlsx', spreadsheet()), ('pdf', pdf())]
        for fmt, data in fixtures:
            with self.subTest(fmt=fmt):
                with redirect_stdout(StringIO()) as logs:
                    response = await self.upload(data, fmt)
                self.assertEqual(200, response.status_code, response.text)
                result = response.json()
                self.assertRegex(result['redacted_text'], r'<[A-Z][A-Z0-9_]*_\d{3,}>')
                self.assertGreater(result['replacement_count'], 0)
                self.assertNotIn(PHONE, json.dumps(result, ensure_ascii=False))
                self.assertNotIn('星云科技', json.dumps(result, ensure_ascii=False))
                self.assertNotIn('mapping', result)
                self.assertEqual('no-store', response.headers['cache-control'])
                self.assertEqual('', logs.getvalue())

    async def test_repeated_values_use_readable_numbering_in_independent_files(self):
        data = f'{PHONE},{PHONE}'.encode()
        first = (await self.upload(data, 'csv')).json()
        second = (await self.upload(data, 'csv')).json()
        self.assertEqual(1, first['entity_count'])
        self.assertEqual(2, first['replacement_count'])
        self.assertEqual(first['redacted_text'], second['redacted_text'])
        self.assertRegex(first['redacted_text'], r'<[A-Z][A-Z0-9_]*_001>')

    async def test_authentication_and_csrf_precede_body_consumption(self):
        consumed = False
        async def body():
            nonlocal consumed
            consumed = True
            yield PHONE.encode()
        for headers, status in (({}, 401), ({'Cookie': self.headers['Cookie']}, 403)):
            response = await self.upload(body(), headers=headers)
            self.assertEqual(status, response.status_code)
            self.assertFalse(consumed)
        for suffix, status in (('/', 307), ('/unknown', 404)):
            response = await self.client.post(PATH + suffix, content=body())
            self.assertEqual(status, response.status_code)
            self.assertFalse(consumed)

    async def test_limits_and_unknown_or_repeated_query_arguments(self):
        response = await self.upload(b'x', headers={**self.headers, 'Content-Length': str(MAX_FILE_BYTES + 1)})
        self.assertEqual(413, response.status_code)
        async def oversized():
            yield b'a' * MAX_FILE_BYTES
            yield b'b'
        self.assertEqual(413, (await self.upload(oversized())).status_code)
        for query in ('format=txt&format=txt', 'format=txt&path=/tmp/private', 'format=doc'):
            response = await self.client.post(PATH + '?' + query, content=PHONE.encode(), headers=self.headers)
            self.assertEqual(422, response.status_code)
            self.assertNotIn(PHONE, response.text)

    async def test_secret_reserved_token_and_detection_failure_release_nothing(self):
        for data, expected in ((b'sk-ABCDEFGH123456789', 403), (b'<<ENT_original>>', 422)):
            response = await self.upload(data)
            self.assertEqual(expected, response.status_code, response.text)
            self.assertNotIn('redacted_text', response.json())
            self.assertNotIn(data.decode(), response.text)
        with patch.object(self.detector, 'detect_many', side_effect=SafetyError(SafetyCode.DETECTION_FAILED)):
            response = await self.upload(PHONE.encode())
        self.assertEqual(503, response.status_code)
        self.assertNotIn(PHONE, response.text)

    async def test_expired_or_revoked_session_during_processing_drops_result(self):
        actual = self.redactor.redact
        def revoke(*args, **kwargs):
            value = actual(*args, **kwargs)
            import hashlib
            self.store.revoke_session(hashlib.sha256(bytes.fromhex(self.token)).hexdigest())
            return value
        with patch.object(self.redactor, 'redact', side_effect=revoke):
            response = await self.upload(PHONE.encode())
        self.assertEqual(401, response.status_code)
        self.assertNotIn('redacted_text', response.json())

    async def test_busy_scope_and_closed_runtime_refuse(self):
        self.redactor.slot.acquire()
        try:
            self.assertEqual(429, (await self.upload(b'hello')).status_code)
        finally:
            self.redactor.slot.release()
        self.redactor.scope = 'another/domain'
        self.assertEqual(403, (await self.upload(b'hello')).status_code)
        self.redactor.scope = self.auth._scope
        self.app.state.runtime_closed = True
        self.assertEqual(503, (await self.upload(b'hello')).status_code)

    async def test_version_failure_returns_no_result(self):
        def corrupt():
            raise SafetyError(SafetyCode.CORRUPTED_PACKAGE)
        self.redactor.verify_assets = corrupt
        response = await self.upload(PHONE.encode())
        self.assertEqual(503, response.status_code)
        self.assertEqual('DOCUMENT_DETECTION_UNAVAILABLE', response.json()['error']['code'])
