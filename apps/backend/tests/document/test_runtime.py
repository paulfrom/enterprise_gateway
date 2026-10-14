"""Runtime binding uses the real local NER and never invokes a supplier."""
import unittest
from unittest.mock import patch

from starlette.testclient import TestClient

from gateway.admin_auth import AdminAuthService
from gateway.admin_storage import AdminStateStore
from infra.errors import SafetyCode, SafetyError
from tests.gateway.test_admin_api import issue_session
from tests.gateway import test_runtime


class FileRuntimeTests(unittest.TestCase):
    def test_runtime_wires_local_detection_without_classification_or_egress_and_closes_parser(self):
        fixture = test_runtime.RuntimeAssemblyTests(methodName='runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        store = AdminStateStore(fixture.root / 'admin')
        store.initialize(salt=b's' * 16, derived_key=b'd' * 32,
                         scrypt_n=2**17, scrypt_r=8, scrypt_p=1, dklen=32)
        token = issue_session(store)
        auth = AdminAuthService(store, scope='processing-tenant/' + fixture.domain)
        app = fixture.app(admin_service=auth, classifier=None, detection_failure_mode='passthrough')
        redactor = app.state.file_redactor
        with patch.object(redactor, 'close', wraps=redactor.close) as close:
            with TestClient(app) as client:
                cookie = {'Cookie': 'admin_session=' + token}
                csrf = client.get('/api/admin/session', headers=cookie).json()['csrf_token']
                headers = {**cookie, 'Origin': 'http://testserver', 'X-Admin-CSRF': csrf,
                           'Content-Type': 'application/octet-stream'}
                response = client.post('/api/admin/documents/redact?format=txt',
                    content='甲公司与张三的电话是13800138000。'.encode(), headers=headers)
                self.assertEqual(200, response.status_code, response.text)
                for value in ('甲公司', '张三', '13800138000'):
                    self.assertNotIn(value, response.text)
                handle = app.state.runtime_pipelines[0].version_handle
                self.assertEqual(handle.package_hash, response.json()['package_hash'])
                self.assertEqual([], fixture.calls)
                self.assertEqual([], list(app.state.runtime_spool_directory.iterdir()))
                self.assertEqual([], list(app.state.runtime_evidence_directory.iterdir()))
                with patch.object(redactor.detector, 'detect_many', side_effect=SafetyError(SafetyCode.DETECTION_FAILED)):
                    refused = client.post('/api/admin/documents/redact?format=txt', content=b'synthetic', headers=headers)
                self.assertEqual(503, refused.status_code)
                self.assertNotIn('redacted_text', refused.json())
                self.assertEqual([], fixture.calls)
            close.assert_called_once()
        self.assertTrue(redactor.parser._closed)
