"""Real PostgreSQL publication and complete runtime snapshot replacement."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from uuid import uuid4

from starlette.testclient import TestClient

from detection.dictionary import analyze_dictionary
from detection.dictionary_store import DictionaryEdit, PostgresDictionaryStore
from gateway.admin_auth import AdminAuthService
from gateway.admin_storage import AdminStateStore
from gateway.dictionary_runtime import DictionaryRuntimeService
from tests.detection import test_dictionary_store
from tests.gateway import test_runtime

MINI_PACKAGE = Path(__file__).parents[1] / 'detection/fixtures/ner/mini-valid-package'


class DictionaryRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_dictionary_store.DictionaryStoreTests.setUpClass()
        cls.connection_uri = test_dictionary_store.DictionaryStoreTests.connection_uri

    def test_publish_preserves_old_assembly_and_updates_chat_files_and_other_workers(self):
        fixture = test_runtime.RuntimeAssemblyTests(methodName='runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        tenant = 'dictionary-runtime-' + uuid4().hex
        store = PostgresDictionaryStore(self.connection_uri, tenant_id=tenant, domain=fixture.domain)
        dictionary = store.bootstrap(fixture.dictionary)
        admin_state = AdminStateStore(fixture.root / 'admin')
        admin_state.initialize(salt=b's' * 16, derived_key=b'd' * 32,
                              scrypt_n=2**17, scrypt_r=8, scrypt_p=1, dklen=32)
        auth = AdminAuthService(admin_state, scope=f'{tenant}/{fixture.domain}')
        app = fixture.app(dictionary=dictionary, dictionary_store=store, tenant_id=tenant,
                          admin_service=auth, ner_package_dir=MINI_PACKAGE)
        term = 'ZXQ_SYNTHETIC_PRODUCT'
        with TestClient(app) as client:
            old = app.state.router.get_pipeline('chat-fixture')
            old_redactor = app.state.file_redactor
            other_app = SimpleNamespace(state=SimpleNamespace(router=app.state.router, file_redactor=None))
            other_worker = DictionaryRuntimeService(other_app, store, revision=1)
            store.edit(DictionaryEdit(expected_revision=1, text=term, entity_type='PROJECT'), 'synthetic-admin')
            app.state.dictionary_service.refresh()
            self.assertIs(old, app.state.router.get_pipeline('chat-fixture'))
            self.assertEqual((), analyze_dictionary(term, old.detector._dictionary).spans)
            result = app.state.dictionary_service.publish(2, 'synthetic-admin')
            new = app.state.router.get_pipeline('chat-fixture')
            self.assertEqual(2, result.published_revision)
            self.assertIsNot(old, new)
            self.assertIs(old.detector._executor, new.detector._executor)
            self.assertNotEqual(old.version_handle.package_hash, new.version_handle.package_hash)
            old.version_handle.manifest.verify_payloads(old._component_payloads())
            self.assertEqual((), analyze_dictionary(term, old_redactor.detector._dictionary).spans)
            self.assertEqual(1, len(analyze_dictionary(term, app.state.file_redactor.detector._dictionary).spans))
            other_worker.refresh()
            self.assertEqual('db-2', other_app.state.router.get_pipeline('chat-fixture').detector._dictionary.version)
            response = fixture.post(client, prompt=term)
            self.assertEqual(200, response.status_code)
            self.assertIn(term, response.text)
            self.assertNotIn(term, fixture.calls[-1].content.decode())
