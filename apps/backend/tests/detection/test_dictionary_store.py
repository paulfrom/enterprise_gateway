"""Real PostgreSQL dictionary persistence, scoped writes and publication safety."""
from concurrent.futures import ThreadPoolExecutor
import os
import unittest
from uuid import uuid4

import psycopg

from detection.dictionary import DictionaryEntry, compile_dictionary, compute_dictionary_hash
from detection.dictionary_store import DictionaryEdit, DictionaryError, PostgresDictionaryStore, TABLES
from tests.pg_support import get_admin_dsn


class DictionaryStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.connection_uri = get_admin_dsn()
        with psycopg.connect(cls.connection_uri) as connection:
            connection.execute('SET TRANSACTION READ ONLY')
            names = connection.execute(
                'SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname=ANY(%s)',
                (list(TABLES),)).fetchall()
        if {name for name, in names} != set(TABLES):
            if os.environ.get('GATEWAY_REQUIRE_DICTIONARY_PG') == '1':
                raise RuntimeError('Deploy redaction_dictionary_v4.sql and existing service grants before dictionary PG tests.')
            raise unittest.SkipTest('Existing PostgreSQL dictionary tables have not been deployed; no automatic DDL.')

    def setUp(self):
        self.domain = 'synthetic-dictionary'
        self.tenant = 'dictionary-test-' + uuid4().hex
        self.store = PostgresDictionaryStore(self.connection_uri, tenant_id=self.tenant, domain=self.domain)
        entries = (DictionaryEntry(text='合成企业甲', entity_type='ORG'),)
        self.seed = compile_dictionary({'dictionary_id': 'synthetic-dictionary', 'version': 'seed-v1',
            'domain': self.domain, 'entries': [entry.model_dump() for entry in entries],
            'sha256': compute_dictionary_hash('synthetic-dictionary', 'seed-v1', self.domain, entries)})
        self.original = self.store.bootstrap(self.seed)

    def edit(self, text='合成企业乙', revision=1, enabled=True, identity=None):
        return self.store.edit(DictionaryEdit(expected_revision=revision, text=text, entity_type='ORG', enabled=enabled),
                               'synthetic-admin', identity)

    def test_drafts_do_not_change_active_snapshot_until_publication(self):
        self.assertEqual('db-1', self.original.version)
        self.edit()
        self.assertEqual((1, None), self.store.active(1))
        result, prepared = self.store.publish(2, 'synthetic-admin', lambda compiled: compiled)
        self.assertEqual(2, result.published_revision)
        self.assertEqual({'合成企业甲', '合成企业乙'}, {entry.text for entry in prepared.entries})
        self.assertEqual(['合成企业甲'], [entry.text for entry in self.original.entries])
        restarted = PostgresDictionaryStore(self.connection_uri, tenant_id=self.tenant, domain=self.domain)
        self.assertEqual(prepared.sha256, restarted.bootstrap().sha256)
        self.assertEqual([2, 1], [version.revision for version in restarted.versions().items])

    def test_existing_scope_does_not_read_initial_seed_again(self):
        def forbidden():
            raise AssertionError('seed loader must not run after initialization')
        self.assertEqual(self.original.sha256, self.store.bootstrap(forbidden).sha256)

    def test_update_search_disable_and_delete_are_persisted(self):
        entry = self.store.list_entries().items[0]
        self.edit(text='合成企业新名称', identity=entry.entry_id, enabled=False)
        self.assertEqual(0, self.store.list_entries(enabled=True).total)
        page = self.store.list_entries(query='新名称', entity_type='ORG', enabled=False)
        self.assertEqual('合成企业新名称', page.items[0].text)
        result = self.store.delete(entry.entry_id, 2, 'synthetic-admin')
        self.assertEqual(3, result.revision)
        self.assertEqual(0, self.store.list_entries().total)
        self.assertEqual((1, None), self.store.active(1))

    def test_concurrent_stale_edits_cannot_overwrite_each_other(self):
        def edit(number):
            try:
                self.edit(text=f'合成企业并发{number}')
                return 'saved'
            except DictionaryError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(edit, range(2)))
        self.assertCountEqual(['saved', 'DICTIONARY_REVISION_CONFLICT'], outcomes)
        self.assertEqual(2, self.store.list_entries().revision)
        self.assertEqual(2, self.store.list_entries().total)

    def test_duplicate_text_is_rejected_without_changing_revision(self):
        with self.assertRaises(DictionaryError) as failure:
            self.edit(text='合成企业甲')
        self.assertEqual('DICTIONARY_ENTRY_CONFLICT', failure.exception.code)
        self.assertEqual(1, self.store.list_entries().revision)

    def test_prepare_failure_rolls_back_publication_and_keeps_old_snapshot(self):
        self.edit()
        def broken(compiled):
            raise RuntimeError('PRIVATE_DICTIONARY_CANARY')
        with self.assertRaises(DictionaryError) as failure:
            self.store.publish(2, 'synthetic-admin', broken)
        self.assertNotIn('PRIVATE_DICTIONARY_CANARY', str(failure.exception))
        self.assertEqual((1, None), self.store.active(1))
        self.assertEqual([1], [version.revision for version in self.store.versions().items])
        self.assertEqual(2, self.store.list_entries().revision)

    def test_empty_publication_and_stale_publication_preserve_existing_version(self):
        entry = self.store.list_entries().items[0]
        self.edit(text=entry.text, identity=entry.entry_id, enabled=False)
        for revision, code in ((1, 'DICTIONARY_REVISION_CONFLICT'), (2, 'DICTIONARY_EMPTY_PUBLICATION')):
            with self.subTest(revision=revision), self.assertRaises(DictionaryError) as failure:
                self.store.publish(revision, 'synthetic-admin', lambda compiled: compiled)
            self.assertEqual(code, failure.exception.code)
        self.assertEqual((1, None), self.store.active(1))

    def test_cross_scope_entry_ids_and_direct_sql_do_not_bypass_rls(self):
        foreign = PostgresDictionaryStore(self.connection_uri, tenant_id='other-' + uuid4().hex, domain=self.domain)
        foreign.bootstrap(self.seed)
        entry = foreign.list_entries().items[0]
        with self.assertRaises(DictionaryError) as failure:
            self.edit(text='合成跨域修改', identity=entry.entry_id)
        self.assertEqual('DICTIONARY_ENTRY_NOT_FOUND', failure.exception.code)
        with self.store.transaction() as connection:
            count = connection.execute('SELECT count(*) FROM redaction_dictionary_entries WHERE entry_id=%s',
                                       (entry.entry_id,)).fetchone()[0]
        self.assertEqual(0, count)
        self.assertEqual('合成企业甲', foreign.list_entries().items[0].text)

    def test_published_version_cannot_be_modified_by_service_role(self):
        with self.assertRaises(DictionaryError):
            with self.store.transaction() as connection:
                connection.execute('UPDATE redaction_dictionary_versions SET sha256=%s '
                    'WHERE tenant_id=%s AND domain=%s AND revision=1',
                    ('00' * 32, self.tenant, self.domain))
        self.assertEqual(self.original.sha256, self.store.active()[1].sha256)
