"""New-layout, forced-RLS and least-privilege history database acceptance."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

import psycopg

from infra.envelope_crypto import StaticTestKmsProvider
from request_history.database import assert_history_connection,prepare_database,validate_namespace
from request_history import HistoryUnavailable,PostgresHistoryStore
from scripts.prepare_request_database import main
from tests.request_history.pg_support import configuration


class HistoryPreparationLocalTests(unittest.TestCase):
    def test_reserved_and_invalid_schema_rejected(self):
        for schema in ('public','pg_history','information_schema','bad-name','history;DROP TABLE x',None):
            with self.subTest(schema=schema),self.assertRaises(HistoryUnavailable):
                validate_namespace(schema)

    def test_cli_error_is_fixed_and_existing_secret_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)/'input.json'
            output = Path(directory)/'output.json'
            config.write_text(json.dumps(dict(schema='gw_history_cli',application_role='synthetic',admin_dsn='unused',app_dsn='unused')))
            stream = io.StringIO()
            with redirect_stdout(stream),patch('scripts.prepare_request_database.prepare_database',side_effect=RuntimeError('synthetic-secret-password')):
                self.assertEqual(1,main(['--config',str(config),'--output-config',str(output)]))
            self.assertFalse(output.exists())
            self.assertNotIn('synthetic-secret-password',stream.getvalue())
            output.write_text('synthetic-existing-secret')
            with redirect_stdout(io.StringIO()),patch('scripts.prepare_request_database.prepare_database') as prepare:
                self.assertEqual(1,main(['--config',str(config),'--output-config',str(output)]))
                prepare.assert_not_called()
            self.assertEqual('synthetic-existing-secret',output.read_text())


class HistoryDatabasePostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get('GATEWAY_HISTORY_PG_CONFIG'):
            raise unittest.SkipTest('Explicit isolated history PostgreSQL configuration required')
        cls.config = configuration()

    def test_forced_rls_reader_scope_expiry_and_no_knowledge_grants(self):
        with psycopg.connect(self.config['app_dsn']) as conn:
            assert_history_connection(conn,expected_schema=self.config['schema'],expected_role=self.config['application_role'])
            self.assertEqual(0,conn.execute('SELECT count(*) FROM request_records').fetchone()[0])
            # The private baseline's schema name can refer to a disposed prior
            # test run. Check actual knowledge assets instead of assuming it exists.
            reachable_knowledge = conn.execute(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE c.relkind='r' AND c.relname LIKE 'knowledge_%' "
                "AND has_schema_privilege(current_user,n.oid,'USAGE') "
                "AND has_table_privilege(current_user,c.oid,'SELECT')",
            ).fetchone()[0]
            self.assertEqual(0,reachable_knowledge)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                conn.execute('ALTER TABLE request_records DISABLE ROW LEVEL SECURITY')
        with tempfile.TemporaryDirectory() as directory:
            store = PostgresHistoryStore(self.config['app_dsn'],StaticTestKmsProvider(),tenant_id='synthetic-'+uuid4().hex,
                                         domain='scope',retention_days=7,bucket='test',audit_directory=directory)
            recorder = store.begin(protocol='deepseek-chat-completions',model='synthetic',raw_body=b'synthetic')
            with store._connection('reader') as conn:
                self.assertEqual(1,conn.execute('SELECT count(*) FROM request_records').fetchone()[0])
                self.assertEqual(0,conn.execute("UPDATE request_records SET model='changed' WHERE request_id=%s",(recorder.request_id,)).rowcount)
                self.assertEqual('synthetic',conn.execute('SELECT model FROM request_records WHERE request_id=%s',(recorder.request_id,)).fetchone()[0])
            with store._connection('reader') as conn:
                conn.execute("SELECT set_config('request_history.domain','foreign-domain',true)")
                self.assertEqual(0,conn.execute('SELECT count(*) FROM request_records').fetchone()[0])

    def test_existing_namespace_refused_without_ddl_changes(self):
        before = None
        with psycopg.connect(self.config['admin_dsn']) as conn:
            before = conn.execute('SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace').fetchone()[0]
        with self.assertRaises(HistoryUnavailable):
            prepare_database(self.config)
        with psycopg.connect(self.config['admin_dsn']) as conn:
            self.assertEqual(before,conn.execute('SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace').fetchone()[0])

    def test_ddl_failure_rolls_back_new_namespace(self):
        schema = 'gw_history_rollback_'+uuid4().hex[:16]
        with patch('request_history.database.RLS_SETUP_SQL','SELECT 1/0'):
            with self.assertRaises(HistoryUnavailable):
                prepare_database(dict(self.config,schema=schema))
        with psycopg.connect(self.config['admin_dsn']) as conn:
            self.assertFalse(conn.execute('SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)',(schema,)).fetchone()[0])

    def test_precommit_missing_rls_gate_rolls_back_new_namespace(self):
        schema = 'gw_history_badgate_'+uuid4().hex[:16]
        with patch('request_history.database.RLS_SETUP_SQL','SELECT 1'):
            with self.assertRaises(HistoryUnavailable):
                prepare_database(dict(self.config,schema=schema))
        with psycopg.connect(self.config['admin_dsn']) as conn:
            self.assertFalse(conn.execute('SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)',(schema,)).fetchone()[0])

    def test_owner_connection_and_disabled_rls_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = PostgresHistoryStore(self.config['admin_dsn'],StaticTestKmsProvider(),tenant_id='synthetic',
                                         domain='scope',retention_days=7,bucket='test',audit_directory=directory)
            with self.assertRaises(HistoryUnavailable):
                owner.check_ready()
        with psycopg.connect(self.config['admin_dsn']) as conn:
            conn.execute('ALTER TABLE request_stage_contents NO FORCE ROW LEVEL SECURITY')
        try:
            with psycopg.connect(self.config['app_dsn']) as conn:
                with self.assertRaises(HistoryUnavailable):
                    assert_history_connection(conn)
        finally:
            with psycopg.connect(self.config['admin_dsn']) as conn:
                conn.execute('ALTER TABLE request_stage_contents FORCE ROW LEVEL SECURITY')
