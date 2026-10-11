"""Unified schema initialization must be atomic and preserve existing data."""
import unittest
from unittest.mock import patch
import subprocess
import sys

import psycopg

from gateway.database import prepare_database
from tests.pg_support import gateway_configuration


class UnifiedDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = gateway_configuration()

    def test_history_ddl_failure_rolls_back_knowledge_tables_and_namespace(self):
        schema = 'gw_test_unified_rollback'
        with psycopg.connect(self.config['admin_dsn']) as owner:
            self.assertIsNone(owner.execute('SELECT to_regnamespace(%s)', (schema,)).fetchone()[0])
        with patch('gateway.database.HISTORY_SQL', 'SELECT 1/0'):
            with self.assertRaises(psycopg.errors.DivisionByZero):
                prepare_database(dict(self.config, schema=schema))
        with psycopg.connect(self.config['admin_dsn']) as owner:
            self.assertIsNone(owner.execute('SELECT to_regnamespace(%s)', (schema,)).fetchone()[0])

    def test_existing_namespace_is_preserved(self):
        with psycopg.connect(self.config['admin_dsn']) as owner:
            before = owner.execute("SELECT oid,relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace ORDER BY oid").fetchall()
        with self.assertRaisesRegex(ValueError, 'namespace_already_exists'):
            prepare_database(self.config)
        with psycopg.connect(self.config['admin_dsn']) as owner:
            after = owner.execute("SELECT oid,relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace ORDER BY oid").fetchall()
        self.assertEqual(before, after)

    def test_missing_history_rls_rolls_back_both_modules_before_commit(self):
        schema = 'gw_test_unified_missing_rls'
        with psycopg.connect(self.config['admin_dsn']) as owner:
            self.assertIsNone(owner.execute('SELECT to_regnamespace(%s)', (schema,)).fetchone()[0])
        with patch('gateway.database.HISTORY_RLS', 'SELECT 1'):
            with self.assertRaisesRegex(ValueError, 'history_schema_incompatible'):
                prepare_database(dict(self.config, schema=schema))
        with psycopg.connect(self.config['admin_dsn']) as owner:
            self.assertIsNone(owner.execute('SELECT to_regnamespace(%s)', (schema,)).fetchone()[0])

    def test_concurrent_test_process_refuses_shared_schema_mutations(self):
        result = subprocess.run([sys.executable, '-c',
            "from tests.pg_support import prepare_test_database; prepare_test_database()"],
            capture_output=True, text=True, timeout=15)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Another gateway database test process is running.', result.stderr)
