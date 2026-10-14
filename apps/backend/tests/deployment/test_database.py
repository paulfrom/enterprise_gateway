"""Existing shared PostgreSQL is verified without provisioning or changing permissions."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import psycopg
from psycopg.conninfo import conninfo_to_dict

from gateway.database import (
    PROJECT_TABLES, bind_database_configuration, gateway_tables_sql, verify_database,
)
from knowledge.age_graph import AgeGraphManager, OutboxGraphSyncer
from knowledge.database_security import DatabaseRoleError, assert_restricted_application_role
from knowledge.knowledge import KnowledgeError
from knowledge.storage import SCHEMA_FINGERPRINT_V3, compute_schema_fingerprint
from request_history.database import EXPECTED_POLICIES, TABLES
from scripts.check_gateway_database import main
from tests import pg_support

ROOT = Path(__file__).resolve().parents[4]
CONFIG = {
    'schema': 'public', 'application_role': 'knowledge_app', 'history_role': 'history_app',
    'admin_role': 'knowledge_admin',
    'app_dsn': 'host=127.0.0.1 port=5433 dbname=shared user=knowledge_app password=synthetic-secret',
    'history_dsn': 'host=127.0.0.1 port=5433 dbname=shared user=history_app password=synthetic-secret',
    'admin_app_dsn': 'host=127.0.0.1 port=5433 dbname=shared user=knowledge_admin password=synthetic-secret',
}


class ExistingConnection:
    """Reject any SQL outside read-only metadata/session checks."""

    def __init__(self, role, *, database='shared', schema='public', database_create=False, missing_dml=False):
        self.info = SimpleNamespace(user=role)
        self.role, self.database, self.schema = role, database, schema
        self.database_create = database_create
        self.missing_dml = missing_dml
        self.statements = []
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, statement, parameters=None):
        self.statements.append(statement)
        if statement == 'SET TRANSACTION READ ONLY':
            self.rows = []
            return self
        if not statement.startswith('SELECT') and not statement.startswith('WITH RECURSIVE'):
            raise AssertionError('Unexpected infrastructure mutation: ' + statement)
        if 'current_database(),inet_server_addr()' in statement:
            self.rows = [(self.database, '127.0.0.1', 5433)]
        elif 'current_schema(),current_schemas(false),current_user' in statement:
            self.rows = [(self.schema, [self.schema], self.role)]
        elif 'current_schema(),current_schemas(false)' in statement:
            self.rows = [(self.schema, [self.schema])]
        elif 'session_user,rolsuper' in statement:
            self.rows = [(self.role, self.role, False, False, False, False, False)]
        elif 'has_database_privilege' in statement:
            self.rows = [(self.database_create,)]
        elif 'WITH RECURSIVE' in statement:
            self.rows = [(0,)]
        elif statement.startswith('SELECT EXISTS'):
            self.rows = [(False,)]
        elif 'has_schema_privilege' in statement:
            self.rows = [(False, False)]
        elif 'relname,has_table_privilege' in statement and 'AND has_table_privilege' in statement:
            self.rows = [(name, not self.missing_dml) for name in parameters[0]]
        elif 'relname,has_table_privilege' in statement:
            self.rows = [(name, name in TABLES) for name in (*PROJECT_TABLES, 'infrastructure_table')]
        elif 'FROM pg_policies' in statement:
            if 'qual,with_check' in statement:
                expression = (f"CURRENT_USER = '{self.role}' AND tenant_id=current_setting('app.tenant',true) "
                              "AND domain=current_setting('app.domain',true) "
                              "AND current_setting('app.admin_context',true)='true'")
                self.rows = [(name, 'dictionary_admin_scope', expression, expression, 'ALL', ['public'])
                             for name in parameters[0]]
            else:
                self.rows = list(EXPECTED_POLICIES)
        elif 'FROM pg_trigger' in statement:
            self.rows = [('O', 27, "BEGIN RAISE EXCEPTION 'Published dictionary versions are immutable'; END;",
                          False, ['search_path=pg_catalog'])]
        elif 'c.relname,c.relrowsecurity' in statement:
            self.rows = [(name, True, True, False, 'r') for name in TABLES]
        elif 'relname,relrowsecurity' in statement:
            self.rows = [(name, True, True, False, True) if 'has_table_privilege' in statement
                         else (name, True, True, False) for name in parameters[0]]
        else:
            raise AssertionError('Unhandled metadata query: ' + statement)
        return self

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class SharedDatabaseTests(unittest.TestCase):
    def connections(self, *, foreign_database=False):
        connections = []

        def connect(dsn):
            role = conninfo_to_dict(dsn)['user']
            conn = ExistingConnection(role, database='other' if foreign_database and role == 'history_app' else 'shared')
            connections.append(conn)
            return conn

        return connections, connect

    def test_existing_shared_schema_and_all_service_connections_are_read_only(self):
        connections, connect = self.connections()
        with patch('gateway.database.psycopg.connect', side_effect=connect), \
                patch('gateway.database.compute_schema_fingerprint', return_value=SCHEMA_FINGERPRINT_V3):
            config = verify_database(CONFIG)
        self.assertEqual('public', config['schema'])
        self.assertEqual(3, len(connections))
        self.assertTrue(all(conn.statements[0] == 'SET TRANSACTION READ ONLY' for conn in connections))
        self.assertTrue(all(conninfo_to_dict(config[key])['dbname'] == 'shared'
                            for key in ('app_dsn', 'history_dsn', 'admin_app_dsn')))

    def test_different_database_is_rejected_without_creating_a_replacement(self):
        connections, connect = self.connections(foreign_database=True)
        with patch('gateway.database.psycopg.connect', side_effect=connect), \
                patch('gateway.database.compute_schema_fingerprint', return_value=SCHEMA_FINGERPRINT_V3):
            with self.assertRaisesRegex(ValueError, 'connections_target_different_databases'):
                verify_database(CONFIG)
        self.assertEqual(2, len(connections))

    def test_test_setup_reuses_tables_and_does_not_need_owner_credentials(self):
        connections, connect = self.connections()
        with patch.object(pg_support, '_initialized', False), \
                patch.object(pg_support, '_runtime_configuration', None), \
                patch.object(pg_support, 'test_configuration', return_value=CONFIG), \
                patch('gateway.database.psycopg.connect', side_effect=connect), \
                patch('gateway.database.compute_schema_fingerprint', return_value=SCHEMA_FINGERPRINT_V3):
            pg_support.prepare_test_database()
            pg_support.prepare_test_database()
            self.assertEqual(3, len(connections))
            self.assertEqual('knowledge_admin', conninfo_to_dict(pg_support._runtime_configuration['admin_dsn'])['user'])

    def test_schema_creation_capability_is_rejected_by_metadata_only(self):
        conn = ExistingConnection('knowledge_app', database_create=True)
        with self.assertRaisesRegex(DatabaseRoleError, 'application_can_create_schema'):
            assert_restricted_application_role(conn)

    def test_existing_owner_input_is_not_propagated_to_applications(self):
        config = bind_database_configuration(dict(CONFIG, admin_dsn='synthetic-owner-secret'))
        self.assertNotIn('admin_dsn', config)

    def test_missing_existing_table_grants_fails_without_granting_them(self):
        conn = ExistingConnection('knowledge_app', missing_dml=True)
        with patch('gateway.database.psycopg.connect', return_value=conn):
            with self.assertRaisesRegex(ValueError, 'existing_table_grants_required'):
                verify_database(CONFIG)

    def test_checker_never_prints_connection_secrets_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'connections.json'
            config.write_text(json.dumps(CONFIG))
            output = io.StringIO()
            with redirect_stdout(output), patch('scripts.check_gateway_database.verify_database',
                                               side_effect=psycopg.OperationalError('synthetic-secret')):
                self.assertEqual(1, main(['--config', str(config)]))
        self.assertNotIn('synthetic-secret', output.getvalue())
        self.assertEqual(json.loads(output.getvalue()), {'ready': False, 'error_type': 'OperationalError'})

    def test_graph_rebuild_requires_scope_before_connecting(self):
        with patch('knowledge.age_graph.psycopg.connect') as connect:
            with self.assertRaises(KnowledgeError):
                OutboxGraphSyncer('unused', SimpleNamespace()).rebuild_all_projections()
            connect.assert_not_called()

    def test_missing_age_is_reported_without_installing_extension(self):
        conn = ExistingConnection('knowledge_admin')
        with patch('knowledge.age_graph.psycopg.connect', return_value=conn):
            with self.assertRaisesRegex(KnowledgeError, 'Existing AGE infrastructure'):
                AgeGraphManager('unused', graph_name='existing_projection').verify_graph()
        self.assertEqual(conn.statements[0], 'SET TRANSACTION READ ONLY')


class ManualTableSqlTests(unittest.TestCase):
    def test_complete_sql_matches_all_project_tables_and_checked_in_artifact(self):
        with patch('psycopg.connect') as connect:
            ddl = gateway_tables_sql()
            connect.assert_not_called()
        tables = re.findall(r'CREATE TABLE IF NOT EXISTS ([a-z_]+)', ddl)
        self.assertEqual(set(tables), set(PROJECT_TABLES))
        self.assertEqual(len(tables), 22)
        self.assertEqual(ddl, (ROOT / 'deploy/sql/gateway_tables.sql').read_text())
        self.assertNotRegex(ddl, r'(?i)(CREATE|DROP)\s+(DATABASE|SCHEMA|ROLE|EXTENSION)')
        self.assertNotRegex(ddl, r'(?i)(GRANT|REVOKE)[^;]+ON\s+(DATABASE|SCHEMA)')
        self.assertNotIn('__ADMIN_ROLE__', ddl)
        self.assertNotIn('__GOVERNANCE_SCHEMA__', ddl)

    def test_alias_increment_is_additive_and_matches_checked_in_artifact(self):
        ddl = gateway_tables_sql(aliases_only=True)
        self.assertEqual(re.findall(r'CREATE TABLE IF NOT EXISTS ([a-z_]+)', ddl), ['entity_aliases'])
        self.assertNotIn('DROP ', ddl)
        self.assertEqual(ddl, (ROOT / 'deploy/sql/entity_aliases_v3.sql').read_text())

    def test_existing_target_names_are_bound_and_sql_injection_is_rejected(self):
        ddl = gateway_tables_sql(schema='existing_gateway', admin_role='existing_admin')
        self.assertIn('SET LOCAL search_path TO "existing_gateway"', ddl)
        self.assertIn("current_user = 'existing_admin'", ddl)
        for schema in ('public; CREATE SCHEMA unexpected', 'pg_catalog', 'information_schema'):
            with self.subTest(schema=schema), self.assertRaises(Exception):
                gateway_tables_sql(schema=schema)

    def test_fingerprint_is_stable_for_public_without_rewriting_publication_names(self):
        class MetadataConnection:
            def __init__(self, schema):
                self.schema = schema

            def execute(self, query, parameters=None):
                if query == 'SELECT current_schema()':
                    self.rows = [(self.schema,)]
                elif 'c.relname,c.relrowsecurity' in query:
                    self.rows = [('knowledge_publications', True, True)]
                elif 'pg_indexes' in query:
                    self.rows = [('knowledge_publications', 'knowledge_publications_pkey',
                                  f'CREATE UNIQUE INDEX knowledge_publications_pkey ON {self.schema}.knowledge_publications (publication_id)')]
                elif 'pg_proc' in query:
                    self.rows = [('read_authorized_knowledge_candidate', '', True,
                                  [f'search_path=pg_catalog, {self.schema}'], 'SELECT * FROM knowledge_publications')]
                elif 'FROM pg_policies' in query:
                    self.rows = [('knowledge_publications', 'admin_access', 'ALL', ['public'],
                                  "current_user = 'knowledge_admin'", None)]
                else:
                    self.rows = []
                return self

            def fetchone(self):
                return self.rows[0]

            def fetchall(self):
                return self.rows

        self.assertEqual(compute_schema_fingerprint(MetadataConnection('public'), admin_role='knowledge_admin'),
                         compute_schema_fingerprint(MetadataConnection('existing_schema'), admin_role='knowledge_admin'))
