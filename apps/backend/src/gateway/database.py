"""Offline table DDL and read-only checks for an existing shared PostgreSQL database."""
from __future__ import annotations

import re

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from knowledge.database_security import (
    assert_no_history_access, assert_no_privilege_path, assert_restricted_application_role,
)
from knowledge.storage import (
    SCHEMA_SQL as KNOWLEDGE_SQL, RLS_SETUP_SQL as KNOWLEDGE_RLS,
    ALIAS_SCHEMA_SQL, ALIAS_RLS_SQL,
    _ASSET_TABLES, _ADMIN_TABLES, SCHEMA_FINGERPRINT_V3, compute_schema_fingerprint,
)
from request_history.database import (
    SCHEMA_SQL as HISTORY_SQL, RLS_SETUP_SQL as HISTORY_RLS,
    TABLES as HISTORY_TABLES, EXPECTED_POLICIES, assert_history_connection, validate_namespace,
)
from detection.dictionary_store import (
    TABLES as DICTIONARY_TABLES, SCHEMA_SQL as DICTIONARY_SQL, RLS_SQL as DICTIONARY_RLS,
    PostgresDictionaryStore,
)

CONNECTION_ROLES = (
    ('app_dsn', 'application_role'), ('history_dsn', 'history_role'),
    ('admin_app_dsn', 'admin_role'),
)
PROJECT_TABLES = (*_ASSET_TABLES, *_ADMIN_TABLES, *HISTORY_TABLES, *DICTIONARY_TABLES)


class DatabaseConfigurationError(ValueError):
    """Static readiness reason; never includes connection or server details."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def bind_database_configuration(config: dict[str, str]) -> dict[str, str]:
    """Bind existing service logins to an existing schema without connecting or provisioning."""
    schema = config.get('schema')
    validate_namespace(schema)
    roles = []
    bound = dict(config)
    bound.pop('admin_dsn', None)
    for dsn_key, role_key in CONNECTION_ROLES:
        role = config.get(role_key)
        if not isinstance(role, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,62}', role) or role.startswith('pg_'):
            raise DatabaseConfigurationError(role_key + '_required')
        if not isinstance(config.get(dsn_key), str) or not config[dsn_key]:
            raise DatabaseConfigurationError(dsn_key + '_required')
        roles.append(role)
        bound[dsn_key] = make_conninfo(config[dsn_key], options='-c search_path=' + schema, connect_timeout=10)
    if len(set(roles)) != len(roles):
        raise DatabaseConfigurationError('purpose_roles_must_be_distinct')
    return bound


def gateway_tables_sql(*, schema: str = 'public', admin_role: str = 'gw_knowledge_admin',
                       aliases_only: bool = False, dictionary_only: bool = False) -> str:
    """Render complete DDL for manual execution; never connect to PostgreSQL."""
    validate_namespace(schema)
    if aliases_only and dictionary_only:
        raise ValueError('one_increment_only')
    if not isinstance(admin_role, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,62}', admin_role) or admin_role.startswith('pg_'):
        raise ValueError('invalid_admin_role')
    namespace = sql.Identifier(schema).as_string()
    administrator = sql.Literal(admin_role).as_string()
    header = (
        ('-- Gateway v3: manually execute in the existing shared database.\n' if aliases_only
         else '-- Gateway v4: manually execute in the existing shared database.\n')
        + '-- Database, schema, logins and service grants are managed by infrastructure.\n'
        '-- Creates project tables and their required constraints, indexes, functions, trigger and policies.\n'
        '-- Existing tables/data are never dropped or reset.\n'
        f'-- Existing knowledge administration login: {admin_role}\n'
        'BEGIN;\n'
        f'SET LOCAL search_path TO {namespace};\n'
    )
    if aliases_only:
        return header + _repeatable_table_sql(ALIAS_SCHEMA_SQL + '\n' + ALIAS_RLS_SQL.replace('__ADMIN_ROLE__', administrator)) + '\nCOMMIT;\n'
    dictionary = DICTIONARY_SQL + '\n' + DICTIONARY_RLS.replace('__ADMIN_ROLE__', administrator)
    if dictionary_only:
        return header + _repeatable_table_sql(dictionary) + '\nCOMMIT;\n'
    knowledge = KNOWLEDGE_SQL.replace('__GOVERNANCE_SCHEMA__', namespace).replace('__ADMIN_ROLE__', administrator)
    policies = KNOWLEDGE_RLS.replace('__ADMIN_ROLE__', administrator)
    return header + _repeatable_table_sql(knowledge + '\n' + policies + '\n' + HISTORY_SQL + '\n' + HISTORY_RLS + '\n' + dictionary) + '\nCOMMIT;\n'


def _repeatable_table_sql(ddl: str) -> str:
    """Make the fixed project DDL repeatable without dropping tables or policies."""
    ddl = re.sub(r'\bCREATE TABLE ', 'CREATE TABLE IF NOT EXISTS ', ddl)
    ddl = re.sub(r'\bCREATE (UNIQUE )?INDEX ', lambda m: 'CREATE ' + (m[1] or '') + 'INDEX IF NOT EXISTS ', ddl)
    ddl = re.sub(r'\bCREATE FUNCTION ', 'CREATE OR REPLACE FUNCTION ', ddl)

    def statement_literal(statement, tag):
        while '$' + tag + '$' in statement:
            tag += '_'
        return '$' + tag + '$' + statement + '$' + tag + '$'

    def existing_policy(match):
        name, table, statement = match[1], match[2], match[0]
        return (
            'DO $gateway_policy$ BEGIN\n'
            ' IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname=' + sql.Literal(name).as_string()
            + ' AND polrelid=to_regclass(' + sql.Literal(table).as_string() + ')) THEN\n'
            '  EXECUTE ' + statement_literal(statement, 'gateway_policy_statement') + ';\n'
            ' END IF;\nEND $gateway_policy$;'
        )

    def existing_trigger(match):
        name, table, statement = match[1], match[2], match[0]
        return (
            'DO $gateway_trigger$ BEGIN\n'
            ' IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname=' + sql.Literal(name).as_string()
            + ' AND tgrelid=to_regclass(' + sql.Literal(table).as_string() + ')) THEN\n'
            '  EXECUTE ' + statement_literal(statement, 'gateway_trigger_statement') + ';\n'
            ' END IF;\nEND $gateway_trigger$;'
        )

    ddl = re.sub(r'CREATE TRIGGER (\w+)\s+.*?\bON (\w+)\s+.*?;', existing_trigger, ddl, flags=re.DOTALL)
    return re.sub(r'CREATE POLICY (\w+) ON (\w+)\s+.*?;', existing_policy, ddl, flags=re.DOTALL)


def verify_database(config: dict[str, str]) -> dict[str, str]:
    """Check existing tables, roles and one common database using read-only transactions."""
    bound = bind_database_configuration(config)
    identity = None
    for dsn_key, role_key in CONNECTION_ROLES:
        with psycopg.connect(bound[dsn_key]) as conn:
            conn.execute('SET TRANSACTION READ ONLY')
            assert_restricted_application_role(conn, bound[role_key])
            current = conn.execute('SELECT current_database(),inet_server_addr()::text,inet_server_port()').fetchone()
            if identity is not None and current != identity:
                raise DatabaseConfigurationError('connections_target_different_databases')
            identity = current
            if conn.execute('SELECT current_schema(),current_schemas(false)').fetchone() != (bound['schema'], [bound['schema']]):
                raise DatabaseConfigurationError('existing_schema_required')
            for _, other_role in CONNECTION_ROLES:
                if other_role != role_key:
                    assert_no_privilege_path(conn, role=bound[role_key], forbidden_role=bound[other_role])
            tables = HISTORY_TABLES if dsn_key == 'history_dsn' else (
                *_ASSET_TABLES, *_ADMIN_TABLES, *(DICTIONARY_TABLES if dsn_key == 'admin_app_dsn' else ()))
            grants = conn.execute(
                "SELECT relname,has_table_privilege(current_user,oid,'SELECT') "
                "AND has_table_privilege(current_user,oid,'INSERT') "
                "AND has_table_privilege(current_user,oid,'UPDATE') "
                "AND has_table_privilege(current_user,oid,'DELETE') "
                'FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname=ANY(%s)',
                (list(tables),),
            ).fetchall()
            if {name for name, _ in grants} != set(tables):
                raise DatabaseConfigurationError('existing_tables_required')
            if any(not granted for _, granted in grants):
                raise DatabaseConfigurationError('existing_table_grants_required')
            if dsn_key == 'history_dsn':
                assert_history_connection(conn, expected_schema=bound['schema'], expected_role=bound[role_key])
                policies = set(conn.execute(
                    'SELECT tablename,policyname FROM pg_policies WHERE schemaname=%s AND tablename=ANY(%s)',
                    (bound['schema'], list(HISTORY_TABLES)),
                ).fetchall())
                if policies != EXPECTED_POLICIES:
                    raise DatabaseConfigurationError('history_schema_incompatible')
            else:
                assert_no_history_access(conn)
                if dsn_key == 'admin_app_dsn':
                    PostgresDictionaryStore.verify_schema(conn)
                if compute_schema_fingerprint(conn, admin_role=bound['admin_role']) != SCHEMA_FINGERPRINT_V3:
                    raise DatabaseConfigurationError('knowledge_schema_incompatible')
                rows = conn.execute(
                    "SELECT relname,relrowsecurity,relforcerowsecurity,pg_has_role(current_user,relowner,'MEMBER') "
                    'FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname=ANY(%s)',
                    (list((*_ASSET_TABLES, *_ADMIN_TABLES)),),
                ).fetchall()
                if len(rows) != len(_ASSET_TABLES) + len(_ADMIN_TABLES) or any(not enabled or not forced or owner for _, enabled, forced, owner in rows):
                    raise DatabaseConfigurationError('existing_forced_rls_tables_required')
    return bound
