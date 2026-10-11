"""Initialize all gateway tables in one new namespace with purpose-bound grants."""
from __future__ import annotations

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from knowledge.database_security import assert_no_privilege_path, assert_restricted_application_role
from knowledge.storage import (
    SCHEMA_SQL as KNOWLEDGE_SQL, RLS_SETUP_SQL as KNOWLEDGE_RLS,
    _ASSET_TABLES, _ADMIN_TABLES, SCHEMA_FINGERPRINT_V2, compute_schema_fingerprint,
)
from request_history.database import (
    SCHEMA_SQL as HISTORY_SQL, RLS_SETUP_SQL as HISTORY_RLS,
    TABLES as HISTORY_TABLES, EXPECTED_POLICIES, assert_history_connection, validate_namespace,
)


def prepare_database(config: dict[str, str]) -> dict[str, str]:
    """Atomically create a fresh schema; never reset or upgrade an existing one.

    Requires pre-created knowledge, history and knowledge-admin application roles.
    The owner DSN is used only for explicit DDL, never by the running applications.
    """
    schema = config['schema']
    validate_namespace(schema)
    roles = (config['application_role'], config['history_role'], config['admin_role'])
    if len(set(roles)) != 3:
        raise ValueError('purpose_roles_must_be_distinct')
    owner_dsn = make_conninfo(config['admin_dsn'], options='', connect_timeout=10)
    with psycopg.connect(owner_dsn) as owner:
        identity = owner.execute('SELECT current_database(),inet_server_addr()::text,inet_server_port()').fetchone()
        controlled = owner.execute('SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
        if not controlled or not controlled[0]:
            raise ValueError('controlled_ddl_owner_required')
        for dsn_key, role in zip(('app_dsn', 'history_dsn', 'admin_app_dsn'), roles):
            with psycopg.connect(make_conninfo(config[dsn_key], options='', connect_timeout=10)) as app:
                assert_restricted_application_role(app, role)
                if app.execute('SELECT current_database(),inet_server_addr()::text,inet_server_port()').fetchone() != identity:
                    raise ValueError('connections_target_different_databases')
            assert_no_privilege_path(owner, role=role, forbidden_role=owner.info.user)
        for role in roles:
            for other in roles:
                if other != role:
                    assert_no_privilege_path(owner, role=role, forbidden_role=other)
        if owner.execute('SELECT to_regnamespace(%s)', (schema,)).fetchone()[0] is not None:
            raise ValueError('namespace_already_exists')
        owner.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        owner.execute(sql.SQL('SET LOCAL search_path TO {}').format(sql.Identifier(schema)))
        literal = sql.Literal(roles[2]).as_string(owner)
        owner.execute(KNOWLEDGE_SQL.replace('__GOVERNANCE_SCHEMA__', sql.Identifier(schema).as_string(owner))
                      .replace('__ADMIN_ROLE__', literal))
        owner.execute(KNOWLEDGE_RLS.replace('__ADMIN_ROLE__', literal))
        owner.execute(HISTORY_SQL)
        owner.execute(HISTORY_RLS)
        owner.execute(sql.SQL('REVOKE ALL ON SCHEMA {} FROM PUBLIC').format(sql.Identifier(schema)))
        owner.execute(sql.SQL('REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM PUBLIC').format(sql.Identifier(schema)))
        knowledge_tables = (*_ASSET_TABLES, *_ADMIN_TABLES)
        for role, tables in ((roles[0], knowledge_tables), (roles[1], HISTORY_TABLES), (roles[2], knowledge_tables)):
            owner.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(schema), sql.Identifier(role)))
            owner.execute(sql.SQL('GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE {} TO {}').format(
                sql.SQL(',').join(sql.Identifier(schema, table) for table in tables), sql.Identifier(role)))
        for role in (roles[0], roles[2]):
            for signature in ('invalidate_knowledge_source(TEXT,TEXT,TEXT,TIMESTAMPTZ)',
                              'read_authorized_knowledge_candidate(UUID)'):
                owner.execute(sql.SQL('GRANT EXECUTE ON FUNCTION {}.' + signature + ' TO {}').format(
                    sql.Identifier(schema), sql.Identifier(role)))
        if compute_schema_fingerprint(owner, admin_role=roles[2]) != SCHEMA_FINGERPRINT_V2:
            raise ValueError('knowledge_schema_incompatible')
        history_rows = owner.execute(
            "SELECT relname,relrowsecurity,relforcerowsecurity,relkind FROM pg_class "
            "WHERE relnamespace=current_schema()::regnamespace AND relname=ANY(%s)",
            (list(HISTORY_TABLES),)).fetchall()
        history_policies = set(owner.execute(
            "SELECT tablename,policyname FROM pg_policies WHERE schemaname=current_schema() "
            "AND tablename=ANY(%s)", (list(HISTORY_TABLES),)).fetchall())
        if ({row[0] for row in history_rows} != set(HISTORY_TABLES)
                or any(not enabled or not forced or kind != 'r' for _, enabled, forced, kind in history_rows)
                or history_policies != EXPECTED_POLICIES):
            raise ValueError('history_schema_incompatible')
        for role, forbidden in ((roles[1], knowledge_tables), (roles[0], HISTORY_TABLES),
                                (roles[2], HISTORY_TABLES)):
            for table in forbidden:
                if owner.execute('SELECT has_table_privilege(%s,%s,%s)',
                                 (role, table, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')).fetchone()[0]:
                    raise ValueError('cross_purpose_table_access')
    bound = dict(config)
    for key in ('admin_dsn', 'app_dsn', 'history_dsn', 'admin_app_dsn'):
        bound[key] = make_conninfo(config[key], options='-c search_path=' + schema)
    with psycopg.connect(bound['history_dsn']) as app:
        assert_history_connection(app, expected_schema=schema, expected_role=roles[1])
    return bound
