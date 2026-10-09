"""Transactional new-namespace DDL and schema-bound application safety checks."""
from __future__ import annotations

import re

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from knowledge.database_security import assert_restricted_application_role
from request_history.models import ERROR_CODES, HistoryUnavailable

TABLES = ("request_records", "request_stage_contents")

SCHEMA_SQL = """
CREATE TABLE request_records (
 request_id UUID PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 domain TEXT NOT NULL,
 protocol TEXT NOT NULL CHECK(protocol IN ('deepseek-chat-completions','claude-messages')),
 model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 256),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('processing','completed','blocked','failed','partial')),
 error_code TEXT CHECK(error_code IS NULL OR error_code IN (__ERROR_CODES__)),
 UNIQUE(tenant_id,domain,request_id),
 CHECK(expires_at>created_at)
);
CREATE INDEX request_records_scope_time ON request_records(tenant_id,domain,created_at DESC,request_id DESC);
CREATE INDEX request_records_expiry ON request_records(tenant_id,domain,expires_at);
CREATE TABLE request_stage_contents (
 tenant_id TEXT NOT NULL,
 domain TEXT NOT NULL,
 request_id UUID NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('input','redacted','upstream','restored')),
 state TEXT NOT NULL CHECK(state IN ('complete','partial')),
 media_type TEXT NOT NULL CHECK(media_type IN ('application/json','text/event-stream')),
 envelope BYTEA NOT NULL,
 PRIMARY KEY(request_id,stage),
 FOREIGN KEY(tenant_id,domain,request_id) REFERENCES request_records(tenant_id,domain,request_id) ON DELETE CASCADE
);
""".replace('__ERROR_CODES__',','.join("'"+code+"'" for code in sorted(ERROR_CODES)))

_SCOPE = "tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true)"
_MODE = "current_setting('request_history.mode',true)"
RLS_SETUP_SQL = f"""
ALTER TABLE request_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_records FORCE ROW LEVEL SECURITY;
ALTER TABLE request_stage_contents ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_stage_contents FORCE ROW LEVEL SECURITY;
CREATE POLICY history_read ON request_records FOR SELECT USING (
 {_SCOPE} AND (({_MODE} IN ('reader','writer') AND expires_at>clock_timestamp())
 OR ({_MODE}='purger' AND expires_at<=clock_timestamp())));
CREATE POLICY history_insert ON request_records FOR INSERT WITH CHECK (
 {_SCOPE} AND {_MODE}='writer' AND status='processing' AND expires_at>clock_timestamp());
CREATE POLICY history_update ON request_records FOR UPDATE USING (
 {_SCOPE} AND {_MODE}='writer' AND expires_at>clock_timestamp())
 WITH CHECK ({_SCOPE} AND {_MODE}='writer' AND expires_at>clock_timestamp());
CREATE POLICY history_purge ON request_records FOR DELETE USING (
 {_SCOPE} AND {_MODE}='purger' AND expires_at<=clock_timestamp());
CREATE POLICY stage_read ON request_stage_contents FOR SELECT USING (
 {_SCOPE} AND {_MODE} IN ('reader','writer') AND EXISTS (
 SELECT 1 FROM request_records r WHERE r.request_id=request_stage_contents.request_id));
CREATE POLICY stage_insert ON request_stage_contents FOR INSERT WITH CHECK (
 {_SCOPE} AND {_MODE}='writer' AND EXISTS (SELECT 1 FROM request_records r
 WHERE r.request_id=request_stage_contents.request_id AND r.status='processing'));
CREATE POLICY stage_update ON request_stage_contents FOR UPDATE USING (
 {_SCOPE} AND {_MODE}='writer' AND EXISTS (SELECT 1 FROM request_records r
 WHERE r.request_id=request_stage_contents.request_id AND r.status='processing'))
 WITH CHECK ({_SCOPE} AND {_MODE}='writer' AND EXISTS (SELECT 1 FROM request_records r
 WHERE r.request_id=request_stage_contents.request_id AND r.status='processing'));
"""


def validate_namespace(schema: str) -> None:
    if (not isinstance(schema, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema)
            or schema.startswith("pg_") or schema in {"public", "information_schema"}):
        raise HistoryUnavailable()


def assert_history_connection(conn: psycopg.Connection, *, expected_schema: str | None = None,
                              expected_role: str | None = None) -> tuple[str, str]:
    """Recheck identity, forced RLS, and inaccessible schema/table owners each session."""
    assert_restricted_application_role(conn, expected_role)
    schema, schemas, role = conn.execute("SELECT current_schema(),current_schemas(false),current_user").fetchone()
    validate_namespace(schema)
    if schemas != [schema] or (expected_schema is not None and schema != expected_schema):
        raise HistoryUnavailable()
    rows = conn.execute(
        "SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,"
        "pg_has_role(current_user,c.relowner,'MEMBER'),c.relkind "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s AND c.relname=ANY(%s)", (schema, list(TABLES)),
    ).fetchall()
    if (len(rows) != len(TABLES) or {row[0] for row in rows} != set(TABLES)
            or any(not row[1] or not row[2] or row[3] or row[4] != 'r' for row in rows)):
        raise HistoryUnavailable()
    namespace = conn.execute(
        "SELECT pg_has_role(current_user,nspowner,'MEMBER'),"
        "has_schema_privilege(current_user,oid,'CREATE') FROM pg_namespace WHERE nspname=%s", (schema,),
    ).fetchone()
    if not namespace or any(namespace):
        raise HistoryUnavailable()
    # This namespace is purpose-exclusive; never point history at the knowledge layout.
    actual = conn.execute(
        "SELECT relname FROM pg_class WHERE relnamespace=%s::regnamespace AND relkind IN ('r','p','v','m','f')",
        (schema,),
    ).fetchall()
    if {row[0] for row in actual} != set(TABLES):
        raise HistoryUnavailable()
    return schema, role


def prepare_database(config: dict[str, str]) -> tuple[dict[str, str], dict]:
    """Provision one new schema; no existing-layout upgrade and no role creation."""
    try:
        schema, role = config['schema'], config['application_role']
        validate_namespace(schema)
        if not isinstance(role, str) or not role:
            raise HistoryUnavailable()
        admin_dsn = make_conninfo(config['admin_dsn'], options='', connect_timeout=10)
        app_dsn = make_conninfo(config['app_dsn'], options='', connect_timeout=10)
        with psycopg.connect(admin_dsn) as admin, psycopg.connect(app_dsn) as app:
            assert_restricted_application_role(app, role)
            identity = "SELECT current_database(),inet_server_addr()::text,inet_server_port()"
            if admin.execute(identity).fetchone() != app.execute(identity).fetchone():
                raise HistoryUnavailable()
            owner = admin.execute('SELECT current_user').fetchone()[0]
            if admin.execute("SELECT pg_has_role(%s,%s,'MEMBER')", (role, owner)).fetchone()[0]:
                raise HistoryUnavailable()
            if admin.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)", (schema,)).fetchone()[0]:
                raise HistoryUnavailable()
            admin.execute(sql.SQL('CREATE SCHEMA {} AUTHORIZATION CURRENT_USER').format(sql.Identifier(schema)))
            admin.execute(sql.SQL('SET LOCAL search_path TO {}').format(sql.Identifier(schema)))
            admin.execute(SCHEMA_SQL)
            admin.execute(RLS_SETUP_SQL)
            admin.execute(sql.SQL('REVOKE ALL ON SCHEMA {} FROM PUBLIC').format(sql.Identifier(schema)))
            admin.execute(sql.SQL('REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM PUBLIC').format(sql.Identifier(schema)))
            admin.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(schema), sql.Identifier(role)))
            admin.execute(sql.SQL('GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA {} TO {}').format(sql.Identifier(schema), sql.Identifier(role)))
            # Validate the new objects within the same DDL transaction. A failed
            # gate must roll back creation instead of leaving a committed layout.
            rows = admin.execute(
                "SELECT relname,relrowsecurity,relforcerowsecurity,pg_has_role(%s,relowner,'MEMBER'),relkind "
                "FROM pg_class WHERE relnamespace=%s::regnamespace AND relname=ANY(%s)",
                (role,schema,list(TABLES)),
            ).fetchall()
            namespace = admin.execute(
                "SELECT pg_has_role(%s,nspowner,'MEMBER'),has_schema_privilege(%s,oid,'CREATE') "
                "FROM pg_namespace WHERE nspname=%s", (role,role,schema),
            ).fetchone()
            expected_policies = {
                ('request_records','history_read'),('request_records','history_insert'),
                ('request_records','history_update'),('request_records','history_purge'),
                ('request_stage_contents','stage_read'),('request_stage_contents','stage_insert'),
                ('request_stage_contents','stage_update'),
            }
            policies = admin.execute(
                'SELECT tablename,policyname FROM pg_policies WHERE schemaname=%s',(schema,),
            ).fetchall()
            if (len(rows)!=len(TABLES) or {row[0] for row in rows}!=set(TABLES)
                    or any(not row[1] or not row[2] or row[3] or row[4]!='r' for row in rows)
                    or not namespace or any(namespace) or set(policies)!=expected_policies):
                raise HistoryUnavailable()
            version = admin.info.server_version
            ssl = admin.execute('SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()').fetchone()
        bound = dict(config, admin_dsn=make_conninfo(admin_dsn, options='-c search_path='+schema),
                     app_dsn=make_conninfo(app_dsn, options='-c search_path='+schema))
        with psycopg.connect(bound['app_dsn']) as app:
            assert_history_connection(app, expected_schema=schema, expected_role=role)
        return bound, {'initialized': True, 'forced_rls': True, 'asset_count': len(TABLES),
                       'application_restricted': True, 'server_version': version, 'tls': bool(ssl and ssl[0])}
    except Exception:
        pass
    raise HistoryUnavailable()
