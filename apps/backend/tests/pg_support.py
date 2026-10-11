"""Explicit, isolated real PostgreSQL test configuration; no substitute or skip."""
from __future__ import annotations
import atexit
import json
import os
from pathlib import Path
import threading
import sys
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo, conninfo_to_dict

_lock = threading.Lock()
_initialized = False
_runtime_configuration = None
_created = []
_session = None
_history_configuration = None
_gateway_configuration = None


def _cleanup() -> None:
    global _session
    for base_admin_dsn, schema, roles in reversed(_created):
        try:
            with psycopg.connect(base_admin_dsn, connect_timeout=10) as conn:
                if schema is not None:
                    conn.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
                for role in roles:
                    if not conn.execute('SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)', (role,)).fetchone()[0]:
                        continue
                    conn.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
                    conn.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))
        except Exception as exc:
            print('Gateway test cleanup failed: '+type(exc).__name__, file=sys.stderr)
    if _session is not None:
        _session.close()
        _session = None


atexit.register(_cleanup)

def test_configuration() -> dict:
    if _runtime_configuration is not None:
        return _runtime_configuration
    path = Path(os.environ.get('GATEWAY_TEST_PG_CONFIG') or os.environ.get('GATEWAY_HISTORY_PG_CONFIG')
                or Path(__file__).resolve().parents[1]/'.env.test')
    if not path.is_file():
        raise RuntimeError('Explicit isolated PostgreSQL test configuration required.')
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    for key in ('app_dsn','admin_dsn','schema','application_role'):
        if not isinstance(config.get(key),str) or not config[key]:
            raise RuntimeError('Incomplete isolated PostgreSQL test configuration.')
    if config['schema'] != 'gw_test_gateway':
        raise RuntimeError('Tests require the single gw_test_gateway schema.')
    if any(conninfo_to_dict(config[key]).get('dbname') != 'enterprise_gateway' for key in ('app_dsn', 'admin_dsn')):
        raise RuntimeError('Tests require the dedicated enterprise_gateway database.')
    return config

def get_test_dsn() -> str:
    return test_configuration()['app_dsn']

def get_admin_dsn() -> str:
    return test_configuration()['admin_dsn']

def prepare_test_database() -> None:
    global _initialized, _runtime_configuration, _session, _history_configuration, _gateway_configuration
    with _lock:
        if _initialized:
            return
        from gateway.database import prepare_database
        config = test_configuration()
        base_admin_dsn = make_conninfo(config['admin_dsn'], options='', connect_timeout=10)
        # A session lock serializes processes using the one fixed test schema.
        # Refuse leftovers from a crashed run; never silently reset existing data.
        _session = psycopg.connect(base_admin_dsn, autocommit=True)
        if not _session.execute("SELECT pg_try_advisory_lock(710231, 1)").fetchone()[0]:
            _session.close()
            _session = None
            raise RuntimeError('Another gateway database test process is running.')
        schema = config['schema']
        if _session.execute('SELECT to_regnamespace(%s)', (schema,)).fetchone()[0] is not None:
            _session.close()
            _session = None
            raise RuntimeError('Existing gateway test schema preserved; explicit cleanup required.')
        token = uuid4().hex[:12]
        history_role, admin_role = 'gw_test_history_'+token, 'gw_test_admin_'+token
        history_password, admin_password = os.urandom(32).hex(), os.urandom(32).hex()
        # Register roles before provisioning; claim a namespace only after our
        # initializer succeeds, so a concurrent external collision is preserved.
        _created.append((base_admin_dsn, None, (history_role, admin_role)))
        with psycopg.connect(base_admin_dsn) as conn:
            for role, password in ((history_role, history_password), (admin_role, admin_password)):
                conn.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB '
                                     'NOCREATEROLE NOREPLICATION PASSWORD {}').format(sql.Identifier(role), sql.Literal(password)))
                conn.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO {}').format(
                    sql.Identifier(conn.info.dbname), sql.Identifier(role)))
        bound = prepare_database(dict(config, admin_dsn=base_admin_dsn, history_role=history_role,
                     history_dsn=make_conninfo(config['app_dsn'], user=history_role, password=history_password),
                     admin_role=admin_role,
                     admin_app_dsn=make_conninfo(config['app_dsn'], user=admin_role, password=admin_password)))
        _created[-1] = (base_admin_dsn, schema, (history_role, admin_role))
        _gateway_configuration = bound
        # Governance tests explicitly need the DDL-owner connection for fixtures.
        # Runtime login tests derive a restricted login from this private owner DSN.
        _runtime_configuration = dict(bound, admin_app_dsn=bound['admin_dsn'])
        _history_configuration = dict(schema=schema, application_role=history_role,
                     admin_dsn=bound['admin_dsn'], app_dsn=bound['history_dsn'],
                     report={'initialized': True, 'forced_rls': True, 'asset_count': 2},
                     original_schema=schema)
        _initialized = True


def history_configuration() -> dict:
    prepare_test_database()
    return _history_configuration


def gateway_configuration() -> dict:
    prepare_test_database()
    return _gateway_configuration
