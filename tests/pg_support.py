"""Explicit, isolated real PostgreSQL test configuration; no substitute or skip."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import threading
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

_lock = threading.Lock()
_initialized = False
_runtime_configuration = None

def test_configuration() -> dict:
    if _runtime_configuration is not None:
        return _runtime_configuration
    path = Path(os.environ.get('GATEWAY_TEST_PG_CONFIG', Path(__file__).resolve().parents[1]/'.env.test'))
    if not path.is_file():
        raise RuntimeError('Explicit isolated PostgreSQL test configuration required.')
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    for key in ('app_dsn','admin_dsn','schema','application_role'):
        if not isinstance(config.get(key),str) or not config[key]:
            raise RuntimeError('Incomplete isolated PostgreSQL test configuration.')
    if not re.fullmatch(r'gw_test_[a-z0-9_]+',config['schema']):
        raise RuntimeError('Test schema must be an explicitly isolated gw_test_ namespace.')
    return config

def get_test_dsn() -> str:
    return test_configuration()['app_dsn']

def get_admin_dsn() -> str:
    return test_configuration()['admin_dsn']

def prepare_test_database() -> None:
    global _initialized, _runtime_configuration
    with _lock:
        if _initialized:
            return
        from knowledge.storage import PostgresKnowledgeStorage
        config=test_configuration()
        # Each verification process uses a fresh schema; never mutate an old layout.
        schema=config['schema']+'_'+uuid4().hex[:12]
        with psycopg.connect(config['admin_dsn']) as conn:
            conn.execute(sql.SQL('CREATE SCHEMA {} AUTHORIZATION CURRENT_USER').format(sql.Identifier(schema)))
        config=dict(config,schema=schema,
                    admin_dsn=make_conninfo(config['admin_dsn'],options='-c search_path='+schema),
                    app_dsn=make_conninfo(config['app_dsn'],options='-c search_path='+schema))
        _runtime_configuration=config
        PostgresKnowledgeStorage(config['admin_dsn']).init_database(enable_rls=True)
        with psycopg.connect(config['admin_dsn']) as conn:
            conn.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(config['schema']),sql.Identifier(config['application_role'])))
            conn.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}').format(sql.Identifier(config['schema']),sql.Identifier(config['application_role'])))
            conn.execute(sql.SQL('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}').format(sql.Identifier(config['schema']),sql.Identifier(config['application_role'])))
            conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION {}.invalidate_knowledge_source(TEXT,TEXT,TEXT,TIMESTAMPTZ) TO {}').format(sql.Identifier(config['schema']),sql.Identifier(config['application_role'])))
            conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION {}.read_authorized_knowledge_candidate(UUID) TO {}').format(sql.Identifier(config['schema']),sql.Identifier(config['application_role'])))
        with psycopg.connect(config['app_dsn']) as conn:
            role=conn.execute('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
            owns=conn.execute('SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)',(config['schema'],)).fetchone()[0]
            if role is None or any(role) or owns:
                raise RuntimeError('Test application must be nonowner, nonsuperuser, and no BYPASSRLS.')
        _initialized=True
