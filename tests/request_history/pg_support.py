"""Fresh history schema and dedicated role; only synthetic records are inserted."""
from __future__ import annotations

import atexit
import json
import os
from pathlib import Path
import threading
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from request_history.database import prepare_database

_lock = threading.Lock()
_config = None
_created = []


def _cleanup() -> None:
    for admin_dsn,schema,role in reversed(_created):
        try:
            with psycopg.connect(admin_dsn,connect_timeout=10) as conn:
                # Only names explicitly created by this process, never a configured existing namespace.
                conn.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
                conn.execute(sql.SQL('REVOKE CONNECT ON DATABASE {} FROM {}').format(
                    sql.Identifier(conn.info.dbname),sql.Identifier(role)))
                conn.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
        except Exception:
            pass


atexit.register(_cleanup)


def configuration() -> dict:
    global _config
    with _lock:
        if _config is not None:
            return _config
        path = os.environ.get('GATEWAY_HISTORY_PG_CONFIG')
        if not path:
            raise RuntimeError('Explicit isolated history PostgreSQL configuration required')
        try:
            base = json.loads(Path(path).read_text(encoding='utf-8-sig'))
            token = uuid4().hex[:16]
            role,schema = 'gw_hist_role_'+token,'gw_history_test_'+token
            password = os.urandom(32).hex()
            admin_dsn = make_conninfo(base['admin_dsn'],options='',connect_timeout=10)
            with psycopg.connect(admin_dsn) as conn:
                conn.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB '
                                     'NOCREATEROLE NOREPLICATION PASSWORD {}').format(
                                         sql.Identifier(role),sql.Literal(password)))
                # Existing databases can revoke PUBLIC CONNECT. This grants
                # only connection admission to this newly created test role;
                # it does not grant any existing schema or knowledge access.
                conn.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO {}').format(
                    sql.Identifier(conn.info.dbname),sql.Identifier(role)))
            _created.append((admin_dsn,schema,role))
            app_dsn = make_conninfo(base['app_dsn'],user=role,password=password,options='',connect_timeout=10)
            config,report = prepare_database(dict(admin_dsn=admin_dsn,app_dsn=app_dsn,
                                                 schema=schema,application_role=role))
            _config = dict(config,report=report,original_schema=base['schema'])
            return _config
        except Exception:
            pass
        raise RuntimeError('Isolated history PostgreSQL setup failed')


def get_test_dsn() -> str:
    return configuration()['app_dsn']


def get_admin_dsn() -> str:
    return configuration()['admin_dsn']
