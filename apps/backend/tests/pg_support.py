"""Reuse existing shared PostgreSQL tables; test setup never performs DDL or grants."""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading

from gateway.database import bind_database_configuration, verify_database

_lock = threading.Lock()
_initialized = False
_runtime_configuration = None


def test_configuration() -> dict:
    if _runtime_configuration is not None:
        return _runtime_configuration
    path = Path(os.environ.get('GATEWAY_TEST_PG_CONFIG') or os.environ.get('GATEWAY_HISTORY_PG_CONFIG')
                or Path(__file__).resolve().parents[1] / '.env.test')
    if not path.is_file():
        raise RuntimeError('Existing shared PostgreSQL service configuration required.')
    return bind_database_configuration(json.loads(path.read_text(encoding='utf-8-sig')))


def get_test_dsn() -> str:
    return test_configuration()['app_dsn']


def get_admin_dsn() -> str:
    """Existing restricted knowledge-admin login; never the infrastructure owner."""
    return test_configuration()['admin_app_dsn']


def prepare_test_database() -> None:
    """Validate deployed tables; preserve schemas, roles and all existing data."""
    global _initialized, _runtime_configuration
    with _lock:
        if _initialized:
            return
        bound = verify_database(test_configuration())
        _runtime_configuration = dict(bound, admin_dsn=bound['admin_app_dsn'])
        _initialized = True


def history_configuration() -> dict:
    prepare_test_database()
    config = test_configuration()
    return dict(schema=config['schema'], application_role=config['history_role'],
                app_dsn=config['history_dsn'], admin_dsn=config['history_dsn'])


def gateway_configuration() -> dict:
    prepare_test_database()
    return test_configuration()
