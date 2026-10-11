#!/usr/bin/env python3
"""Read existing bindings and check permissions before updating running services."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=('backend', 'worker'), required=True)
    args = parser.parse_args(argv)
    phase = 'state'
    try:
        state = Path(os.environ['GATEWAY_STATE_DIR'])
        if not (state / 'keys').is_dir() or not (state / 'spool').is_dir():
            raise ValueError('existing initialized state required')
        if args.role == 'worker':
            phase = 'worker_database'
            from start_knowledge_worker import _secret, _validate_database
            from knowledge.storage import PostgresKnowledgeStorage
            _validate_database(PostgresKnowledgeStorage(_secret('GATEWAY_KNOWLEDGE_PG_DSN')))
        else:
            phase = 'admin_directory'
            directory = state / 'admin'
            if not directory.is_dir():
                raise ValueError('admin directory required')
            # This creates and removes one new probe file, never existing state.
            with tempfile.TemporaryFile(dir=directory) as probe:
                probe.write(b'SYNTHETIC_PERMISSION_PROBE'); probe.flush()
            phase = 'assets'
            for name in ('GATEWAY_DICTIONARY_FILE', 'GATEWAY_POLICY_FILE'):
                if not Path(os.environ[name]).is_file(): raise ValueError('controlled asset missing')
            if not Path(os.environ['GATEWAY_NER_PACKAGE_DIR']).is_dir():
                raise ValueError('existing model package required')
            phase = 'key_files'
            from start_gateway import _load_secret, _history_spec
            for name in ('GATEWAY_KMS_MASTER_KEY', 'GATEWAY_HMAC_KEY', 'GATEWAY_SOURCE_CORRELATION_KEY'):
                _load_secret(name, exact_bytes=32 if name == 'GATEWAY_KMS_MASTER_KEY' else None)
            phase = 'history_database'
            history = _history_spec()
            if history is not None:
                import psycopg
                from request_history.database import assert_history_connection
                with psycopg.connect(history['connection_uri'], connect_timeout=5) as conn:
                    assert_history_connection(conn)
        print(json.dumps({'validated': True, 'role': args.role, 'uid': os.getuid()}))
        return 0
    except Exception as error:
        # Server exception messages can contain DSNs. Emit only the known phase and class.
        print(json.dumps({'validated': False, 'role': args.role, 'phase': phase,
                          'exception_class': type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
