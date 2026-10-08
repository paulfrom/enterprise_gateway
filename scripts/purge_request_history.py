"""Physically delete expired history in one configured service domain.

This does not certify removal of backups or destruction of copied keys.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'), str(ROOT)]

from infra.file_kms import FileKmsProvider
from request_history.storage import PostgresHistoryStore
from start_gateway import _load_secret


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path,
                        help='Private JSON: app_dsn, tenant_id, domain, retention_days, bucket, audit_directory, kms_directory')
    args = parser.parse_args(argv)
    try:
        config = json.loads(args.config.read_text(encoding='utf-8-sig'))
        kms = FileKmsProvider(Path(config['kms_directory']),
                              _load_secret('GATEWAY_KMS_MASTER_KEY', exact_bytes=32))
        store = PostgresHistoryStore(config['app_dsn'],kms,tenant_id=config['tenant_id'],domain=config['domain'],
                                     retention_days=config['retention_days'],bucket=config['bucket'],
                                     audit_directory=config['audit_directory'])
        store.check_ready()
        count = store.purge_expired()
        print(json.dumps({'purged':count,'backups_deleted':False}))
        return 0
    except Exception:
        print(json.dumps({'purged':None,'reason':'request_history_purge_failed'}))
        return 1


if __name__=='__main__':
    sys.exit(main())
