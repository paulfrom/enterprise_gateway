"""Explicit transactional initialization of a new request-history namespace."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from request_history.database import prepare_database, validate_namespace
from request_history.models import HistoryUnavailable


def load_configuration(path: Path) -> dict[str, str]:
    try:
        config = json.loads(path.read_text(encoding='utf-8-sig'))
        fields = ('schema','application_role','admin_dsn','app_dsn')
        if not isinstance(config,dict) or any(
            not isinstance(config.get(key),str) or not config[key].strip() for key in fields
        ):
            raise HistoryUnavailable()
        validate_namespace(config['schema'])
        return {key:config[key] for key in fields}
    except Exception:
        pass
    raise HistoryUnavailable()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True,
                        help='Private JSON: schema, application_role, admin_dsn, app_dsn')
    parser.add_argument('--output-config',type=Path,required=True,
                        help='New private file for schema-bound application/admin DSNs')
    args = parser.parse_args(argv)
    identity = None
    try:
        with args.output_config.open('x',encoding='utf-8') as output:
            stat = os.fstat(output.fileno())
            identity = (stat.st_dev,stat.st_ino)
            os.chmod(args.output_config,0o600)
            config = load_configuration(args.config)
            bound,report = prepare_database(config)
            json.dump(bound,output,indent=2)
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps(report,sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({'initialized':False,'reason':'request_history_preparation_failed'}))
    finally:
        if identity is not None:
            try:
                stat = args.output_config.stat()
                if stat.st_size==0 and (stat.st_dev,stat.st_ino)==identity:
                    args.output_config.unlink()
            except OSError:
                pass
    return 1


if __name__=='__main__':
    sys.exit(main())
