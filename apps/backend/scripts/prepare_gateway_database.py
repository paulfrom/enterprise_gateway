"""Explicit initialization of all gateway tables in a single new schema."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gateway.database import prepare_database


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--output-config', required=True, type=Path)
    args = parser.parse_args()
    created = False
    try:
        fd = os.open(args.output_config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, 'w') as output:
            config = prepare_database(json.loads(args.config.read_text()))
            json.dump(config, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({'initialized': True, 'table_count': 17, 'forced_rls': True}))
        return 0
    except Exception as exc:
        # Never print server exceptions or DSNs: they can contain connection secrets.
        if created and args.output_config.stat().st_size == 0:
            args.output_config.unlink()
        print(json.dumps({'initialized': False, 'error_type': type(exc).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
