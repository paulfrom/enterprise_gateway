#!/usr/bin/env python3
"""Read-only verification of existing gateway tables and service connections."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gateway.database import DatabaseConfigurationError, PROJECT_TABLES, verify_database
from knowledge.database_security import DatabaseRoleError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        verify_database(json.loads(args.config.read_text(encoding='utf-8-sig')))
    except (DatabaseConfigurationError, DatabaseRoleError) as exc:
        print(json.dumps({'ready': False, 'reason': exc.reason, 'error_type': type(exc).__name__}))
        return 1
    except Exception as exc:
        print(json.dumps({'ready': False, 'error_type': type(exc).__name__}))
        return 1
    print(json.dumps({'ready': True, 'table_count': len(PROJECT_TABLES), 'read_only': True}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
