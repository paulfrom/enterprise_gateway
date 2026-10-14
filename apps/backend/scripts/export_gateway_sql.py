#!/usr/bin/env python3
"""Export complete table SQL for manual deployment into an existing database/schema."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gateway.database import gateway_tables_sql


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema', default='public', help='Existing infrastructure schema')
    parser.add_argument('--admin-role', default='gw_knowledge_admin', help='Existing knowledge administration login')
    parser.add_argument('--aliases-only', action='store_true', help='Export only the additive v2-to-v3 alias table SQL')
    parser.add_argument('--dictionary-only', action='store_true', help='Export only the additive v3-to-v4 dictionary tables')
    args = parser.parse_args(argv)
    sys.stdout.write(gateway_tables_sql(schema=args.schema, admin_role=args.admin_role,
                                      aliases_only=args.aliases_only, dictionary_only=args.dictionary_only))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
