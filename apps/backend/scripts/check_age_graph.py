#!/usr/bin/env python3
"""Read-only verification of an existing infrastructure AGE projection."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from psycopg.conninfo import make_conninfo

from knowledge.age_graph import AgeGraphManager
from request_history.database import validate_namespace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = json.loads(args.config.read_text(encoding='utf-8-sig'))
        validate_namespace(config['schema'])
        dsn = make_conninfo(config['admin_app_dsn'], options='-c search_path=' + config['schema'])
        graph = AgeGraphManager(dsn, graph_name=config.get('graph_name'))
        graph.verify_graph()
    except Exception as exc:
        print(json.dumps({'ready': False, 'error_type': type(exc).__name__}))
        return 1
    print(json.dumps({'graph_name': graph.graph_name, 'ready': True}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
