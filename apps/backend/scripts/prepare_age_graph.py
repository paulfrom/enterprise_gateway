#!/usr/bin/env python3
"""Provision an AGE projection and grant access to the restricted admin role."""

import argparse
import json
from pathlib import Path

from psycopg.conninfo import make_conninfo

from knowledge.age_graph import AgeGraphManager
from request_history.database import validate_namespace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    config = json.loads(parser.parse_args().config.read_text())
    validate_namespace(config['schema'])
    dsn = make_conninfo(config['admin_dsn'], options='-c search_path=' + config['schema'])
    graph = AgeGraphManager(dsn)
    graph.ensure_graph(application_role=config['admin_role'])
    print(json.dumps({'graph_name': graph.graph_name, 'prepared': True}))


if __name__ == '__main__':
    main()
