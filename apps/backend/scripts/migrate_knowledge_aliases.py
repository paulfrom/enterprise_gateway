#!/usr/bin/env python3
"""Explicitly add governed alias storage to an intact v2 deployment."""

import argparse
import json
from pathlib import Path

from gateway.database import migrate_knowledge_aliases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True, help='Private database deployment configuration')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    result = migrate_knowledge_aliases(config)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
