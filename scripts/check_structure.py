#!/usr/bin/env python3
"""Validate the monorepo's source and dependency boundaries before installation."""
from pathlib import Path
import json
import os
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
GENERATED = {'.git', '.venv', '.uv-cache', '.codebase-memory', 'node_modules',
             'models', 'dist', 'build', '__pycache__', '.runtime_state',
             'runtime_state', '.pgdata', '.pg-runtime', 'reports', 'evidence'}


def check(root=ROOT):
    package = json.loads((root / 'package.json').read_text())
    if package.get('private') is not True or package.get('workspaces') != ['apps/admin-web']:
        raise RuntimeError('Root must be private with exactly the admin-web npm workspace')
    for name in ('src', 'tests', 'config', 'pyproject.toml', 'uv.lock',
                 'start_gateway.py', 'start_knowledge_worker.py', 'compose.yaml', 'Dockerfile'):
        if (root / name).exists() or (root / name).is_symlink():
            raise RuntimeError('Obsolete root source/configuration path: ' + name)
    required = ('package-lock.json', '.node-version', 'apps/backend/pyproject.toml',
                'apps/backend/uv.lock', 'apps/backend/scripts/check.sh',
                'apps/admin-web/package.json', 'contracts/admin.openapi.json',
                'deploy/compose.yaml', 'deploy/nginx/admin.conf')
    for name in required:
        if not (root / name).is_file():
            raise RuntimeError('Missing required input: ' + name)
    backend = tomllib.loads((root / 'apps/backend/pyproject.toml').read_text())
    if backend.get('project', {}).get('name') != 'enterprise-privacy-gateway':
        raise RuntimeError('Backend package identity changed')
    if 'workspace' in backend.get('tool', {}).get('uv', {}):
        raise RuntimeError('A Python workspace is outside the monorepo contract')
    if (root / 'apps/backend/src/gateway/web').exists():
        raise RuntimeError('Obsolete backend web assets remain')
    for directory, folders, files in os.walk(root, followlinks=False):
        path = Path(directory)
        if path != root and '.git' in (*folders, *files):
            raise RuntimeError('Nested Git repository: ' + str(path.relative_to(root)))
        folders[:] = [name for name in folders if name not in GENERATED]
        for name in files:
            relative = (path / name).relative_to(root).as_posix()
            if name in {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'uv.lock', 'pyproject.toml'}:
                if relative not in {'package-lock.json', 'apps/backend/uv.lock', 'apps/backend/pyproject.toml'}:
                    raise RuntimeError('Additional dependency root/lock: ' + relative)
    node = (root / '.node-version').read_text().strip()
    if not re.fullmatch(r'22\.\d+\.\d+', node):
        raise RuntimeError('.node-version must pin the verified Node 22 patch version')
    actual = subprocess.check_output(['node', '--version'], text=True).strip()
    if not actual.startswith('v22.'):
        raise RuntimeError('Node 22 is required: ' + actual)
    print('Monorepo structure passed: one Git root, npm workspace and Python project.')


if __name__ == '__main__':
    check()
