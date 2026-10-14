#!/usr/bin/env python3
"""Prove both Docker allowlists with synthetic files and real BuildKit exports."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ('package.json', 'package-lock.json', '.node-version', 'contracts/admin.openapi.json',
            'deploy/nginx/admin.conf', 'apps/admin-web/package.json', 'apps/admin-web/index.html',
            'apps/admin-web/tsconfig.json', 'apps/admin-web/tsconfig.app.json',
            'apps/admin-web/tsconfig.node.json', 'apps/admin-web/vite.config.ts',
            'apps/admin-web/src/main.tsx', 'apps/admin-web/src/api/client.ts',
            'apps/admin-web/src/styles/index.css', 'apps/admin-web/public/favicon.ico')
EXCLUDED = ('apps/backend/src/canary.py', 'apps/backend/.env', 'apps/unknown/canary.ts',
            'contracts/private.json', 'deploy/private/canary.conf', 'apps/admin-web/private/canary.ts',
            'apps/admin-web/.env.local', 'apps/admin-web/src/.env', 'apps/admin-web/src/secret.key',
            'apps/admin-web/src/private.dat', 'apps/admin-web/public/unknown/canary.dat',
            'apps/admin-web/src/secrets/canary.ts', 'apps/admin-web/src/models/canary.ts',
            'apps/admin-web/src/.runtime_state/canary.ts', 'apps/admin-web/src/node_modules/canary.ts',
            'apps/admin-web/src/dist/canary.ts', 'apps/admin-web/src/private.log',
            '.runtime_state/canary', 'unknown/canary', 'node_modules/canary')
BACKEND_REQUIRED = ('requirements-runtime.txt', 'start_gateway.py', 'start_knowledge_worker.py',
                    'src/gateway/app.py', 'config/providers.json', 'config/local-review.json',
                    'scripts/check_gateway_health.py', 'scripts/check_local_resources.py',
                    'scripts/prepare_admin_state.py', 'scripts/check_gateway_database.py', 'scripts/export_gateway_sql.py',
                    'scripts/check_age_graph.py', 'scripts/purge_request_history.py',
                    *(f'models/bert4ner-base-chinese-onnx/{name}' for name in
                      ('manifest.json', 'config.json', 'license-excerpt.json', 'model.onnx', 'tokenizer.json')))
BACKEND_EXCLUDED = ('.env.test', '.venv/canary', '.uv-cache/canary', 'tests/canary.py',
                    'reports/canary', '.runtime_state/canary', '.git/config',
                    'secrets/canary.key', 'unknown/canary', 'src/gateway/private.key',
                    'src/gateway/.env', 'src/secrets/canary.py', 'config/private.json',
                    'scripts/private.py', 'models/bert4ner-base-chinese/pytorch_model.bin',
                    'models/bert4ner-base-chinese-onnx/private.key',
                    'models/bert4ner-base-chinese-onnx/unknown.json')


def verify(label, required, excluded, ignore):
    with tempfile.TemporaryDirectory(prefix='gateway-context-') as temporary:
        base = Path(temporary)
        context, exported = base / 'context', base / 'exported'
        for filename in (*required, *excluded):
            target = context / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('SYNTHETIC_BUILD_CONTEXT_CANARY\n')
        dockerfile = context / 'Dockerfile'
        dockerfile.write_text('FROM scratch\nCOPY . /context/\n')
        shutil.copyfile(ignore,
                        dockerfile.with_name('Dockerfile.dockerignore'))
        subprocess.run(['docker', 'buildx', 'build', '--no-cache', '--progress=plain',
                        '-f', str(dockerfile), '--output', 'type=local,dest=' + str(exported),
                        str(context)], check=True, timeout=120)
        for filename in required:
            if not (exported / 'context' / filename).is_file():
                raise RuntimeError('Required input excluded: ' + filename)
        for filename in excluded:
            if (exported / 'context' / filename).exists():
                raise RuntimeError('Forbidden input admitted: ' + filename)
        actual = {str(f.relative_to(exported / 'context'))
                  for f in (exported / 'context').rglob('*') if f.is_file()}
        if actual != set(required):
            raise RuntimeError('Unexpected exported files: ' + repr(actual - set(required)))
        print(f'{label} Docker context passed: {len(required)} required inputs; {len(excluded)} exclusions.')


def main():
    verify('Frontend', REQUIRED, EXCLUDED, ROOT / 'apps/admin-web/Dockerfile.dockerignore')
    verify('Backend', BACKEND_REQUIRED, BACKEND_EXCLUDED, ROOT / 'apps/backend/.dockerignore')


if __name__ == '__main__':
    main()
