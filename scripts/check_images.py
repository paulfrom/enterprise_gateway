#!/usr/bin/env python3
"""Inspect the two built runtime images and verify source/model asset hashes."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def main():
    backend = ROOT / 'apps/backend'
    script = '''from pathlib import Path
import hashlib, json, os
root = Path('/app')
files = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in root.rglob('*') if p.is_file()}
assert os.getuid() == 65532
assert os.access(root / 'state/admin', os.W_OK)
from detection.ner_model import load_model_package
load_model_package(root / 'models/bert4ner-base-chinese-onnx')
print(json.dumps(files, sort_keys=True))
'''
    result = subprocess.run(['docker', 'run', '--rm', '--network', 'none',
                             '--entrypoint', 'python', 'enterprise-privacy-gateway:local',
                             '-c', script], check=True, stdout=subprocess.PIPE, text=True, timeout=120)
    files = json.loads(result.stdout)
    allowed = {}
    sources = [*backend.glob('src/**/*.py'), *backend.glob('models/bert4ner-base-chinese-onnx/*')]
    sources += [backend / name for name in ('requirements-runtime.txt', 'start_gateway.py',
                'start_knowledge_worker.py', 'config/providers.json', 'config/local-review.json',
                'scripts/check_gateway_health.py', 'scripts/check_local_resources.py',
                'scripts/prepare_admin_state.py', 'scripts/prepare_gateway_database.py', 'scripts/prepare_knowledge_database.py',
                'scripts/prepare_request_database.py', 'scripts/purge_request_history.py')]
    for source in sources:
        if source.is_file():
            allowed[source.relative_to(backend).as_posix()] = hashlib.sha256(source.read_bytes()).hexdigest()
    if files != allowed:
        raise RuntimeError('Backend image inputs differ from the reviewed source/model files')
    print('Backend image passed: exact source/model hashes, model validation, UID and writable admin directory.')
    name = 'gw-image-check-' + uuid4().hex[:12]
    try:
        subprocess.run(['docker', 'create', '--name', name, 'enterprise-admin-web:local'],
                       check=True, stdout=subprocess.DEVNULL, timeout=30)
        with tempfile.TemporaryDirectory(prefix='gateway-static-image-') as temporary:
            directory = Path(temporary)
            subprocess.run(['docker', 'cp', name + ':/usr/share/nginx/html/.', str(directory)],
                           check=True, timeout=30)
            actual = {p.relative_to(directory).as_posix(): p.read_bytes()
                      for p in directory.rglob('*') if p.is_file()}
            dist = ROOT / 'apps/admin-web/dist'
            expected = {p.relative_to(dist).as_posix(): p.read_bytes()
                        for p in dist.rglob('*') if p.is_file()}
            if not expected or actual != expected:
                raise RuntimeError('Frontend runtime assets differ from the verified production dist')
        subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'sh',
                        'enterprise-admin-web:local', '-ec',
                        'test ! -e /workspace; test ! -e /app; test ! -e /usr/local/bin/node; '
                        'test ! -e /usr/share/nginx/html/node_modules; '
                        'test ! -e /usr/share/nginx/html/src; test ! -e /usr/share/nginx/html/contracts'],
                       check=True, timeout=30)
        print('Frontend image passed: exact production dist and no application/build source tree.')
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)


if __name__ == '__main__':
    main()
