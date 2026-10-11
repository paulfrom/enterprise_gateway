#!/usr/bin/env python3
"""Run the React browser flow through the built Nginx image and an isolated local backend."""
from pathlib import Path
import os
import subprocess
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def main():
    if not os.environ.get('GATEWAY_HISTORY_PG_CONFIG'):
        raise RuntimeError('GATEWAY_HISTORY_PG_CONFIG must identify the private local test configuration')
    name = 'gw-browser-nginx-' + uuid4().hex[:12]
    try:
        with tempfile.TemporaryDirectory(prefix='gateway-nginx-browser-') as temporary:
            config = Path(temporary) / 'admin.conf'
            backend_port = int(os.environ.get('GATEWAY_E2E_BACKEND_PORT', '18877'))
            frontend_port = int(os.environ.get('GATEWAY_NGINX_E2E_PORT', '14175'))
            if not all(1 <= port <= 65535 for port in (backend_port, frontend_port)):
                raise ValueError('Invalid browser test port')
            config.write_text((ROOT / 'deploy/nginx/admin.conf').read_text().replace(
                'http://backend:8080', f'http://127.0.0.1:{backend_port}').replace(
                'listen 80;', f'listen 127.0.0.1:{frontend_port};'))
            environment = dict(os.environ, GATEWAY_BROWSER_BASE_URL=f'http://127.0.0.1:{frontend_port}',
                               GATEWAY_E2E_BACKEND_PORT=str(backend_port), GATEWAY_E2E_REUSE_BACKEND='0')
            subprocess.run(['docker', 'run', '-d', '--name', name, '--network', 'host',
                            '-v', str(config) + ':/etc/nginx/conf.d/default.conf:ro',
                            'enterprise-admin-web:local'], check=True, stdout=subprocess.DEVNULL, timeout=60)
            result = subprocess.run(['npm', 'run', 'test:e2e', '--workspace', 'apps/admin-web'],
                                    cwd=ROOT, env=environment, timeout=480)
            return result.returncode
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)


if __name__ == '__main__':
    raise SystemExit(main())
