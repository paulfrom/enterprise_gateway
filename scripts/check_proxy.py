#!/usr/bin/env python3
"""Exercise Nginx error status/body isolation using only a disposable synthetic upstream."""
from pathlib import Path
import json
import socket
import subprocess
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def docker(*args):
    return subprocess.run(['docker', *args], check=True, stdout=subprocess.DEVNULL, timeout=60)


def fetch(base, path, data=None):
    with tempfile.TemporaryDirectory(prefix='gateway-proxy-response-') as temporary:
        output = Path(temporary) / 'response'
        command = ['curl', '--silent', '--show-error', '--max-time', '5',
                   '--output', str(output), '--write-out', '%{http_code} %{content_type}']
        if data is not None:
            command += ['--header', 'Expect: 100-continue', '--data-binary', '@-']
        result = subprocess.run([*command, base + path], input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=8)
        if result.returncode:
            raise ConnectionError('Proxy test connection failed')
        status, _, media = result.stdout.decode().partition(' ')
        return int(status), media, output.read_bytes()


def check(base, path, status, code, data=None):
    actual, media, body = fetch(base, path, data)
    assert actual == status, (path, actual, status)
    assert 'application/json' in media, (path, media)
    assert json.loads(body)['error']['code'] == code, (path, body)


def main():
    token = uuid4().hex[:12]
    network, upstream, frontend = [f'gw-proxy-{kind}-{token}' for kind in ('net', 'upstream', 'frontend')]
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    try:
        with tempfile.TemporaryDirectory(prefix='gateway-proxy-') as temp:
            directory = Path(temp)
            (directory / 'admin.conf').write_text((ROOT / 'deploy/nginx/admin.conf').read_text()
                .replace('proxy_read_timeout 300s', 'proxy_read_timeout 1s')
                .replace('proxy_read_timeout 120s', 'proxy_read_timeout 1s'))
            (directory / 'stub.py').write_text('''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, time, threading
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/admin/close':
            self.send_response(200); self.end_headers(); self.wfile.write(b'{}');
            threading.Thread(target=self.server.shutdown, daemon=True).start(); return
        if 'timeout' in self.path: time.sleep(3)
        body = json.dumps({'error': {'code': 'SYNTHETIC_BACKEND_ERROR'}, 'host': self.headers['Host']}).encode()
        self.send_response(502 if 'backend-error' in self.path else 200)
        self.send_header('Content-Type','application/json'); self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass
        if self.path.endswith('/shutdown'): threading.Thread(target=self.server.shutdown).start()
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        while length:
            chunk = self.rfile.read(min(length, 65536))
            if not chunk: break
            length -= len(chunk)
        self.do_GET()
    def log_message(self, *args): pass
server = ThreadingHTTPServer(('0.0.0.0',8080), Handler)
server.serve_forever(); server.server_close(); time.sleep(300)
''')
            docker('network', 'create', network)
            docker('run', '-d', '--name', upstream, '--network', network, '--network-alias', 'backend',
                   '-v', str(directory / 'stub.py') + ':/tmp/stub.py:ro',
                   'enterprise-privacy-gateway:local', 'python', '/tmp/stub.py')
            docker('run', '-d', '--name', frontend, '--network', network, '-p', f'127.0.0.1:{port}:80',
                   '-v', str(directory / 'admin.conf') + ':/etc/nginx/conf.d/default.conf:ro',
                   'enterprise-admin-web:local')
            deadline = time.monotonic() + 20
            while True:
                try:
                    if fetch(base, '/login')[0] == 200: break
                except ConnectionError: pass
                if time.monotonic() > deadline: raise RuntimeError('Nginx test entry did not become ready')
                time.sleep(.2)
            for path in ('/api/admin/session', '/v1/chat/completions', '/v1/messages'):
                status, _, body = fetch(base, path)
                assert status == 200
                assert json.loads(body)['host'] == f'127.0.0.1:{port}'
                check(base, path, 413, 'REQUEST_TOO_LARGE', b'x' * (1024 * 1024 + 1))
                check(base, path + '?backend-error=1', 502, 'SYNTHETIC_BACKEND_ERROR')
                check(base, path + '?timeout=1', 504, 'GATEWAY_TIMEOUT')
            file_path = '/api/admin/documents/redact'
            status, _, body = fetch(base, file_path + '?format=txt', b'x' * (2 * 1024 * 1024))
            assert status == 200
            assert json.loads(body)['host'] == f'127.0.0.1:{port}'
            check(base, file_path, 413, 'REQUEST_TOO_LARGE', b'x' * (10 * 1024 * 1024 + 1))
            check(base, file_path + '?backend-error=1', 502, 'SYNTHETIC_BACKEND_ERROR', b'x')
            check(base, file_path + '?timeout=1', 504, 'GATEWAY_TIMEOUT', b'x')
            assert fetch(base, '/admin/documents')[0] == 200
            for path in ('/api', '/api/requests', '/v1/unknown', '/history', '/healthz', '/readyz',
                         '/assets/missing.js', '/missing.js', '/unknown'):
                check(base, path, 404, 'NOT_FOUND')
            fetch(base, '/api/admin/shutdown')
            time.sleep(.5)
            for path in ('/api/admin/session', '/v1/chat/completions', '/v1/messages', file_path):
                check(base, path, 502, 'BAD_GATEWAY')
            print('Nginx passed: Host port, file upload limits/page, 413/502/504 JSON, backend errors and missing routes.')
    finally:
        for container in (frontend, upstream):
            subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


if __name__ == '__main__':
    main()
