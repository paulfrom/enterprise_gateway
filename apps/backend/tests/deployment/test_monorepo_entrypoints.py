"""Deployment CLI failures must leave services intact and use explicit resources."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]


class RebuildEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='gateway-entrypoint-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copyfile(ROOT / 'rebuild_and_run.sh', self.root / 'rebuild_and_run.sh')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'calls.jsonl'
        self.environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                                ENTRYPOINT_CALLS=str(self.log))
        for name in ('GATEWAY_PUBLISHED_PORT', 'FRONTEND_HTTP_PORT'):
            self.environment.pop(name, None)
        for name, body in (
            ('docker', """import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['ENTRYPOINT_CALLS'], 'a') as output:
    output.write(json.dumps(['docker', *args]) + '\\n')
if 'config' in args and '--env-file' not in args: sys.exit(23)
if 'port' in args:
    port = os.environ.get('GATEWAY_PUBLISHED_PORT', '19080') if 'backend' in args else os.environ.get('FRONTEND_HTTP_PORT', '19180')
    print('127.0.0.1:' + port)
"""),
            ('curl', """import json, os, sys
with open(os.environ['ENTRYPOINT_CALLS'], 'a') as output:
    output.write(json.dumps(['curl', *sys.argv[1:]]) + '\\n')
"""),
            ('hostname', "print('127.0.0.1')\n"),
        ):
            executable = self.bin / name
            executable.write_text('#!/usr/bin/env python3\n' + body)
            executable.chmod(0o700)

    def run_entrypoint(self, *arguments):
        result = subprocess.run(['bash', str(self.root / 'rebuild_and_run.sh'), *arguments],
                                cwd='/tmp', env=self.environment, capture_output=True,
                                text=True, timeout=15)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls

    def test_missing_standard_configuration_changes_no_services(self):
        result, calls = self.run_entrypoint()
        self.assertEqual(result.returncode, 23)
        self.assertEqual(len(calls), 1)
        self.assertIn('config', calls[0])

    def test_existing_local_configuration_is_loaded_before_compose_validation(self):
        local = self.root / '.runtime_state/local/up.sh'
        local.parent.mkdir(parents=True)
        local.write_text('#!/usr/bin/env bash\nprintf \'["local", "%s"]\\n\' "$1" >> "$ENTRYPOINT_CALLS"\n')
        result, calls = self.run_entrypoint()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0], ['local', '--build'])
        self.assertFalse(any(call[0] == 'docker' for call in calls))
        self.assertTrue(any(call[-1].endswith('/login') for call in calls if call[0] == 'curl'))

    def test_explicit_configuration_overrides_local_and_uses_published_ports(self):
        local = self.root / '.runtime_state/local/up.sh'
        local.parent.mkdir(parents=True)
        local.write_text('exit 99\n')
        config = self.root / 'private.env'
        config.write_text('SYNTHETIC_CONFIGURATION=1\n')
        result, calls = self.run_entrypoint('--env-file', str(config))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--env-file', calls[0])
        self.assertIn(['curl', '--noproxy', '*', '--max-time', '30', '-fsS',
                       'http://127.0.0.1:19080/readyz'], calls)
        self.assertIn(['curl', '--noproxy', '*', '--max-time', '5', '-fsS',
                       'http://127.0.0.1:19180/login'], calls)
        self.assertFalse(any('down' in call for call in calls))

    def test_export_only_needs_no_runtime_secrets_and_starts_no_services(self):
        result, calls = self.run_entrypoint('--export-only', str(self.root / 'images.tar'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(call[1] == 'build' for call in calls), 2)
        self.assertEqual(calls[-1][1], 'save')
        self.assertFalse(any('compose' in call for call in calls))


if __name__ == '__main__':
    unittest.main()
