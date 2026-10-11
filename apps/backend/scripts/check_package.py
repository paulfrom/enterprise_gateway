#!/usr/bin/env python3
"""Verify the frozen Docker dependencies and the wheel's actual source contents."""
from pathlib import Path
import subprocess
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def requirements(text):
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


def main():
    exported = subprocess.check_output([
        'uv', 'export', '--frozen', '--offline', '--no-dev', '--no-hashes',
        '--no-emit-project', '--format', 'requirements-txt', '--cache-dir', '.uv-cache',
    ], cwd=ROOT, text=True)
    if requirements(exported) != requirements((ROOT / 'requirements-runtime.txt').read_text()):
        raise RuntimeError('Docker runtime requirements differ from the frozen uv lock')
    config = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    packages = config['tool']['hatch']['build']['targets']['wheel']['packages']
    with tempfile.TemporaryDirectory(prefix='gateway-wheel-') as temporary:
        subprocess.run(['uv', 'build', '--offline', '--no-sources', '--wheel',
                        '--cache-dir', '.uv-cache', '--out-dir', temporary],
                       cwd=ROOT, check=True, timeout=120)
        wheels = list(Path(temporary).glob('*.whl'))
        if len(wheels) != 1:
            raise RuntimeError('Expected one backend wheel')
        expected = {}
        for package in packages:
            for source in (ROOT / package).rglob('*'):
                if source.is_file() and '__pycache__' not in source.parts and source.suffix != '.pyc':
                    expected[source.relative_to(ROOT / 'src').as_posix()] = source.read_bytes()
        with zipfile.ZipFile(wheels[0]) as wheel:
            actual = {name for name in wheel.namelist() if '.dist-info/' not in name}
            if actual != set(expected):
                raise RuntimeError('Wheel/source paths differ: ' + repr(actual ^ set(expected)))
            for name, data in expected.items():
                if wheel.read(name) != data:
                    raise RuntimeError('Wheel/source bytes differ: ' + name)
            if any('/web/' in name or name.endswith(('.tsx', '.js', '.html')) for name in actual):
                raise RuntimeError('Frontend assets must not enter the backend wheel')
        print(f'Backend package passed: {len(expected)} source files and frozen Docker requirements.')


if __name__ == '__main__':
    main()
