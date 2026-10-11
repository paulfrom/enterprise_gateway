#!/usr/bin/env python3
"""Inject reachable TypeScript errors in disposable copies and require both gates to refuse them."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='gateway-types-') as temporary:
        root = Path(temporary)
        frontend = root / 'apps/admin-web'
        frontend.mkdir(parents=True)
        (root / 'node_modules').symlink_to(ROOT / 'node_modules', target_is_directory=True)
        for name in ('package.json', 'package-lock.json'):
            shutil.copyfile(ROOT / name, root / name)
        for name in ('package.json', 'index.html', 'tsconfig.json', 'tsconfig.app.json',
                     'tsconfig.node.json', 'vite.config.ts', 'playwright.config.ts'):
            shutil.copyfile(ROOT / 'apps/admin-web' / name, frontend / name)
        for directory in ('src', 'e2e'):
            for source in (ROOT / 'apps/admin-web' / directory).rglob('*'):
                if source.is_file() and source.suffix in ('.ts', '.tsx', '.css'):
                    target = frontend / source.relative_to(ROOT / 'apps/admin-web')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
        for label, target, content in (
            ('app', frontend / 'src/__typecheck_canary.ts', 'export const typecheckCanary: string = 42;\n'),
            ('node', frontend / 'vite.config.ts', '\nexport const typecheckCanary: string = 42;\n'),
        ):
            previous = target.read_text() if target.exists() else None
            target.write_text((previous or '') + content)
            for gate in ('typecheck', 'build'):
                result = subprocess.run(['npm', 'run', gate], cwd=root, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, timeout=90)
                diagnostic = target.name + '('
                if result.returncode == 0 or diagnostic not in result.stdout or 'TS2322' not in result.stdout:
                    raise RuntimeError(f'{gate} did not reject the reachable {label} type error: {result.stdout}')
                print(f'{gate} refused {label} canary (TS2322).')
            if previous is None: target.unlink()
            else: target.write_text(previous)


if __name__ == '__main__':
    main()
