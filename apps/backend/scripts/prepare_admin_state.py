"""Explicit one-time initialization of the controlled single-admin state.

Creates <state-dir>/admin with the fixed admin account and initial password
from the implementation plan. Existing admin state is never overwritten:
re-running refuses, and service restarts never re-initialize. The password is
never printed or persisted; only a random salt and the scrypt derived value
reach disk.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from gateway.admin_auth import initialize_admin_state
from gateway.admin_storage import AdminStateAlreadyExists, AdminStateStore

INITIAL_ADMIN_PASSWORD = "admin@123"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True,
                        help="Persistent gateway state directory; admin state goes to <dir>/admin")
    args = parser.parse_args(argv)
    try:
        initialize_admin_state(AdminStateStore(args.state_dir / "admin"), INITIAL_ADMIN_PASSWORD)
    except AdminStateAlreadyExists:
        print("Admin state already exists; initialization refused.", file=sys.stderr)
        return 2
    except Exception:
        # Never echo storage or environment detail that could embed operator paths/content.
        print("Admin state initialization refused: storage or environment unavailable.",
              file=sys.stderr)
        return 2
    print("Admin state initialized for the fixed admin account.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
