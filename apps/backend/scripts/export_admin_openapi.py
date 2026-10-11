#!/usr/bin/env python3
"""Export the FastAPI admin console route definitions to OpenAPI JSON.

Produces a deterministic, reproducible OpenAPI 3.x contract containing only
the actual registered `/api/admin/*` routes and their referenced schemas.
Does not perform external I/O, does not read real database content, and does
not require production secrets.

Usage:
    uv run --frozen --offline --group dev python scripts/export_admin_openapi.py --output ../../contracts/admin.openapi.json
    uv run --frozen --offline --group dev python scripts/export_admin_openapi.py --check --output ../../contracts/admin.openapi.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
from typing import Any

# Ensure backend/src is on sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
SRC_DIR = BACKEND_DIR / "src"
REPO_ROOT = SCRIPT_DIR.parents[2]  # enterprise_gateway root

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fastapi.openapi.utils import get_openapi
from gateway.admin_auth import AdminAuthService
from gateway.admin_storage import AdminStateStore
from gateway.app import create_app

OPENAPI_TITLE = "Enterprise Privacy Gateway Admin API"
OPENAPI_VERSION = "1.0.0"
OPENAPI_DESCRIPTION = "Enterprise Privacy Gateway Admin Console API contract."
ADMIN_PATH_PREFIX = "/api/admin/"


class _ExportHistoryStore:
    """Zero-I/O placeholder history store to enable route registration."""
    pass


def build_export_app():
    """Construct FastAPI app with real admin routes mounted without side effects."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = AdminStateStore(tmpdir)
        admin_service = AdminAuthService(store, scope="admin")
        app = create_app(
            admin_service=admin_service,
            history_store=_ExportHistoryStore(),
            knowledge_governance=None,
            audit_reader=None,
            audit_builder=None,
        )
        # Cleanly shut down executors so no background threads linger
        for name in ("admin_knowledge_executor", "admin_audit_executor"):
            executor = getattr(app.state, name, None)
            if executor is not None:
                executor.shutdown(wait=False, cancel_futures=True)
        return app


def generate_admin_openapi() -> dict[str, Any]:
    """Generate deterministic OpenAPI dictionary for all /api/admin/* routes."""
    app = build_export_app()
    admin_routes = [
        route for route in app.routes
        if getattr(route, "path", "").startswith(ADMIN_PATH_PREFIX)
    ]

    schema = get_openapi(
        title=OPENAPI_TITLE,
        version=OPENAPI_VERSION,
        description=OPENAPI_DESCRIPTION,
        routes=admin_routes,
    )

    # Sort operation parameters for absolute determinism
    for path_item in schema.get("paths", {}).values():
        if isinstance(path_item, dict):
            for op in path_item.values():
                if isinstance(op, dict) and "parameters" in op:
                    op["parameters"].sort(
                        key=lambda p: (0 if p.get("in") == "path" else 1, p.get("name", ""))
                    )

    return schema


def serialize_openapi(schema: dict[str, Any]) -> str:
    """Serialize OpenAPI dictionary to deterministic JSON with trailing newline."""
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export or check admin OpenAPI schema from registered routes."
    )
    default_output = REPO_ROOT / "contracts" / "admin.openapi.json"
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=default_output,
        help=f"Target path for OpenAPI JSON (default: {default_output})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check target file against generated schema without overwriting (exits non-zero on drift)",
    )

    args = parser.parse_args(argv)
    target_path = Path(args.output).resolve()

    schema = generate_admin_openapi()
    content = serialize_openapi(schema)

    if args.check:
        if not target_path.is_file():
            sys.stderr.write(
                f"[DRIFT] Admin OpenAPI contract file missing: {target_path}\n"
            )
            return 1

        existing = target_path.read_text(encoding="utf-8")
        if existing != content:
            sys.stderr.write(
                f"[DRIFT] Admin OpenAPI contract drift detected at {target_path}\n"
            )
            return 1

        sys.stdout.write(
            f"[OK] Admin OpenAPI contract is up-to-date: {target_path}\n"
        )
        return 0

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(content, encoding="utf-8")
    sys.stdout.write(
        f"[EXPORTED] Admin OpenAPI contract written to {target_path}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
