#!/usr/bin/env bash
set -euo pipefail
BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BACKEND_DIR"
uv sync --frozen --offline --group dev --no-editable --reinstall-package enterprise-privacy-gateway --cache-dir .uv-cache
uv run --frozen --offline --no-editable --group dev --cache-dir .uv-cache python scripts/export_admin_openapi.py --check
uv run --frozen --offline --no-editable --group dev --cache-dir .uv-cache python scripts/check_package.py
# Fail on timeout rather than reporting incomplete discovery as success.
timeout --kill-after=10 "${GATEWAY_TEST_TIMEOUT_SECONDS:-1800}" uv run --frozen --offline --no-editable --group dev --cache-dir .uv-cache python -m unittest discover -s tests -t . -v
