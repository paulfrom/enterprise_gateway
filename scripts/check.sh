#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
python3 scripts/check_structure.py
[[ -n "${GATEWAY_HISTORY_PG_CONFIG:-}" && -r "$GATEWAY_HISTORY_PG_CONFIG" ]] || {
  echo 'Set GATEWAY_HISTORY_PG_CONFIG to an explicit private PG 5433 test configuration.' >&2
  exit 1
}
export GATEWAY_TEST_PG_CONFIG="${GATEWAY_TEST_PG_CONFIG:-$GATEWAY_HISTORY_PG_CONFIG}"
export GATEWAY_DATABASE_DEPLOYMENT_CONFIG="${GATEWAY_DATABASE_DEPLOYMENT_CONFIG:-$GATEWAY_HISTORY_PG_CONFIG}"
bash apps/backend/scripts/check.sh
npm ci
npm audit --audit-level=high
for gate in check:api typecheck lint test build; do npm run "$gate"; done
python3 scripts/check_typecheck.py
if [[ "${GATEWAY_CHECK_BROWSER:-0}" == 1 ]]; then npm run test:e2e --workspace apps/admin-web; fi
if [[ "${GATEWAY_CHECK_DOCKER:-0}" == 1 ]]; then
  python3 scripts/check_docker_context.py
  docker build -f apps/backend/Dockerfile -t enterprise-privacy-gateway:local apps/backend
  docker build -f apps/admin-web/Dockerfile -t enterprise-admin-web:local .
  python3 scripts/check_images.py
  python3 scripts/check_proxy.py
  python3 scripts/run_nginx_e2e.py
fi
