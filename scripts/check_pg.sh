#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/apps/backend"
PG_SERVICE_CONFIG="${GATEWAY_TEST_PG_CONFIG:-${GATEWAY_HISTORY_PG_CONFIG:-$BACKEND_DIR/.env.test}}"
[[ -r "$PG_SERVICE_CONFIG" ]] || {
  echo 'Existing shared PostgreSQL service configuration required.' >&2
  exit 1
}
export GATEWAY_TEST_PG_CONFIG="$PG_SERVICE_CONFIG"
export GATEWAY_HISTORY_PG_CONFIG="$PG_SERVICE_CONFIG"
export PYTHONPATH="$BACKEND_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
cd "$BACKEND_DIR"
.venv/bin/python scripts/check_gateway_database.py --config "$PG_SERVICE_CONFIG"
timeout --kill-after=10 "${GATEWAY_TEST_TIMEOUT_SECONDS:-900}" .venv/bin/python -m unittest -v \
  tests.deployment.test_database \
  tests.knowledge.test_storage \
  tests.knowledge.test_governance \
  tests.knowledge.test_remediation \
  tests.knowledge.test_worker_database_gate \
  tests.knowledge.test_worker_lifecycle \
  tests.knowledge.test_standalone_worker \
  tests.knowledge.test_age_graph \
  tests.knowledge.test_governed_graph_query \
  tests.knowledge.test_graph_outbox_scope \
  tests.request_history.test_storage \
  tests.request_history.test_local_e2e \
  tests.gateway.test_admin_knowledge_api \
  tests.integration.test_admin_governance \
  tests.integration.test_admin_governance_faults \
  tests.integration.test_admin_console \
  tests.integration.test_workbuddy_synthetic_roundtrip
