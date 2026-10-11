#!/usr/bin/env bash
# Update this development stack without stopping it before configuration checks.
# Defaults to 0.0.0.0 for external/LAN access. Supports --export to save local images.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EXPORT_ARCHIVE=""
DO_RUN=1
ENV_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      [[ $# -gt 1 && -f "$2" ]] || { echo '--env-file requires an existing private configuration file.' >&2; exit 2; }
      ENV_FILE="$(realpath "$2")"
      shift 2
      ;;
    --export)
      if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
        EXPORT_ARCHIVE="$2"
        shift 2
      else
        EXPORT_ARCHIVE="$ROOT_DIR/enterprise_gateway_images.tar"
        shift
      fi
      ;;
    --export-only)
      if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
        EXPORT_ARCHIVE="$2"
        shift 2
      else
        EXPORT_ARCHIVE="$ROOT_DIR/enterprise_gateway_images.tar"
        shift
      fi
      DO_RUN=0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

# Environment variables take precedence over Compose --env-file. Only supply
# shell defaults when no explicit file was selected, so its ports remain valid.
if [[ -z "$ENV_FILE" ]]; then
  export GATEWAY_BIND_ADDRESS="${GATEWAY_BIND_ADDRESS:-0.0.0.0}"
  export GATEWAY_PUBLISHED_PORT="${GATEWAY_PUBLISHED_PORT:-8080}"
  export FRONTEND_BIND_ADDRESS="${FRONTEND_BIND_ADDRESS:-0.0.0.0}"
  export FRONTEND_HTTP_PORT="${FRONTEND_HTTP_PORT:-80}"
fi

compose=(docker compose -f "$ROOT_DIR/deploy/compose.yaml")
if [[ -n "$ENV_FILE" ]]; then compose+=(--env-file "$ENV_FILE"); fi

LOCAL_RUN_SCRIPT="$ROOT_DIR/.runtime_state/local/up.sh"
USE_LOCAL=0
if [[ -f "$LOCAL_RUN_SCRIPT" && -z "$ENV_FILE" ]]; then USE_LOCAL=1; fi
# Local configuration is loaded by its own entry point. Standard deployment
# validates the explicit configuration before building or changing services.
if [[ "$DO_RUN" -eq 1 && "$USE_LOCAL" -eq 0 ]]; then "${compose[@]}" config --quiet; fi
if [[ -n "$EXPORT_ARCHIVE" || "$DO_RUN" -eq 0 || "$USE_LOCAL" -eq 0 ]]; then
  echo "==> 正在构建前端与后端本地镜像 ..."
  docker build -f "$ROOT_DIR/apps/backend/Dockerfile" -t enterprise-privacy-gateway:local "$ROOT_DIR/apps/backend"
  docker build -f "$ROOT_DIR/apps/admin-web/Dockerfile" -t enterprise-admin-web:local "$ROOT_DIR"
fi

if [[ -n "$EXPORT_ARCHIVE" ]]; then
  echo "==> 正在导出本地镜像至: $EXPORT_ARCHIVE ..."
  mkdir -p "$(dirname "$EXPORT_ARCHIVE")"
  docker save -o "$EXPORT_ARCHIVE" enterprise-admin-web:local enterprise-privacy-gateway:local
  echo "==> 镜像导出完成 ($EXPORT_ARCHIVE)。"
  if [[ "$DO_RUN" -eq 0 ]]; then
    exit 0
  fi
fi

if [[ "$USE_LOCAL" -eq 1 ]]; then
  if [[ -n "$EXPORT_ARCHIVE" ]]; then bash "$LOCAL_RUN_SCRIPT"; else bash "$LOCAL_RUN_SCRIPT" --build; fi
else
  "${compose[@]}" run --rm --no-deps backend python scripts/check_local_resources.py --role backend
  "${compose[@]}" run --rm --no-deps knowledge-worker python scripts/check_local_resources.py --role worker
  "${compose[@]}" up -d backend frontend knowledge-worker
  # Use actual published ports, including overrides from --env-file.
  BACKEND_ADDRESS="$("${compose[@]}" port backend 8080)"
  FRONTEND_ADDRESS="$("${compose[@]}" port frontend 80)"
  BACKEND_ADDRESS="${BACKEND_ADDRESS/0.0.0.0/127.0.0.1}"
  BACKEND_ADDRESS="${BACKEND_ADDRESS/\[::\]/127.0.0.1}"
  FRONTEND_ADDRESS="${FRONTEND_ADDRESS/0.0.0.0/127.0.0.1}"
  FRONTEND_ADDRESS="${FRONTEND_ADDRESS/\[::\]/127.0.0.1}"
fi
BACKEND_ADDRESS="${BACKEND_ADDRESS:-127.0.0.1:$GATEWAY_PUBLISHED_PORT}"
FRONTEND_ADDRESS="${FRONTEND_ADDRESS:-127.0.0.1:$FRONTEND_HTTP_PORT}"

for _ in $(seq 1 6); do
  if curl --noproxy '*' --max-time 30 -fsS "http://$BACKEND_ADDRESS/readyz" >/dev/null 2>&1 && curl --noproxy '*' --max-time 5 -fsS "http://$FRONTEND_ADDRESS/login" >/dev/null 2>&1; then
    PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")"
    echo "=================================================="
    echo "==> 网关与前端已就绪"
    echo "    - 管理端:             http://$FRONTEND_ADDRESS/login"
    echo "    - 网关API:            http://$BACKEND_ADDRESS"
    if [[ -z "$ENV_FILE" && "$FRONTEND_BIND_ADDRESS" == 0.0.0.0 && -n "$PRIMARY_IP" && "$PRIMARY_IP" != "127.0.0.1" ]]; then
      echo "    - 外部/局域网管理端:  http://${PRIMARY_IP}:$FRONTEND_HTTP_PORT/login"
      echo "    - 外部/局域网网关API: http://${PRIMARY_IP}:$GATEWAY_PUBLISHED_PORT"
    fi
    echo "常用命令提示："
    echo "    - 查看实时日志: docker compose -f deploy/compose.yaml logs -f backend frontend knowledge-worker"
    echo "    - 停止服务运行: docker compose -f deploy/compose.yaml stop"
    echo "=================================================="
    exit 0
  fi
  sleep 1
done

echo 'Backend readiness failed; inspect backend and worker logs.' >&2
exit 1
