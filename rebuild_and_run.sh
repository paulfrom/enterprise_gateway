#!/usr/bin/env bash
# 重新根据源码构建企业隐私网关 Docker 镜像并在本地启动（对外发布端口 8080）
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="enterprise-privacy-gateway:local"

# 默认绑定到 0.0.0.0，使局域网及外部客户端均可访问
export GATEWAY_BIND_ADDRESS="${GATEWAY_BIND_ADDRESS:-0.0.0.0}"
export GATEWAY_PUBLISHED_PORT="${GATEWAY_PUBLISHED_PORT:-8080}"

echo "=================================================="
echo "1. 正在根据当前源码重新构建 Docker 镜像: ${IMAGE_NAME} ..."
echo "=================================================="
docker build -t "${IMAGE_NAME}" "${ROOT_DIR}/apps/backend"

echo ""
echo "=================================================="
echo "2. 正在启动网关容器（对外绑定: ${GATEWAY_BIND_ADDRESS}:${GATEWAY_PUBLISHED_PORT}）..."
echo "=================================================="

LOCAL_RUN_SCRIPT="${ROOT_DIR}/.runtime_state/local/up.sh"

if [ -f "${LOCAL_RUN_SCRIPT}" ]; then
  bash "${LOCAL_RUN_SCRIPT}"
else
  docker compose -f "${ROOT_DIR}/deploy/compose.yaml" down --remove-orphans || true
  docker compose -f "${ROOT_DIR}/deploy/compose.yaml" up -d gateway
fi

echo ""
echo "=================================================="
echo "3. 等待网关健康检查就绪 ..."
echo "=================================================="

HEALTH_URL="http://127.0.0.1:${GATEWAY_PUBLISHED_PORT}"
HEALTH_OK=0

for i in $(seq 1 30); do
  if curl -sf "${HEALTH_URL}/healthz" >/dev/null 2>&1; then
    HEALTH_OK=1
    break
  fi
  sleep 1
done

PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")"

if [ "${HEALTH_OK}" -eq 1 ]; then
  echo "==> 网关已就绪！服务已对外发布："
  echo "    - 本机地址:   http://127.0.0.1:${GATEWAY_PUBLISHED_PORT}"
  if [ "${PRIMARY_IP}" != "127.0.0.1" ]; then
    echo "    - 局域网地址: http://${PRIMARY_IP}:${GATEWAY_PUBLISHED_PORT}"
  fi
  if curl -sf -o /dev/null "http://127.0.0.1:${GATEWAY_PUBLISHED_PORT}/login"; then
    echo "    - 管理员登录: http://${PRIMARY_IP}:${GATEWAY_PUBLISHED_PORT}/login"
    echo "      (管理员状态初始化见 apps/backend/scripts/prepare_admin_state.py)"
  fi
else
  echo "==> 网关启动耗时较长，请检查容器运行状态。"
fi

echo ""
echo "=================================================="
echo "常用命令提示："
echo "  - 查看实时日志: docker logs -f enterprise-gateway-local"
echo "  - 停止网关运行: docker stop enterprise-gateway-local"
echo "=================================================="
