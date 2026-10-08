FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# 1. 安装基础依赖
COPY requirements-runtime.txt ./
RUN pip install --no-cache-dir -r requirements-runtime.txt

# 2. 复制源码、配置、模型权重与启动入口
COPY src/ ./src/
COPY config/ ./config/
COPY models/ ./models/
COPY start_gateway.py start_knowledge_worker.py ./
COPY scripts/check_gateway_health.py scripts/prepare_knowledge_database.py scripts/prepare_request_database.py scripts/purge_request_history.py ./scripts/

# 3. 创建运行时状态目录并切换非 root 用户 (UID 65532)
RUN mkdir -p /app/state && chown -R 65532:65532 /app
USER 65532:65532

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python scripts/check_gateway_health.py

# 4. 默认启动独立脱敏网关 (BYOK 多供应商路由模式)
CMD ["python", "start_gateway.py", "--host", "0.0.0.0", "--port", "8080"]
