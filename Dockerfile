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
COPY start_gateway.py ./

# 3. 创建运行时状态目录并切换非 root 用户 (UID 65532)
RUN mkdir -p /app/.runtime_state && chown -R 65532:65532 /app
USER 65532:65532

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"

# 4. 默认启动独立脱敏网关 (BYOK 多供应商路由模式)
CMD ["python", "start_gateway.py", "--host", "0.0.0.0", "--port", "8080"]
