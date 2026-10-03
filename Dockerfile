# Local review only. A production image must use an approved digest and scanned lock.
FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements-runtime.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements-runtime.txt
COPY src/ ./src/
ENV PYTHONPATH=/app/src
USER 65532:65532
CMD ["python", "-m", "uvicorn", "enterprise_gateway.app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]

