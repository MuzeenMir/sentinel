FROM python:3.12-slim
LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL data collector — ingests network telemetry and host events"

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py ./
COPY integrations/ integrations/

COPY data-collector/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt gunicorn gevent

COPY data-collector/ data-collector/

WORKDIR /app/data-collector

ENV PYTHONUNBUFFERED=1
EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5001/health || exit 1

CMD ["gunicorn", "collector:app", "-b", "0.0.0.0:5001", "-k", "gevent", "-w", "4", "--timeout", "120", "--access-logfile", "-"]
