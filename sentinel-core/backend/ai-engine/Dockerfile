FROM python:3.12-slim
LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL AI engine — ML-based threat detection and classification"

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sentinel && useradd -r -g sentinel -d /app -s /sbin/nologin sentinel

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py ./
COPY integrations/ integrations/

COPY ai-engine/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

COPY ai-engine/ ai-engine/

RUN mkdir -p /models && chown -R sentinel:sentinel /app /models
USER sentinel

WORKDIR /app/ai-engine

ENV PYTHONUNBUFFERED=1
EXPOSE 5003

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5003/health || exit 1

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5003", "-k", "gevent", "-w", "2", "--timeout", "300", "--access-logfile", "-"]
