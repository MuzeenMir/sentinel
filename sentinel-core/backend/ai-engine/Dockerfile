FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203
LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL AI engine — ML-based threat detection and classification"

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sentinel && useradd -r -g sentinel -d /app -s /sbin/nologin sentinel

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py ./
COPY integrations/ integrations/
COPY _lib/ _lib/

COPY ai-engine/requirements.lock .
# torch installed separately from the PyTorch CPU index (excluded from the lock
# via --no-emit-package torch); everything else is hash-pinned from requirements.lock.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir --require-hashes -r requirements.lock

COPY ai-engine/ ai-engine/

RUN mkdir -p /models && chown -R sentinel:sentinel /app /models
USER sentinel

WORKDIR /app/ai-engine

ENV PYTHONUNBUFFERED=1
EXPOSE 5003

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5003/health || exit 1

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5003", "-k", "gevent", "-w", "2", "--timeout", "300", "--access-logfile", "-"]
