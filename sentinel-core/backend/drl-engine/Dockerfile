FROM python:3.11-slim
LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL DRL engine — deep reinforcement learning policy optimization"

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sentinel && useradd -r -g sentinel -d /app -s /sbin/nologin sentinel

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py ./
COPY integrations/ integrations/

COPY drl-engine/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt gevent

COPY drl-engine/ drl-engine/

RUN mkdir -p /models/drl && chown -R sentinel:sentinel /app /models
USER sentinel

WORKDIR /app/drl-engine

ENV PYTHONUNBUFFERED=1
EXPOSE 5005

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5005/health || exit 1

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5005", "-k", "gevent", "-w", "2", "--timeout", "300", "--access-logfile", "-"]
