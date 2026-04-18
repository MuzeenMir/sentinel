FROM python:3.12-slim
LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL authentication and authorization service"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        pkg-config \
        libxml2-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sentinel && useradd -r -g sentinel -d /app -s /sbin/nologin sentinel

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py audit_logger.py ./
COPY integrations/ integrations/

COPY auth-service/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY auth-service/ auth-service/
COPY migrations/ migrations/

RUN chown -R sentinel:sentinel /app
USER sentinel

WORKDIR /app/auth-service

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5000", "-k", "gevent", "-w", "4", "--timeout", "120", "--access-logfile", "-"]
