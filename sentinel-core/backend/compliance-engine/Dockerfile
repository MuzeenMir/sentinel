FROM python:3.12-slim
LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL compliance engine — CIS/NIST/PCI-DSS benchmark assessment"

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sentinel && useradd -r -g sentinel -d /app -s /sbin/nologin sentinel

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py ./
COPY integrations/ integrations/

COPY compliance-engine/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt gevent

COPY compliance-engine/ compliance-engine/

RUN chown -R sentinel:sentinel /app
USER sentinel

WORKDIR /app/compliance-engine

ENV PYTHONUNBUFFERED=1
EXPOSE 5007

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5007/health || exit 1

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5007", "-k", "gevent", "-w", "4", "--timeout", "120", "--access-logfile", "-"]
