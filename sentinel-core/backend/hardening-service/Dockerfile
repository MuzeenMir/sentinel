FROM python:3.12-slim
LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL hardening service — CIS benchmark enforcement and eBPF runtime protection"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        iproute2 \
        iptables \
        libelf1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py ./
COPY integrations/ integrations/
COPY ebpf-lib/ ebpf_lib/

COPY hardening-service/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt gevent

COPY hardening-service/ hardening-service/

RUN mkdir -p /var/lib/sentinel/backups

WORKDIR /app/hardening-service

ENV PYTHONUNBUFFERED=1
EXPOSE 5011

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5011/health || exit 1

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5011", "-k", "gevent", "-w", "4", "--timeout", "120", "--access-logfile", "-"]
