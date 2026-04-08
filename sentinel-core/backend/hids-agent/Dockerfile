FROM python:3.12-slim
LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL HIDS agent — eBPF-powered host intrusion detection"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        iproute2 \
        libelf1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py ./
COPY integrations/ integrations/
COPY ebpf-lib/ ebpf_lib/

COPY hids-agent/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt gevent

COPY hids-agent/ hids-agent/

WORKDIR /app/hids-agent

ENV PYTHONUNBUFFERED=1
EXPOSE 5010

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5010/health || exit 1

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5010", "-k", "gevent", "-w", "4", "--timeout", "120", "--access-logfile", "-"]
