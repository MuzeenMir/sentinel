FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libbpf-dev \
    libelf-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ../ebpf-lib /app/ebpf_lib
COPY . /app

# Hardening service needs write access to host /etc for remediations
# and privileged for eBPF LSM enforcement:
#   -v /etc:/host/etc:rw -v /proc:/host/proc:ro --privileged

EXPOSE 5011

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5011/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5011", "--workers", "2", "--timeout", "120", "app:app"]
