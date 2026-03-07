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

# HIDS agent needs: --privileged or --cap-add=CAP_BPF --cap-add=CAP_PERFMON
# Mount host filesystem read-only:
#   -v /etc:/host/etc:ro -v /var/log:/host/var/log:ro -v /proc:/host/proc:ro

EXPOSE 5010

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5010/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5010", "--workers", "2", "--timeout", "120", "app:app"]
