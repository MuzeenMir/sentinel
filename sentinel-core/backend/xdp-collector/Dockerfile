FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libbpf-dev \
    libelf-dev \
    clang \
    llvm \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the ebpf-lib shared library
COPY ../ebpf-lib /app/ebpf_lib

COPY . /app

# XDP collector needs privileged access: --cap-add=CAP_BPF --cap-add=CAP_NET_ADMIN
# or --privileged with --network=host

EXPOSE 5012

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5012/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5012", "--workers", "2", "--timeout", "120", "app:app"]
