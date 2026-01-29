FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for XDP/AF_XDP support
RUN apt-get update && apt-get install -y \
    gcc \
    libbpf-dev \
    libelf-dev \
    clang \
    llvm \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# XDP collector needs privileged access to the host network/NIC,
# so this image is intended to be run with:
#   --network=host --cap-add=ALL --privileged

EXPOSE 5010

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5010/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5010", "--workers", "2", "--timeout", "120", "app:app"]

