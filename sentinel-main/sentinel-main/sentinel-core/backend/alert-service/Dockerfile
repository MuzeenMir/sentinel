FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Set ownership
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 5002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5002/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5002", "--workers", "4", "--worker-class", "gevent", "--timeout", "120", "--keep-alive", "5", "--log-level", "info", "app:app"]