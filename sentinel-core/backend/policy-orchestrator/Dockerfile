# Build with context: ./backend (docker-compose) so firewall-adapters is available.
FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc curl && rm -rf /var/lib/apt/lists/*

COPY policy-orchestrator/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY firewall-adapters /app/firewall-adapters
RUN pip install --no-cache-dir -e /app/firewall-adapters

COPY policy-orchestrator /app
WORKDIR /app

EXPOSE 5004

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5004/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5004", "--workers", "2", "app:app"]
