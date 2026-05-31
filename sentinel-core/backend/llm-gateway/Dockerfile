FROM python:3.12-slim

# Create non-root user
RUN useradd --create-home --shell /bin/bash --uid 1000 appuser

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Switch to non-root user
USER appuser

EXPOSE 5012

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5012/health')"

CMD ["gunicorn", "--bind", "0.0.0.0:5012", "--workers", "2", "app:app"]
