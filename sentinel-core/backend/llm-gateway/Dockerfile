FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203
LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL LLM gateway — grounded analyst copilot (advisory-only)"

# Build context is backend/ (like the sibling services): the image needs the
# shared _lib package next to the service dir, mirroring the repo layout.

RUN useradd --create-home --shell /bin/bash --uid 1000 appuser

WORKDIR /app

COPY llm-gateway/requirements.lock .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --require-hashes -r requirements.lock

COPY _lib/ _lib/
COPY llm-gateway/ llm-gateway/

USER appuser
# app.py bootstraps sys.path one level up, so _lib resolves from /app.
WORKDIR /app/llm-gateway

EXPOSE 5012

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5012/health', timeout=5).raise_for_status()"

CMD ["gunicorn", "--bind", "0.0.0.0:5012", "--workers", "2", "app:app"]
