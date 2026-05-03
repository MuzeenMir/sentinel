FROM python:3.12-slim
LABEL maintainer="DRAGON_SCALE Team"
LABEL description="DRAGON_SCALE XAI service — explainable AI for threat decision transparency"

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r dragon-scale && useradd -r -g dragon-scale -d /app -s /sbin/nologin dragon-scale

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py ./
COPY integrations/ integrations/

COPY xai-service/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt gevent

COPY xai-service/ xai-service/

RUN chown -R dragon-scale:dragon-scale /app
USER dragon-scale

WORKDIR /app/xai-service

ENV PYTHONUNBUFFERED=1
EXPOSE 5006

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5006/health || exit 1

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5006", "-k", "gevent", "-w", "2", "--timeout", "300", "--access-logfile", "-"]
