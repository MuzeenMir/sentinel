FROM python:3.12-slim
LABEL maintainer="DRAGON_SCALE Team"
LABEL description="DRAGON_SCALE policy orchestrator — firewall rule management and enforcement"

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r dragon-scale && useradd -r -g dragon-scale -d /app -s /sbin/nologin dragon-scale

WORKDIR /app

COPY auth_middleware.py observability.py metrics.py resilience.py tenant_middleware.py ./
COPY integrations/ integrations/

COPY policy-orchestrator/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt gevent

COPY policy-orchestrator/ policy-orchestrator/

RUN chown -R dragon-scale:dragon-scale /app
USER dragon-scale

WORKDIR /app/policy-orchestrator

ENV PYTHONUNBUFFERED=1
EXPOSE 5004

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5004/health || exit 1

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5004", "-k", "gevent", "-w", "4", "--timeout", "120", "--access-logfile", "-"]
