FROM python:3.12-slim

LABEL maintainer="SENTINEL Team"
LABEL description="SENTINEL unified host security agent"

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sentinel-agent

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/lib/sentinel /var/log/sentinel

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "agent.py"]
