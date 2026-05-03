FROM python:3.12-slim

LABEL maintainer="DRAGON_SCALE Team"
LABEL description="DRAGON_SCALE unified host security agent"

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/dragon-scale-agent

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/lib/dragon-scale /var/log/dragon-scale

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "agent.py"]
