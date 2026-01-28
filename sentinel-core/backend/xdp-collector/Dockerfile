FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# XDP collector needs privileged access to the host network/NIC,
# so this image is intended to be run with:
#   --network=host --cap-add=ALL --privileged

EXPOSE 5010

CMD ["python", "-m", "app"]

