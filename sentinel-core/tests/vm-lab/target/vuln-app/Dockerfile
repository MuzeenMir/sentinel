FROM python:3.10-slim

LABEL maintainer="sentinel-lab"
LABEL description="Intentionally vulnerable web app for SSS lab testing"

WORKDIR /app

# No additional dependencies needed — stdlib only
COPY app.py .

EXPOSE 8888

# Run as non-root (the app itself is vulnerable, not the container)
RUN useradd -r -s /bin/false vulnapp
USER vulnapp

CMD ["python", "app.py"]
