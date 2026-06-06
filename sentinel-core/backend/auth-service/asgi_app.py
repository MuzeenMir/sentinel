"""FastAPI application for the auth-service migration."""

from __future__ import annotations

from datetime import datetime

from fastapi import FastAPI


asgi = FastAPI(title="SENTINEL Auth Service")


@asgi.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@asgi.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready"}
