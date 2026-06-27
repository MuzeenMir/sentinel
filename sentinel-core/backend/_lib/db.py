"""Shared PostgreSQL connection helper for node-path services."""
from __future__ import annotations

import os

import psycopg2


def connect(dsn: str | None = None):
    dsn = dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL environment variable is required")
    return psycopg2.connect(dsn)
