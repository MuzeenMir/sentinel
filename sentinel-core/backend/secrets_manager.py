"""Unified secrets management for SENTINEL backend services.

Supports multiple backends (env vars, AWS Secrets Manager, HashiCorp Vault)
selected via the ``SECRETS_BACKEND`` environment variable.  Provides
thread-safe caching with configurable TTL and automatic fallback to
environment variables when an external backend is unreachable.

Usage::

    from secrets_manager import get_secrets_manager

    secrets = get_secrets_manager()
    db_password = secrets.get_secret("DB_PASSWORD")
"""

import json
import logging
import os
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


class _CacheEntry:
    __slots__ = ("value", "expires_at")

    def __init__(self, value: str, ttl: float):
        self.value = value
        self.expires_at = time.monotonic() + ttl


class SecretsManager:
    """Thread-safe secrets manager with pluggable backends and TTL cache."""

    _instance: Optional["SecretsManager"] = None
    _init_lock = threading.Lock()

    def __new__(cls, *_args, **_kwargs):
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(
        self,
        backend: Optional[str] = None,
        cache_ttl: int = 300,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        vault_mount: str = "secret",
        aws_region: Optional[str] = None,
    ):
        if getattr(self, "_initialized", False):
            return

        self._backend = (backend or os.environ.get("SECRETS_BACKEND", "env")).lower()
        self._cache_ttl = cache_ttl
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

        self._vault_addr = vault_addr or os.environ.get("VAULT_ADDR", "")
        self._vault_token = vault_token or os.environ.get("VAULT_TOKEN", "")
        self._vault_mount = vault_mount
        self._vault_client = None

        self._aws_region = aws_region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self._aws_client = None

        self._initialized = True
        logger.info("SecretsManager initialized: backend=%s cache_ttl=%ds", self._backend, cache_ttl)

    def get_secret(self, name: str) -> str:
        """Retrieve a secret by *name*, returning a cached value when valid."""
        with self._lock:
            entry = self._cache.get(name)
            if entry is not None and time.monotonic() < entry.expires_at:
                return entry.value

        value = self._fetch(name)

        with self._lock:
            self._cache[name] = _CacheEntry(value, self._cache_ttl)

        return value

    def invalidate(self, name: Optional[str] = None) -> None:
        """Drop one or all cached entries so the next read hits the backend."""
        with self._lock:
            if name is not None:
                self._cache.pop(name, None)
            else:
                self._cache.clear()

    def _fetch(self, name: str) -> str:
        if self._backend == "aws":
            try:
                return self._fetch_aws(name)
            except Exception:
                logger.warning("AWS Secrets Manager unavailable for '%s'; falling back to env", name, exc_info=True)
                return self._fetch_env(name)

        if self._backend == "vault":
            try:
                return self._fetch_vault(name)
            except Exception:
                logger.warning("Vault unavailable for '%s'; falling back to env", name, exc_info=True)
                return self._fetch_env(name)

        return self._fetch_env(name)

    @staticmethod
    def _fetch_env(name: str) -> str:
        value = os.environ.get(name, "")
        if not value:
            logger.warning("Secret '%s' not found in environment", name)
        return value

    def _get_aws_client(self):
        if self._aws_client is None:
            import boto3  # noqa: delayed import — optional dependency
            self._aws_client = boto3.client("secretsmanager", region_name=self._aws_region)
        return self._aws_client

    def _fetch_aws(self, name: str) -> str:
        client = self._get_aws_client()
        response = client.get_secret_value(SecretId=name)
        raw = response["SecretString"]
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and len(parsed) == 1:
                return str(next(iter(parsed.values())))
            return raw
        except (json.JSONDecodeError, StopIteration):
            return raw

    def _get_vault_client(self):
        if self._vault_client is None:
            import hvac  # noqa: delayed import — optional dependency
            self._vault_client = hvac.Client(url=self._vault_addr, token=self._vault_token)
            if not self._vault_client.is_authenticated():
                self._vault_client = None
                raise RuntimeError("Vault authentication failed")
        return self._vault_client

    def _fetch_vault(self, name: str) -> str:
        client = self._get_vault_client()
        response = client.secrets.kv.v2.read_secret_version(
            path=name,
            mount_point=self._vault_mount,
        )
        data = response["data"]["data"]
        if isinstance(data, dict) and len(data) == 1:
            return str(next(iter(data.values())))
        return json.dumps(data)


def get_secrets_manager(**kwargs) -> SecretsManager:
    """Return the singleton :class:`SecretsManager` instance."""
    return SecretsManager(**kwargs)
