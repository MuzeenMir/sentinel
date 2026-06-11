"""C5 — per-tenant inference quota (request count + token budget).

One tenant must not be able to exhaust copilot capacity or run up unbounded
cost for everyone else. Each tenant gets an isolated fixed-window budget for
both request count and total tokens, backed by Redis counters keyed by tenant.
Exceeding either limit returns a deny with a ``retry_after`` so the caller can
surface HTTP 429 + ``Retry-After``. Buckets are per-tenant: tenant A hitting a
limit never affects tenant B.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

DEFAULT_MAX_REQUESTS = 60
DEFAULT_MAX_TOKENS = 200_000
DEFAULT_WINDOW_SECONDS = 60


@dataclass
class QuotaResult:
    allowed: bool
    retry_after: int = 0
    reason: str = ""


class TenantQuota:
    def __init__(
        self,
        redis_client: Any,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        window: int = DEFAULT_WINDOW_SECONDS,
    ):
        self.redis = redis_client
        self.max_requests = max_requests
        self.max_tokens = max_tokens
        self.window = window

    def _req_key(self, tenant_id: str) -> str:
        return f"copilot:quota:req:{tenant_id}"

    def _tok_key(self, tenant_id: str) -> str:
        return f"copilot:quota:tok:{tenant_id}"

    def check_request(self, tenant_id: str) -> QuotaResult:
        """Count one request against the tenant's window budget."""
        key = self._req_key(tenant_id)
        count = self.redis.incr(key)
        if count == 1:
            self.redis.expire(key, self.window)
        if count > self.max_requests:
            return QuotaResult(False, self.window, "request quota exceeded")
        return QuotaResult(True)

    def consume_tokens(self, tenant_id: str, tokens: int) -> QuotaResult:
        """Reserve ``tokens`` against the tenant's window budget.

        INCRBY-then-check so concurrent callers cannot both slip under the
        limit (a rejected call rolls its reservation back and consumes no
        budget). The TTL is set only when the key is created — consuming more
        tokens never extends an already-running window.
        """
        key = self._tok_key(tenant_id)
        total = self.redis.incrby(key, tokens)
        if total == tokens:
            self.redis.expire(key, self.window)
        if total > self.max_tokens:
            self.redis.decrby(key, tokens)
            return QuotaResult(False, self.window, "token budget exceeded")
        return QuotaResult(True)


def make_tenant_quota(redis_client: Any) -> TenantQuota:
    """Build a TenantQuota from env-configured limits (safe defaults)."""
    return TenantQuota(
        redis_client,
        max_requests=int(
            os.environ.get("COPILOT_TENANT_MAX_REQUESTS", DEFAULT_MAX_REQUESTS)
        ),
        max_tokens=int(os.environ.get("COPILOT_TENANT_MAX_TOKENS", DEFAULT_MAX_TOKENS)),
        window=int(
            os.environ.get("COPILOT_TENANT_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS)
        ),
    )
