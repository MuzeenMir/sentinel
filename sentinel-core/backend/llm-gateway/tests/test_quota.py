"""C5 — per-tenant inference quota (request count + token budget).

Prevents one tenant from exhausting copilot capacity / running up cost. Buckets
are per-tenant and isolated; exceeding a limit returns a deny with Retry-After.
"""

from quota import TenantQuota


def test_per_tenant_request_limit(fake_redis):
    q = TenantQuota(fake_redis, max_requests=2, window=60)
    assert q.check_request("tenant-a").allowed is True
    assert q.check_request("tenant-a").allowed is True
    denied = q.check_request("tenant-a")
    assert denied.allowed is False
    assert denied.retry_after == 60


def test_request_buckets_are_isolated_per_tenant(fake_redis):
    q = TenantQuota(fake_redis, max_requests=1, window=60)
    assert q.check_request("tenant-a").allowed is True
    assert q.check_request("tenant-a").allowed is False  # a exhausted
    assert q.check_request("tenant-b").allowed is True  # b independent


def test_token_budget_enforced(fake_redis):
    q = TenantQuota(fake_redis, max_tokens=100, window=60)
    assert q.consume_tokens("tenant-a", 60).allowed is True
    over = q.consume_tokens("tenant-a", 60)  # 120 > 100
    assert over.allowed is False
    assert over.retry_after == 60


def test_token_budget_isolated_per_tenant(fake_redis):
    q = TenantQuota(fake_redis, max_tokens=100, window=60)
    assert q.consume_tokens("tenant-a", 100).allowed is True
    assert q.consume_tokens("tenant-a", 1).allowed is False
    assert q.consume_tokens("tenant-b", 100).allowed is True


def test_rejected_consume_rolls_back_reservation(fake_redis):
    q = TenantQuota(fake_redis, max_tokens=100, window=60)
    assert q.consume_tokens("tenant-a", 60).allowed is True
    assert q.consume_tokens("tenant-a", 60).allowed is False  # 120 > 100, rolled back
    assert q.consume_tokens("tenant-a", 40).allowed is True  # 60 + 40 fits


def test_consume_does_not_extend_running_window(fake_redis):
    # Regression: TTL must be set once at window creation. Re-setting it on
    # every consume slides the window forward, so a busy tenant's budget
    # would never reset.
    q = TenantQuota(fake_redis, max_tokens=100, window=60)
    q.consume_tokens("tenant-a", 10)
    q.consume_tokens("tenant-a", 10)
    q.consume_tokens("tenant-a", 10)
    tok_key = q._tok_key("tenant-a")
    assert [c for c in fake_redis.expire_calls if c[0] == tok_key] == [(tok_key, 60)]
