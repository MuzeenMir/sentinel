# Code Review: `main` — SENTINEL

**Date:** 2026-04-18
**Reviewer:** Claude (/engineering:code-review)
**Focus:** Security · Performance · Correctness
**Scope:** Current `main` branch state at `C:\Projects\sentinel`, with extra weight on recently modified code (agent installer, Dockerfiles, compose, auth-service, api-gateway, enterprise_schema migration).

> Note on the working tree: the uncommitted changes to `sentinel-core/agent/install.sh`, the two Dockerfiles, and `docker-compose.yml` are pure CRLF/LF churn (`git diff --ignore-all-space --stat` shows 0 insertions/deletions in three of them; `install.sh` is exactly 171↔171 insertions/deletions). There is no functional change to review there; findings below are against current content on `main`.

## Summary

SENTINEL has the security-product bones in the right places — bcrypt password hashing, JWT with Redis blacklist, rate limiting, a circuit-breaker'd auth middleware, SCAP-style audit logging, per-tenant data model, DRL shadow-mode as default. But several **production defaults and RBAC wiring on the gateway would let a naive deployment be trivially compromised**, and the account-lockout logic in `auth-service/app.py` is ordered in a way that makes it effectively decorative against brute force. For a security platform these are show-stoppers before any real deployment.

## Critical Issues

| # | File | Line | Issue | Severity |
|---|---|---|---|---|
| 1 | `sentinel-core/backend/api-gateway/app.py` | 603-613, 760-770, 397-424 | **Broad authorization gaps on mutating endpoints.** `update_policy`, `delete_policy`, `admin_get_users`, `admin_update_user`, `acknowledge_alert`, `update_alert`, `resolve_alert`, `tenants`, `tenant_detail` all use `@require_auth` instead of a role check. Any authenticated user (including `viewer`) can delete firewall policies, update/ack alerts, or hit admin endpoints. The downstream auth-service re-checks some of them — but the gateway is the enforcement surface clients see, and several of these (alert ack/resolve, policy update) land straight at a backend that does no further RBAC. | 🔴 Critical |
| 2 | `sentinel-core/backend/auth-service/app.py` | 345-366 | **Account lockout is ordered after password verification.** `check_password` runs (and on failure returns 401) *before* `login_attempts_exceeded()`. That means `locked_until` only gates access if the attacker already entered the right password. The 5-attempt/15-minute lockout has no effect on actual brute-force attempts — only the 5/min Flask-Limiter + per-IP Redis counter slow things down, and neither is tied to the account. Move the status/lockout checks ahead of `check_password`. | 🔴 Critical |
| 3 | `sentinel-core/docker-compose.yml` | 9, 71, 73, 468 | **Insecure defaults baked into compose.** `POSTGRES_PASSWORD:-sentinel_password`, `JWT_SECRET_KEY:-change-this-in-production`, `ADMIN_PASSWORD:-ChangeMe!2026`, `GRAFANA_PASSWORD:-sentinel`. `auth-service/app.py` does correctly refuse to start on an empty `JWT_SECRET_KEY` (line 40-41), but compose *fills it in* with the placeholder string, so the refusal never fires. Any operator running `docker compose up -d` without editing `.env` gets a known-to-the-attacker JWT signing key plus a known admin password. | 🔴 Critical |
| 4 | `sentinel-core/agent/install.sh` | 3, 93-97 | **Agent binary downloaded over HTTP(S) with no signature/checksum verification, then run as root via systemd.** Usage advertises `curl -sSL … | bash -s --` and the binary is fetched with bare `curl -fsSL -o`. There is no TLS pinning, no cosign/GPG verification, no `sha256sum -c`, no URL-scheme enforcement on `--server` (an operator can pass `http://`). Compromise of the download server — or any MITM position — ships a root-level backdoor to every host running the installer. For a security product this is the most important gap to close. | 🔴 Critical |
| 5 | `sentinel-core/agent/install.sh` | 138 | `NoNewPrivileges=no` in the systemd unit **actively disables** the single most valuable runtime hardening flag, on the service designed to protect the host. If the agent needs privileges for eBPF, declare them explicitly with `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN …` + `AmbientCapabilities=…` and keep `NoNewPrivileges=yes`. | 🔴 Critical |
| 6 | `sentinel-core/backend/api-gateway/app.py` | 145; `docker-compose.yml` 525 | `INTERNAL_SERVICE_TOKEN` defaults to empty string in both compose and gateway. The gateway sends `Authorization: Bearer ` (trailing space, no token) when aggregating stats. Either downstream services are publicly readable with a missing/empty token, or every stats aggregation silently 401s — both are bad outcomes and neither is intentional. | 🔴 Critical |
| 7 | `sentinel-core/docker-compose.yml` | many (10-11, 67, 94, 104, 129, 206, 229, 262, 275, 291, 337, 375, 406, 450, 466) | **Every backend microservice is bound to `0.0.0.0` on the host.** Only the admin console and API gateway should be host-exposed. As shipped, auth-service (5000), alert-service (5002), ai-engine (5003), policy-orchestrator (5004), drl-engine (5005), xai-service (5006), compliance-engine (5007), hids-agent (5010), hardening-service (5011), plus Postgres (5433), Redis (6379), Kafka (9092), Zookeeper (2181), Elasticsearch (9200/9300), Kibana (5601) are all reachable from anything that can route to the host. Most of these do not enforce auth at all (see #6). Either drop the `ports:` stanzas on internal services or bind them to `127.0.0.1:`. | 🔴 Critical |

## Suggestions

| # | File | Line | Suggestion | Category |
|---|---|---|---|---|
| 1 | `sentinel-core/backend/api-gateway/app.py` | 22 | `CORS(app)` with no config → wildcard CORS on every route including `/api/v1/auth/*` proxies. Pass `resources={r"/api/*": {"origins": os.environ["CORS_ORIGINS"].split(",")}}` and fail fast if `CORS_ORIGINS` is unset. | Security |
| 2 | `sentinel-core/backend/api-gateway/app.py` | 253-272 | `auth_proxy` does not forward the `Authorization` header, so authenticated auth endpoints called through the gateway catch-all (`/api/v1/auth/profile`, `logout`, `change-password`) return 401. Forward the header unconditionally, and add `timeout=5` to every downstream call here — the catch-all currently has none, so a slow auth-service hangs gateway workers. | Correctness + Perf |
| 3 | `sentinel-core/backend/api-gateway/app.py` | 260, 302-304 | `params=request.args` forwards every query param, including `token=` (which the gateway accepts on `_extract_token` for SSE). Tokens then land in downstream access logs. Strip `token` before forwarding, or route SSE auth via a short-lived nonce instead of passing the JWT as a query param. | Security |
| 4 | `sentinel-core/backend/api-gateway/app.py` | 114-127 | `get_request_stats()` does 300 separate `SCAN` iterations per `/health` call. That's healthcheck-amplified load on Redis. Switch to a single sorted-set bucketed by minute, or cache the aggregate for ≥5 s like `_fetch_downstream_stats` does. | Performance |
| 5 | `sentinel-core/backend/api-gateway/app.py` | 489-531 | `_sse_pubsub_stream` opens a fresh `redis.from_url` connection per SSE client and relies on `finally:` for cleanup. Under gevent + abrupt client disconnects, cleanup can race. Add a gevent-friendly close on `GeneratorExit` and cap concurrent SSE connections, or back the pubsub with a pooled client. | Perf / Resource leak |
| 6 | `sentinel-core/backend/auth-service/app.py` | 345-347 | On unknown username the code returns fast without hashing; on known username it runs bcrypt. Timing difference = username enumeration oracle. Always run a dummy `bcrypt.checkpw` against a fixed hash when `user is None`. | Security |
| 7 | `sentinel-core/backend/auth-service/app.py` | 34 | `CORS_ORIGINS` defaults to `*`. Credentialed CORS with wildcard is browser-blocked, but any service that lives behind the same origin can still drive unauthenticated POSTs. Require explicit origins in production. | Security |
| 8 | `sentinel-core/backend/auth-service/app.py` | 759-796, 816 | `_bootstrap_initial_admin()` runs on module import in every gunicorn worker. Four workers race on the "no admin yet?" check → second-place workers get a unique-constraint violation, which is swallowed as a warning. Wrap with a Postgres advisory lock, or gate on a one-shot init container (the `db-migrate` service is the natural place). | Correctness |
| 9 | `sentinel-core/backend/auth-service/app.py` | 703-717 | `deactivate_tenant` has no guard against the `default` tenant. Deactivating it orphans every migrated resource. Refuse when `tenant.name == 'default'` or when it's the only active tenant. | Correctness |
| 10 | `sentinel-core/backend/auth-service/app.py` | 610-635 | `update_user` treats any `data['role']` with no value validation — `getattr(UserRole, data['role'].upper())` raises `AttributeError` on bad input, which then hits the bare `except Exception` and returns a 500 (plus admins can silently promote other users to ADMIN without secondary confirmation). Validate `role`/`status` against the enum and return 400 on bad input; audit-log the privilege change at `AuditCategory.CRITICAL`. | Correctness |
| 11 | `sentinel-core/agent/install.sh` | 101-113 | Agent token is interpolated straight into a JSON heredoc. A token containing `"` or `\` produces invalid JSON or lets a hostile control-plane inject extra config fields. Use `python3 -c 'import json,sys,os; …'` or `jq -n --arg token "$SENTINEL_AGENT_TOKEN" …` to build the config safely. | Correctness |
| 12 | `sentinel-core/docker-compose.yml` | 176, 187, 396, 425 | `privileged: true` is appropriate for `xdp-collector` and `hardening-service`, marginal for `data-collector` (raw socket → `CAP_NET_RAW` is enough) and `hids-agent` (eBPF perf events → `CAP_BPF`+`CAP_PERFMON`). Tightening these reduces the blast radius if one container is compromised. | Security |
| 13 | `sentinel-core/docker-compose.yml` | 413 | `hardening-service` mounts `/etc:/host/etc:rw`. Necessary for the service's job, but combine with read-only root fs, `no-new-privileges:true`, and a drop-all capability policy so the only way to reach `/host/etc` is via the service's deliberate code paths. | Security |
| 14 | `sentinel-core/docker-compose.yml` | 108-110 | Kafka `PLAINTEXT_HOST` listener on `0.0.0.0:9092` is exposed to the host and any adjacent network. Either remove the host listener entirely in production compose, or move to SASL/mTLS. | Security |
| 15 | `sentinel-core/docker-compose.yml` | 490, 508, 527 | Flink checkpoints under `file:///tmp/flink-checkpoints/…` — ephemeral inside the container, lost on restart, not backed by a named volume. Add volumes and keep `/tmp` for scratch only. | Performance / Correctness |
| 16 | `sentinel-core/backend/api-gateway/Dockerfile` · `auth-service/Dockerfile` | 1 | `FROM python:3.12-slim` is unpinned. Pin by digest (`python:3.12-slim@sha256:…`) for reproducibility and supply-chain integrity. | Security |
| 17 | `sentinel-core/backend/migrations/versions/20260313_001_enterprise_schema.py` | 87-100 | Table name list is a hardcoded whitelist (`alerts`, `threats`, `firewall_policies`, …), so the f-string is safe today, but the loop does `UPDATE {table} SET tenant_id = …` unconditionally even when `tenant_id` was already present. That's a full-table rewrite every time the migration runs — fine on an empty DB, painful on a backfilled one. Skip the UPDATE if the column existed before this migration added it. | Performance |
| 18 | `sentinel-core/backend/migrations/versions/20260313_001_enterprise_schema.py` | 298-306 | `downgrade()` drops tables but leaves `update_updated_at_column()` behind. Minor, but downgrade-idempotency matters for drift tests. | Correctness |
| 19 | `sentinel-core/backend/auth_middleware.py` | 67 | `_extract_token` falls back to `request.args.get("token")`. Tokens-in-URL leak through proxy logs, browser history, and Referer headers. Prefer a short-lived, one-use SSE nonce over passing the JWT in the URL. | Security |
| 20 | `sentinel-core/backend/auth-service/app.py` | 44-45 | JWT access token TTL defaults to **24 hours** with a 30-day refresh. For a product pitched as enterprise-grade, 15 minutes access / 1-7 day refresh with rotation on use is the safer baseline. | Security |

## What Looks Good

- Password hashing uses `bcrypt` with `gensalt()` rather than a fixed work factor, and enforces a plausible strength policy.
- JWT blacklist is written to both Redis (fast path) and Postgres (durable), with a consistent `token_in_blocklist_loader`.
- `auth_middleware.py` wraps the verify call in `circuit_breaker` + `retry_with_backoff` — the exact right shape for preventing auth-service blips from cascading across every service.
- Per-service SQLAlchemy engine options set `pool_pre_ping=True` and `pool_recycle=3600`, which is the correct defense against long-lived idle connections dropping.
- The enterprise migration (`20260313_001`) is genuinely idempotent and drift-tolerant: it introspects `has_table`/`has_column` rather than assuming state, uses `ON CONFLICT DO NOTHING` for the seed tenant, and defines its trigger function before any trigger depends on it. The commit narrative in `DB-MIGRATION-DRIFT-AUDIT.md` is a good artifact.
- DRL engine defaults to `DRL_SHADOW_MODE=true`. Shipping enforcement off by default is the right posture for a policy-autonomy system.
- MFA path uses `pyotp.TOTP.verify(…, valid_window=1)` plus SHA-256'd backup codes that are consumed on use — not rolled by hand.
- SOC2 audit log has a `verify_integrity` endpoint, implying tamper-evident chaining. Good.

## Verdict

**Request Changes — do not deploy `main` to any reachable environment as-is.**

The four highest-signal fixes before anything else:

1. Move lockout/status checks before `check_password` in `auth-service/app.py:login`.
2. Close the RBAC gap in `api-gateway/app.py` — every mutating endpoint wants an explicit `@require_role(...)`.
3. Make `docker-compose.yml` refuse to start when `JWT_SECRET_KEY` / `ADMIN_PASSWORD` / `POSTGRES_PASSWORD` are unset (drop the `:-default` fallbacks, or fail the entrypoint), and stop exposing internal services on `0.0.0.0`.
4. Add signature/checksum verification to `agent/install.sh` and restore `NoNewPrivileges=yes` on the systemd unit.

Everything else in the Suggestions table is worth addressing but none are merge-blockers on their own. Happy to do a follow-up diff review once a branch is up.
