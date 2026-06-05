# ADR-016 — API gateway FastAPI runtime

- **Status:** Accepted
- **Date:** 2026-06-03
- **Accepted:** 2026-06-04
- **Deciders:** SENTINEL backend CODEOWNERS
- **Supersedes:** None
- **Superseded by:** None

## Context

The API gateway was implemented as a Flask service and started in the container
with `gunicorn app:app`. Phase 3 K1 required sunset of Flask services, starting
with an incremental API gateway port that kept the existing Flask parity tests
green while a new FastAPI ASGI surface grew alongside it.

The current gateway has a larger surface than the initial K1.1 prompt described:
health, auth proxy, threats, alerts, config, stats, SSE, policy, compliance,
XAI, AI, DRL, hardening, HIDS, admin users, traffic, tenants, integrations, and
SOC2 audit endpoints. A runtime flip without covering these routes would drop
active gateway behavior.

## Decision

Move the API gateway container runtime from Flask/Gunicorn to FastAPI/Uvicorn:

- `api-gateway/asgi_app.py` exposes `asgi = FastAPI(...)` and route parity for
  the current gateway surface.
- `api-gateway/gateway_core.py` owns framework-agnostic configuration, Redis,
  request-statistics, SSE, audit, and downstream-statistics helpers.
- `api-gateway/Dockerfile` starts `uvicorn asgi_app:asgi` on port 8080.
- The former Flask parity suite remains as a migrated ASGI regression oracle;
  the Flask `app.py` source and gateway Flask dependencies are removed.
- ASGI middleware records request counts and response times.
- SlowAPI stores rate-limit state in the configured Redis instance so limits
  apply across workers.
- A verified SSE `?token=` is reconstructed as a downstream Bearer token.
- Audit-read endpoints require the admin role and scope reads to the verified
  tenant.

## Consequences

- Positive: production container startup exercises the sole FastAPI/Uvicorn
  gateway runtime.
- Positive: gateway source and runtime dependencies no longer include Flask,
  Flask-CORS, Flask-Limiter, Gunicorn, or Flask OpenTelemetry instrumentation.
- Positive: the full migrated oracle and ASGI parity suites protect the route
  table without retaining a second implementation.
- Positive: the shared audit logger lazily integrates with Flask request context,
  allowing Flask-free services to import it while preserving existing callers.
- Negative: SSE still wraps the synchronous Redis pub/sub generator. Replacing
  it with a native asynchronous Redis stream remains deferred.

## Alternatives considered

- **Big-bang Flask deletion.** Rejected because the real route surface is broad,
  and deleting the Flask module before full ASGI parity would hide regressions.
- **Keep Flask as the production runtime until all helpers are extracted.**
  Rejected because the ASGI surface now covers the active route table and the
  runtime flip can be verified independently.
- **Run FastAPI behind Gunicorn UvicornWorker.** Deferred. Direct Uvicorn keeps
  the container command simpler for this first runtime flip.

## References

- `.team/prompts/2026-06-03-kai-api-gateway-fastapi-port.md`
- `.team/prompts/2026-06-04-kai-K1.1e-gateway-flask-removal.md`
- `sentinel-core/backend/api-gateway/asgi_app.py`
- `sentinel-core/backend/api-gateway/gateway_core.py`
- `sentinel-core/backend/api-gateway/Dockerfile`
- `sentinel-core/backend/tests/test_api_gateway_asgi.py`
- `sentinel-core/backend/tests/test_api_gateway.py`
