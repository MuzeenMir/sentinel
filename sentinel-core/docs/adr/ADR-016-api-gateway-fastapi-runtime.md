# ADR-016 — API gateway FastAPI runtime

- **Status:** Proposed
- **Date:** 2026-06-03
- **Deciders:** SENTINEL backend CODEOWNERS
- **Supersedes:** None
- **Superseded by:** None

## Context

The API gateway was implemented as a Flask service and started in the container
with `gunicorn app:app`. Phase 3 K1 requires sunset of Flask services, starting
with an incremental API gateway port that keeps existing Flask parity tests
green while a new FastAPI ASGI surface grows alongside it.

The current gateway has a larger surface than the initial K1.1 prompt described:
health, auth proxy, threats, alerts, config, stats, SSE, policy, compliance,
XAI, AI, DRL, hardening, HIDS, admin users, traffic, tenants, integrations, and
SOC2 audit endpoints. A runtime flip without covering these routes would drop
active gateway behavior.

## Decision

Move the API gateway container runtime from Flask/Gunicorn to FastAPI/Uvicorn:

- `api-gateway/asgi_app.py` exposes `asgi = FastAPI(...)` and route parity for
  the current gateway surface.
- `api-gateway/Dockerfile` starts `uvicorn asgi_app:asgi` on port 8080.
- Existing Flask parity tests remain in place while the compatibility module is
  still present.
- New ASGI parity tests cover the FastAPI gateway surface and the container
  runtime command.

This ADR does not claim Flask helper retirement is complete. `asgi_app.py` still
imports selected helpers from the existing Flask `app.py` while the migration is
being de-risked. Full Flask dependency removal requires a later extraction or
rewrite of shared config, SSE, stats, audit, and compatibility helpers.

## Consequences

- Positive: production container startup now exercises the FastAPI gateway path.
- Positive: the route table is covered by ASGI tests before Flask is removed.
- Positive: the old Flask tests remain available as a regression oracle during
  the transition.
- Negative: the gateway still installs Flask dependencies until helper
  extraction is complete.
- Negative: importing `asgi_app.py` still imports `app.py`, so this is a runtime
  flip, not a complete source-level Flask deletion.

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
- `sentinel-core/backend/api-gateway/asgi_app.py`
- `sentinel-core/backend/api-gateway/Dockerfile`
- `sentinel-core/backend/tests/test_api_gateway_asgi.py`
- `sentinel-core/backend/tests/test_api_gateway.py`
