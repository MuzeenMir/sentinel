# SENTINEL — OTel Pilot (Phase 0 slice 5)

One service (`api-gateway`) wired end-to-end with OpenTelemetry so the pattern
can be validated before Phase 1 lifts `observability.py` into
`backend/_lib/otel/` and rolls it across the consolidated services
(`console`, `controller`, `analyzer`, `collector`, `llm-gateway`).

## What's wired

| Piece | Location | Notes |
|---|---|---|
| SDK bootstrap | `backend/observability.py :: init_telemetry()` | Already existed pre-Phase 0. Lazy imports; no-op if SDK unavailable. |
| Call site | `backend/api-gateway/app.py` (after `configure_logging`) | Only service calling it in Phase 0. |
| Pip deps | `backend/api-gateway/requirements.txt` | `opentelemetry-{api,sdk}`, `exporter-otlp-proto-grpc`, `instrumentation-flask`. |
| Endpoint env | `docker-compose.yml :: api-gateway` | `OTEL_EXPORTER_OTLP_ENDPOINT` + `OTEL_SERVICE_NAME`. Unset = disabled. |
| Backend | `docker-compose.yml :: tempo` (profile `observability`) | Grafana Tempo 2.5, OTLP gRPC `:4317`, query `:3200`. Local filesystem storage. |
| Config | `observability/tempo/tempo.yaml` | Minimal single-binary. |

## Running the pilot locally

```bash
cd sentinel-core
cp .env.example .env   # if you don't have one yet
docker compose --profile observability up -d tempo
docker compose up -d postgres redis auth-service api-gateway
export OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4317
docker compose up -d --force-recreate api-gateway
curl -i http://localhost:8080/health
# Query Tempo:
curl -s 'http://localhost:3200/api/search?tags=service.name=api-gateway' | jq .
```

With the endpoint unset, `init_telemetry()` logs one INFO line
(`telemetry disabled`) and returns — the service runs unchanged.

## Acceptance

- `init_telemetry` is idempotent per-process (module-level globals).
- No-op fallback path exercised when `opentelemetry-*` wheels are absent
  (see `_NoOpTracer` / `_NoOpMeter` / `_NoOpSpan` in `observability.py`).
- FlaskInstrumentor attaches only when Flask app is passed.
- Spans exported via OTLP gRPC using `BatchSpanProcessor` (30s metric
  export interval, default batch for spans).
- Trace + span IDs appear in structured JSON log records via the existing
  `_JSONFormatter` (fields `trace_id`, `span_id`).

## Phase 1 plan (follow-up, not in this slice)

1. Lift `observability.py` → `backend/_lib/otel/__init__.py`. Deprecate
   the per-service copy pattern (`Dockerfile COPY observability.py`).
2. Propagate `init_telemetry()` to the other three services in the
   consolidation set (`controller`, `analyzer`, `collector`) plus
   `llm-gateway` — behind `USE_V2_OTEL=1` to let the canary tenant cut
   over without pulling the others.
3. Add Grafana datasource provisioning for Tempo at
   `observability/grafana/provisioning/datasources/tempo.yml` so traces
   are one click from existing Prometheus dashboards.
4. Replace filesystem storage with S3/MinIO backing via Helm values; see
   SDD-002 §observability.
5. Add `tempo` to Helm values for the `sentinel-internal` canary env.

## Why api-gateway first

- Only service on the request hot path — proves end-to-end trace
  propagation (HTTP in → proxy HTTP out to 9 downstream services).
- Already had `configure_logging` wired, so the code diff was tiny.
- Failure mode is contained: if OTel breaks, gateway's own request
  handling is unaffected (all OTel calls wrapped in try/except in
  `observability.py`).

## Risks (called out, not blocking)

- **Trace context propagation to downstream services.** FlaskInstrumentor
  auto-injects W3C `traceparent` on inbound requests but `requests`
  outbound calls inside the gateway's proxy handlers are NOT auto-
  instrumented yet. Downstream services won't show as children of the
  gateway span until Phase 1 adds `RequestsInstrumentor().instrument()`
  alongside `init_telemetry`. Acceptable for the pilot: single-service
  traces still validate OTLP wiring.
- **Tempo local storage.** Dev only — drops on volume prune. Phase 1
  Helm values move to S3.
- **No sampling config.** Default = always-on. Fine for a single service
  at dev traffic; Phase 1 sets `OTEL_TRACES_SAMPLER=parentbased_traceidratio`
  at 0.1 before rollout.
