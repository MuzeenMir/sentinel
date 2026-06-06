# ADR-021 — EU data-residency posture for copilot inference

- **Status:** Proposed
- **Date:** 2026-06-04
- **Deciders:** SENTINEL backend CODEOWNERS
- **Relates to:** ADR-012 (LLM analyst copilot), Plan CLAUDE C5

## Context

The target persona is an **EU regulated mid-market SOC**. Such buyers audit *where*
inference runs and where prompt/response data is processed before purchase. The
Phase-2 copilot calls the **Anthropic API**; by default that is **not an
EU-resident inference path**. We need a way for a deployment to route inference
to an EU-resident or on-prem endpoint **without code changes**, and we need to be
honest about what is and is not guaranteed today.

## Decision

Introduce a **routing seam**, not a residency guarantee:

- `llm-gateway/residency.py` resolves an inference target from config:
  - `INFERENCE_PROVIDER` (`anthropic` | `self_hosted` | …),
  - `INFERENCE_REGION` (`default` | `us` | `eu` | `on_prem` | …),
  - `INFERENCE_BASE_URL` (explicit endpoint; kept out of source).
- `AnthropicProvider.build_client` passes `base_url` through to the SDK; an
  `InferenceProvider` Protocol lets a **self-hosted / on-prem** adapter drop in
  later as a config swap (no gateway code change).
- **Default is unchanged**: with nothing configured, inference uses the default
  Anthropic endpoint exactly as before.
- `/readyz` reports `inference_provider` / `inference_region` /
  `inference_default_endpoint` for honest operational visibility.

## Honest claim boundaries (do NOT over-claim)

- This is a **routing seam**. Setting a region or base_url only points the client
  at the configured endpoint. It does **not** by itself make inference
  "EU-resident."
- Real data residency is a **deployment + contractual property** of the endpoint
  that is configured (e.g. an EU-resident model host with a data-processing
  agreement). SENTINEL does **not** ship EU-resident inference today, and the
  marketing/UI must not claim it.
- No on-prem model is shipped. The self-hosted path is an **interface**, ready
  for a future on-prem model deployment; it is not a working on-prem model.

## Consequences

- Positive: an EU/on-prem deployment is a config change, not a fork.
- Positive: `/readyz` makes the active inference target auditable.
- Negative: until an EU-resident endpoint is actually configured and contracted,
  the residency requirement is **not** met — this ADR exists so that gap is
  explicit, not hidden.

## Follow-ups

- Configure + contract an EU-resident inference endpoint and validate the data-
  processing path before making any EU-residency claim to customers.
- Implement and test a concrete self-hosted provider when an on-prem model is
  selected.

## References

- `sentinel-core/backend/llm-gateway/residency.py`
- `sentinel-core/backend/llm-gateway/tests/test_residency.py`
- `.team/specs/2026-06-03-plan-CLAUDE-copilot-production-hardening.md` (C5)
