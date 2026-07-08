"""The analyst copilot must be part of the composed stack.

llm-gateway shipped in v1.7.x but was never added to docker-compose.yml, so
the composed product had no analyst. These assertions pin the service and the
env contract it needs to be functional AND offline-capable:

* the service exists, builds from the llm-gateway Dockerfile;
* it gets the service token (tool auth) and the proposal signing key;
* it reads the detector feed as the runtime app role (sentinel_app — the
  20260703_001 migration grants SELECT on node_alerts);
* inference is provider-switchable via env with NO hard requirement on an
  Anthropic key — `INFERENCE_PROVIDER=local` + a host-side Ollama must be a
  pure .env change (the offline-node thesis).
"""

import json
import os

import yaml

_COMPOSE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "docker-compose.yml")
)


def _services():
    with open(_COMPOSE) as fh:
        return yaml.safe_load(fh)["services"]


def _service():
    return _services()["llm-gateway"]


def _env(service):
    return dict(e.split("=", 1) for e in service["environment"])


def test_llm_gateway_is_composed_with_required_env():
    svc = _service()
    assert svc["build"]["dockerfile"] == "llm-gateway/Dockerfile"
    env = _env(svc)
    assert "INTERNAL_SERVICE_TOKEN" in env
    assert "COPILOT_PROPOSAL_SIGNING_KEY" in env
    assert env["REDIS_URL"].startswith("redis://")
    # detector feed read as the runtime app role, not the owner
    assert env["DATABASE_URL"].startswith("postgresql://sentinel_app:")


def test_llm_gateway_inference_is_env_switchable_and_cloud_optional():
    env = _env(_service())
    assert "INFERENCE_PROVIDER" in env
    assert "LOCAL_LLM_BASE_URL" in env
    assert "LOCAL_LLM_MODEL" in env
    # the Anthropic key must be optional — offline node runs without it
    assert ":?" not in env.get("ANTHROPIC_API_KEY", "")


def test_llm_gateway_can_reach_a_host_side_ollama():
    # LOCAL_LLM_BASE_URL defaults to the host gateway; the extra_hosts entry
    # is what makes host.docker.internal resolvable on Linux/WSL2 engines.
    svc = _service()
    assert "host-gateway" in " ".join(svc.get("extra_hosts", []))


def test_llm_gateway_has_default_tenant_for_audit_rls():
    # The copilot audit trail writes audit_log as sentinel_app, which is
    # RLS-gated on app.tenant_id. Requests arriving without X-Tenant-Id must
    # fall back to the node's single "default" tenant (id 1) or every copilot
    # call dies at the audit hook with an RLS violation.
    env = _env(_service())
    assert env.get("DEFAULT_TENANT_ID") == "${DEFAULT_TENANT_ID:-1}"


def test_llm_gateway_image_ships_shared_audit_modules():
    # audit.py lazily imports the backend-root audit_logger (which pulls in
    # audit_merkle); if the image doesn't ship them, every copilot call 500s
    # at the audit hook instead of completing.
    dockerfile = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "Dockerfile")
    )
    with open(dockerfile) as fh:
        copy_lines = " ".join(
            line for line in fh.read().splitlines() if line.startswith("COPY")
        )
    assert "audit_logger.py" in copy_lines
    assert "audit_merkle.py" in copy_lines


def test_triage_worker_is_composed_reaper_style():
    # The auto-triage worker is the spine link alert -> analyst. It reuses the
    # llm-gateway image with a command override (node-collector/reaper pattern)
    # so slow local inference can never stall the HTTP copilot or the detector.
    svc = _services()["triage-worker"]
    assert svc["build"]["dockerfile"] == "llm-gateway/Dockerfile"
    assert svc["command"] == ["python", "triage_worker.py"]
    env = _env(svc)
    # Reads node_alerts and writes node_alert_triage as the runtime app role
    # (20260707_001 grants SELECT/INSERT/UPDATE on the triage table).
    assert env["DATABASE_URL"].startswith("postgresql://sentinel_app:")
    # Same provider seam as the gateway: offline is a pure .env change.
    assert "INFERENCE_PROVIDER" in env
    assert "LOCAL_LLM_BASE_URL" in env
    assert ":?" not in env.get("ANTHROPIC_API_KEY", "")
    # Proposal drafts must be signable + tools authenticated.
    assert "COPILOT_PROPOSAL_SIGNING_KEY" in env
    assert "INTERNAL_SERVICE_TOKEN" in env
    # Audit writes are RLS-gated; the worker needs the default tenant too.
    assert env.get("DEFAULT_TENANT_ID") == "${DEFAULT_TENANT_ID:-1}"
    assert svc["depends_on"]["db-migrate"]["condition"] == (
        "service_completed_successfully"
    )
    # Host-side Ollama must be reachable on Linux/WSL2 engines.
    assert "host-gateway" in " ".join(svc.get("extra_hosts", []))
    # No HTTP surface — liveness is heartbeat-file freshness, reaper-style.
    assert "triage-heartbeat" in " ".join(svc["healthcheck"]["test"])


def test_llm_gateway_worker_timeout_covers_local_inference():
    # gunicorn's default 30s worker timeout kills CPU-bound local inference
    # mid-request (model load alone can take ~20s); the CMD must carry an
    # explicit budget that covers a full grounded copilot exchange.
    dockerfile = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "Dockerfile")
    )
    with open(dockerfile) as fh:
        cmd = next(line for line in fh.read().splitlines() if line.startswith("CMD"))
    args = json.loads(cmd[len("CMD ") :])
    assert "--timeout" in args
    assert int(args[args.index("--timeout") + 1]) >= 180
