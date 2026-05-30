from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
BACKEND = REPO / "sentinel-core" / "backend"
E2E_SMOKE = REPO / ".github" / "workflows" / "e2e-smoke.yml"
SECURITY = REPO / ".github" / "workflows" / "security.yml"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_ai_engine_image_installs_shared_auth_middleware_dependencies():
    requirements = _read(BACKEND / "ai-engine" / "requirements.txt")

    assert "requests" in requirements


def test_policy_orchestrator_image_copies_audit_logger_shared_module():
    dockerfile = _read(BACKEND / "policy-orchestrator" / "Dockerfile")

    assert "audit_logger.py" in dockerfile


def test_data_collector_uses_python312_compatible_kafka_python():
    requirements = _read(BACKEND / "data-collector" / "requirements.txt")

    assert "kafka-python==2.0.2" not in requirements
    assert "kafka-python>=2.1" in requirements


def test_e2e_smoke_exercises_data_collector_and_health_checks_runtime_services():
    workflow = _read(E2E_SMOKE)

    assert "data-collector" in workflow
    assert "pipefail" in workflow
    assert "sentinel-data-collector" in workflow
    assert "sentinel-ai-engine" in workflow
    assert "sentinel-policy-orchestrator" in workflow


def test_security_dast_bootstraps_minimal_gateway_stack():
    workflow = _read(SECURITY)
    dast_job = workflow.split("  security-dast:", 1)[1].split("\n  security:", 1)[0]

    for name in (
        "POSTGRES_PASSWORD",
        "SENTINEL_APP_DB_PASSWORD",
        "JWT_SECRET_KEY",
        "ADMIN_PASSWORD",
        "GRAFANA_PASSWORD",
        "INTERNAL_SERVICE_TOKEN",
    ):
        assert f"{name}:" in dast_job

    assert "docker compose up -d --build postgres redis db-migrate" in dast_job
    assert "docker inspect sentinel-db-migrate" in dast_job
    assert "docker compose up -d --build --no-deps auth-service" in dast_job
    assert "docker compose up -d --build --no-deps api-gateway" in dast_job
    assert "curl -sf http://localhost:8080/health" in dast_job
