from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
BACKEND = REPO / "sentinel-core" / "backend"
E2E_SMOKE = REPO / ".github" / "workflows" / "e2e-smoke.yml"


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
