import importlib.util
import os
import subprocess
import sys
from pathlib import Path


REQUIRED_SECRETS = (
    "POSTGRES_PASSWORD",
    "JWT_SECRET_KEY",
    "ADMIN_PASSWORD",
    "GRAFANA_PASSWORD",
    "INTERNAL_SERVICE_TOKEN",
)


def load_validator(repo_core: Path):
    script = repo_core / "scripts" / "validate_compose_security.py"
    spec = importlib.util.spec_from_file_location("validate_compose_security", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def valid_compose_text() -> str:
    return """
services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}
  auth-service:
    image: sentinel-auth-service
    environment:
      - JWT_SECRET_KEY=${JWT_SECRET_KEY:?set JWT_SECRET_KEY}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD:?set ADMIN_PASSWORD}
      - LOCKOUT_THRESHOLD=5
  grafana:
    image: grafana/grafana:10.4.0
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:?set GRAFANA_PASSWORD}
  flink-drl-feed:
    image: sentinel-flink-drl-feed
    environment:
      - INTERNAL_SERVICE_TOKEN=${INTERNAL_SERVICE_TOKEN:?set INTERNAL_SERVICE_TOKEN}
"""


def test_docker_compose_security_invariants():
    repo_core = Path(__file__).resolve().parents[2]
    script = repo_core / "scripts" / "validate_compose_security.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=repo_core,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_docker_compose_rejects_empty_required_secrets():
    repo_core = Path(__file__).resolve().parents[2]
    env = {
        "POSTGRES_PASSWORD": "",
        "JWT_SECRET_KEY": "",
        "ADMIN_PASSWORD": "",
        "GRAFANA_PASSWORD": "",
        "INTERNAL_SERVICE_TOKEN": "",
    }
    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=repo_core,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode != 0


def test_validator_rejects_secret_syntax_that_allows_empty_values(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)

    for secret in REQUIRED_SECRETS:
        compose = tmp_path / f"{secret}.yml"
        compose.write_text(
            valid_compose_text().replace(
                f"${{{secret}:?set {secret}}}", f"${{{secret}?set {secret}}}"
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(validator, "COMPOSE", compose)

        assert validator.main() == 1
        captured = capsys.readouterr()
        assert f"{secret} must use non-empty required-variable syntax" in captured.err


def test_validator_rejects_unprofiled_host_network_mode(tmp_path, monkeypatch, capsys):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    compose = tmp_path / "compose.yml"
    compose.write_text(
        valid_compose_text()
        + """
  xdp-collector:
    image: sentinel-xdp-collector
    network_mode: "host"
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "COMPOSE", compose)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "host network mode is forbidden: xdp-collector" in captured.err


def test_validator_rejects_unexpected_privileged_service(tmp_path, monkeypatch, capsys):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    compose = tmp_path / "compose.yml"
    compose.write_text(
        valid_compose_text()
        + """
  data-collector:
    image: sentinel-data-collector
    privileged: true
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "COMPOSE", compose)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "privileged mode is not allowed: data-collector" in captured.err


def test_validator_rejects_host_network_even_when_profiled(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    compose = tmp_path / "compose.yml"
    compose.write_text(
        valid_compose_text()
        + """
  xdp-collector:
    image: sentinel-xdp-collector
    network_mode: "host"
    environment:
      - xdp
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "COMPOSE", compose)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "host network mode is forbidden: xdp-collector" in captured.err


def test_validator_rejects_host_network_localhost_kafka_dependency(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    compose = tmp_path / "compose.yml"
    compose.write_text(
        valid_compose_text()
        + """
  xdp-collector:
    image: sentinel-xdp-collector
    profiles: ["xdp"]
    network_mode: "host"
    environment:
      - KAFKA_BOOTSTRAP_SERVERS=localhost:9092
      - AUTH_SERVICE_URL=https://control-plane.example.com
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "COMPOSE", compose)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "host network mode is forbidden: xdp-collector" in captured.err


def test_xdp_profile_config_renders_without_stale_localhost_dependencies():
    repo_core = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env.update(
        {
            "POSTGRES_PASSWORD": "x",
            "JWT_SECRET_KEY": "y",
            "ADMIN_PASSWORD": "z",
            "GRAFANA_PASSWORD": "g",
            "INTERNAL_SERVICE_TOKEN": "t",
        }
    )

    result = subprocess.run(
        ["docker", "compose", "--profile", "xdp", "config", "xdp-collector"],
        cwd=repo_core,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    xdp_service = result.stdout.split("\n  xdp-collector:", 1)[1].split(
        "\n  zookeeper:", 1
    )[0]
    assert "KAFKA_BOOTSTRAP_SERVERS: kafka:29092" in xdp_service
    assert "AUTH_SERVICE_URL: http://auth-service:5000" in xdp_service
    assert "REDIS_URL: redis://redis:6379" in xdp_service
    assert "kafka:" in xdp_service
    assert "condition: service_healthy" in xdp_service
    assert "redis:" in xdp_service
    assert "KAFKA_BOOTSTRAP_SERVERS=localhost" not in xdp_service
    assert "AUTH_SERVICE_URL=http://localhost" not in xdp_service
    assert "localhost:9092" not in xdp_service
    assert "localhost:5000" not in xdp_service


def test_validator_rejects_inline_ports_on_internal_services(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    compose = tmp_path / "compose.yml"
    compose.write_text(
        valid_compose_text().replace(
            "  postgres:\n    image: postgres:13",
            '  postgres:\n    image: postgres:13\n    ports: ["5432:5432"]',
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "COMPOSE", compose)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "internal service exposes host ports: postgres" in captured.err


def test_validator_rejects_0_0_0_0_host_ports_on_internal_services(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    compose = tmp_path / "compose.yml"
    compose.write_text(
        valid_compose_text()
        + """
  api-gateway:
    image: sentinel-api-gateway
    ports:
      - "0.0.0.0:8080:8080"
  alert-service:
    image: sentinel-alert-service
    ports:
      - "0.0.0.0:5002:5002"
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "COMPOSE", compose)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "internal service publishes 0.0.0.0 host port: alert-service" in captured.err
    assert "api-gateway" not in captured.err


def test_validator_rejects_known_secret_default_fallbacks(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    compose = tmp_path / "compose.yml"
    compose.write_text(
        valid_compose_text()
        + """
  secret-regression:
    image: scratch
    environment:
      - JWT_SECRET=${JWT_SECRET:-dev}
      - DATABASE_PASSWORD=${DATABASE_PASSWORD:-dev}
      - REDIS_PASSWORD=${REDIS_PASSWORD:-dev}
      - AGENT_TOKEN=${AGENT_TOKEN:-dev}
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "COMPOSE", compose)

    assert validator.main() == 1
    captured = capsys.readouterr()
    for secret in ("JWT_SECRET", "DATABASE_PASSWORD", "REDIS_PASSWORD", "AGENT_TOKEN"):
        assert f"{secret} must not define a default fallback" in captured.err


def test_validator_rejects_missing_installer_checksum_or_https(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    installer = tmp_path / "install.sh"
    installer.write_text(
        """
curl -fsSL http://sentinel.example.com/agent -o /tmp/sentinel-agent
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "INSTALLER", installer, raising=False)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "agent installer must verify downloads with sha256sum" in captured.err
    assert "agent installer must require https:// downloads" in captured.err


def test_validator_rejects_missing_auth_lockout_threshold_env(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    compose = tmp_path / "compose.yml"
    compose.write_text(
        valid_compose_text().replace("      - LOCKOUT_THRESHOLD=5\n", ""),
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "COMPOSE", compose)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "auth-service must declare LOCKOUT_THRESHOLD" in captured.err


def test_validator_rejects_missing_viewer_forbidden_api_gateway_test(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    test_file = tmp_path / "test_api_gateway.py"
    test_file.write_text("def test_admin_can_mutate():\n    pass\n", encoding="utf-8")
    monkeypatch.setattr(validator, "API_GATEWAY_TEST", test_file, raising=False)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "api-gateway tests must include viewer forbidden coverage" in captured.err


def test_validator_rejects_missing_systemd_hardening_flags(
    tmp_path, monkeypatch, capsys
):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)
    installer = tmp_path / "install.sh"
    installer.write_text(
        """
curl --proto '=https' --tlsv1.2 -fsSL https://sentinel.example.com/agent
sha256sum -c -
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=true
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "INSTALLER", installer, raising=False)

    assert validator.main() == 1
    captured = capsys.readouterr()
    assert "agent installer systemd unit must set ProtectHome=true" in captured.err
