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


def test_validator_rejects_secret_syntax_that_allows_empty_values(tmp_path, monkeypatch, capsys):
    repo_core = Path(__file__).resolve().parents[2]
    validator = load_validator(repo_core)

    for secret in REQUIRED_SECRETS:
        compose = tmp_path / f"{secret}.yml"
        compose.write_text(
            valid_compose_text().replace(f"${{{secret}:?set {secret}}}", f"${{{secret}?set {secret}}}"),
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
    assert "host network service must be behind an explicit profile: xdp-collector" in captured.err


def test_validator_ignores_xdp_outside_profiles_for_host_network(tmp_path, monkeypatch, capsys):
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
    assert "host network service must be behind an explicit profile: xdp-collector" in captured.err


def test_validator_rejects_host_network_localhost_kafka_dependency(tmp_path, monkeypatch, capsys):
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
    assert "host network service uses localhost dependency KAFKA_BOOTSTRAP_SERVERS: xdp-collector" in captured.err


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
        ["docker", "compose", "--profile", "xdp", "config"],
        cwd=repo_core,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "KAFKA_BOOTSTRAP_SERVERS=localhost" not in result.stdout
    assert "AUTH_SERVICE_URL=http://localhost" not in result.stdout
    assert "localhost:9092" not in result.stdout
    assert "localhost:5000" not in result.stdout


def test_validator_rejects_inline_ports_on_internal_services(tmp_path, monkeypatch, capsys):
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
