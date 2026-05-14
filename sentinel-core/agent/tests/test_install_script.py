from pathlib import Path


INSTALL_SCRIPT = Path(__file__).resolve().parents[1] / "install.sh"


def install_script() -> str:
    return INSTALL_SCRIPT.read_text(encoding="utf-8")


def test_installer_requires_https_control_plane():
    text = install_script()

    assert '[[ "$SENTINEL_API_URL" == https://* ]]' in text
    assert "curl --proto '=https' --tlsv1.2" in text


def test_installer_requires_and_verifies_sha256():
    text = install_script()

    assert "--sha256" in text
    assert "SENTINEL_AGENT_SHA256" in text
    assert "sha256sum -c -" in text
    assert "Agent binary checksum verification failed" in text


def test_installer_writes_config_with_json_encoder():
    text = install_script()

    assert "json.dump(config" in text
    assert '"auth_token": os.environ["SENTINEL_AGENT_TOKEN"]' in text
    assert 'cat > "$INSTALL_DIR/config.json"' not in text


def test_systemd_unit_keeps_no_new_privileges_enabled():
    text = install_script()

    assert "NoNewPrivileges=yes" in text
    assert "NoNewPrivileges=no" not in text
    assert "CapabilityBoundingSet=" in text
    assert "AmbientCapabilities=" in text
