from pathlib import Path


INSTALL_SCRIPT = Path(__file__).resolve().parents[1] / "install.sh"
REQUIRED_HARDENING_FLAGS = {
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "PrivateTmp=true",
}


def systemd_unit_text() -> str:
    text = INSTALL_SCRIPT.read_text(encoding="utf-8")
    marker = 'cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF'
    start = text.index(marker) + len(marker)
    end = text.index("\nEOF", start)
    return text[start:end]


def test_systemd_unit_enforces_required_hardening_flags():
    unit = systemd_unit_text()

    for flag in REQUIRED_HARDENING_FLAGS:
        assert flag in unit
