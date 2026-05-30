from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "runtime_role_isolation_check.sh"
)


def test_post_insert_audit_update_check_captures_intentional_failure():
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index(
        'echo "==> [audit] sentinel_app cannot UPDATE audit_log row it just inserted"'
    )
    end = text.index('if [ "${RC}" -eq 0 ]; then', start)
    block = text[start:end]

    assert block.index("set +e") < block.index("ERR=$(")
    assert block.index("RC=$?") < block.index("set -e")
