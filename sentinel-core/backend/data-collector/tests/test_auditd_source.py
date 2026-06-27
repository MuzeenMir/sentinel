from auditd_source import parse_event, _parse_kv, _parse_msg_ts

SYSCALL = (
    'type=SYSCALL msg=audit(1700000000.123:4567): arch=c000003e syscall=59 '
    'success=yes exit=0 ppid=1000 pid=1234 auid=0 uid=0 gid=0 '
    'comm="bash" exe="/usr/bin/bash" key="exec"'
)
EXECVE = 'type=EXECVE msg=audit(1700000000.123:4567): argc=3 a0="/bin/bash" a1="-c" a2="id"'


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
