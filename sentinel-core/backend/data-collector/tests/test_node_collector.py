import json
import fakeredis
from node_collector import NodeCollector, _group_by_serial

LOG = """\
type=SYSCALL msg=audit(1700000000.1:10): syscall=59 pid=11 uid=0 comm="bash" exe="/usr/bin/bash"
type=EXECVE msg=audit(1700000000.1:10): argc=1 a0="bash"
type=SYSCALL msg=audit(1700000000.2:11): syscall=59 pid=22 uid=1000 comm="nc" exe="/usr/bin/nc"
type=EXECVE msg=audit(1700000000.2:11): argc=3 a0="nc" a1="-e" a2="/bin/sh"
""".splitlines()


def test_group_by_serial_splits_events():
    groups = _group_by_serial(LOG)
    assert len(groups) == 2
    assert all(len(g) == 2 for g in groups)


def test_feed_lines_emits_each_event_to_stream():
    r = fakeredis.FakeStrictRedis(decode_responses=True)
    c = NodeCollector(r, stream="node:events")
    n = c.feed_lines(LOG)
    assert n == 2
    entries = r.xrange("node:events")
    assert len(entries) == 2
    first = json.loads(entries[0][1]["event"])
    assert first["comm"] == "bash"
    second = json.loads(entries[1][1]["event"])
    assert second["comm"] == "nc"
    assert second["args"] == ["nc", "-e", "/bin/sh"]
