"""Regression coverage for the xdp-collector eBPF build artifact."""

import subprocess
from pathlib import Path


REPO_CORE = Path(__file__).resolve().parents[2]


def test_ebpf_makefile_exposes_xdp_artifact_target():
    makefile_dir = REPO_CORE / "backend" / "ebpf-lib"

    result = subprocess.run(
        ["make", "-C", str(makefile_dir), "--dry-run", "xdp"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "compiled/xdp/xdp_flow.o" in result.stdout


def test_xdp_collector_dockerfile_builds_loader_artifact():
    dockerfile = REPO_CORE / "backend" / "xdp-collector" / "Dockerfile"
    text = dockerfile.read_text(encoding="utf-8")

    assert "COPY ebpf-lib/ ebpf_lib/" in text
    assert "make -C ebpf_lib xdp" in text
