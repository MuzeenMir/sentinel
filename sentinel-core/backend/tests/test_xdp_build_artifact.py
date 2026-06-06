"""Regression coverage for the xdp-collector eBPF build artifact."""

import re
import subprocess
from pathlib import Path


REPO_CORE = Path(__file__).resolve().parents[2]
XDP_DOCKERFILE = REPO_CORE / "backend" / "xdp-collector" / "Dockerfile"


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
    text = XDP_DOCKERFILE.read_text(encoding="utf-8")

    assert "COPY ebpf-lib/ ebpf_lib/" in text
    assert "make -C ebpf_lib xdp" in text


def test_xdp_collector_dockerfile_uses_named_builder_and_runtime_stages():
    text = XDP_DOCKERFILE.read_text(encoding="utf-8")

    stages = re.findall(
        r"^FROM\s+(?P<image>\S+)\s+AS\s+(?P<alias>[a-z0-9_-]+)\s*$",
        text,
        flags=re.MULTILINE | re.IGNORECASE,
    )

    assert stages, "xdp-collector Dockerfile must use named multi-stage FROM lines"
    assert [alias.lower() for _, alias in stages] == ["builder", "runtime"]
    assert all("@sha256:" in image for image, _ in stages)


def test_xdp_collector_runtime_copies_compiled_xdp_artifact_from_builder():
    text = XDP_DOCKERFILE.read_text(encoding="utf-8")

    assert re.search(
        r"^COPY\s+--from=builder\s+\S*compiled/xdp/xdp_flow\.o\s+\S*compiled/xdp/xdp_flow\.o\s*$",
        text,
        flags=re.MULTILINE,
    ), "runtime stage must copy compiled/xdp/xdp_flow.o from the builder stage"


def test_xdp_collector_runtime_stage_does_not_install_build_packages():
    text = XDP_DOCKERFILE.read_text(encoding="utf-8")
    runtime_match = re.search(
        r"^FROM\s+\S+\s+AS\s+runtime\s*$\n(?P<body>.*)",
        text,
        flags=re.MULTILINE | re.IGNORECASE | re.DOTALL,
    )

    assert runtime_match, "xdp-collector Dockerfile must declare a named runtime stage"
    runtime_stage = runtime_match.group("body")

    forbidden_packages = {"clang", "llvm", "make", "libbpf-dev", "bpftool"}
    installed_packages = set()
    for install_block in re.findall(
        r"apt-get\s+install\s+-y\s+--no-install-recommends\s+\\?\n(?P<packages>.*?)(?=\s*&&|\n\n|\Z)",
        runtime_stage,
        flags=re.DOTALL,
    ):
        installed_packages.update(
            re.findall(r"\b[a-z0-9][a-z0-9+.-]*\b", install_block)
        )

    assert not (installed_packages & forbidden_packages)
