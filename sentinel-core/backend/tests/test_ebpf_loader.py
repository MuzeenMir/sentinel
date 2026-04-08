"""Tests for the eBPF program loader (dry-run / non-privileged mode)."""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ebpf_lib.loader.program_loader import ProgramLoader, ProgramInfo, SignatureVerifier


class TestSignatureVerifier:
    def test_no_key_allows_everything(self):
        verifier = SignatureVerifier(key_path="/nonexistent/path")
        with tempfile.NamedTemporaryFile(suffix=".o") as f:
            f.write(b"fake eBPF object")
            f.flush()
            assert verifier.verify(f.name) is True

    def test_with_key_rejects_missing_sig(self):
        with tempfile.NamedTemporaryFile(suffix=".key", mode="w") as kf:
            kf.write("testsecretkey123")
            kf.flush()
            verifier = SignatureVerifier(key_path=kf.name)
            with tempfile.NamedTemporaryFile(suffix=".o") as f:
                f.write(b"fake eBPF object")
                f.flush()
                assert verifier.verify(f.name) is False

    def test_with_key_accepts_valid_sig(self):
        with tempfile.NamedTemporaryFile(suffix=".key", mode="w", delete=False) as kf:
            kf.write("testsecretkey123")
            kf.flush()
            key_path = kf.name

        try:
            verifier = SignatureVerifier(key_path=key_path)
            with tempfile.NamedTemporaryFile(suffix=".o", delete=False) as f:
                f.write(b"fake eBPF object")
                f.flush()
                obj_path = f.name

            sig = verifier.sign(obj_path)
            sig_path = obj_path + ".sig"
            with open(sig_path, "w") as sf:
                sf.write(sig)

            assert verifier.verify(obj_path, sig_path) is True
        finally:
            for p in [key_path, obj_path, sig_path]:
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def test_with_key_rejects_tampered_sig(self):
        with tempfile.NamedTemporaryFile(suffix=".key", mode="w", delete=False) as kf:
            kf.write("testsecretkey123")
            kf.flush()
            key_path = kf.name

        try:
            verifier = SignatureVerifier(key_path=key_path)
            with tempfile.NamedTemporaryFile(suffix=".o", delete=False) as f:
                f.write(b"fake eBPF object")
                f.flush()
                obj_path = f.name

            sig_path = obj_path + ".sig"
            with open(sig_path, "w") as sf:
                sf.write("0" * 64)

            assert verifier.verify(obj_path, sig_path) is False
        finally:
            for p in [key_path, obj_path, sig_path]:
                try:
                    os.unlink(p)
                except OSError:
                    pass


class TestProgramLoader:
    def test_load_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            loader = ProgramLoader(compiled_dir=tmpdir)
            with pytest.raises(FileNotFoundError):
                loader.load("nonexistent_program")

    def test_dry_run_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            obj_path = os.path.join(tmpdir, "test_prog.o")
            with open(obj_path, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 100)

            audit_events = []
            loader = ProgramLoader(
                compiled_dir=tmpdir,
                audit_callback=lambda e: audit_events.append(e),
            )
            info = loader.load("test_prog", prog_type="xdp")

            assert isinstance(info, ProgramInfo)
            assert info.name == "test_prog"
            assert info.sha256 != ""
            assert loader.is_loaded("test_prog")
            assert len(audit_events) == 1
            assert audit_events[0]["action"] == "load"
            assert audit_events[0]["success"] is True

    def test_unload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            obj_path = os.path.join(tmpdir, "test_prog.o")
            with open(obj_path, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 100)

            loader = ProgramLoader(compiled_dir=tmpdir)
            loader.load("test_prog")
            assert loader.is_loaded("test_prog")

            loader.unload("test_prog")
            assert not loader.is_loaded("test_prog")

    def test_unload_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            loader = ProgramLoader(compiled_dir=tmpdir)
            loader.unload("nonexistent")

    def test_get_loaded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            obj_path = os.path.join(tmpdir, "prog1.o")
            with open(obj_path, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 100)

            loader = ProgramLoader(compiled_dir=tmpdir)
            loader.load("prog1")
            loaded = loader.get_loaded()
            assert "prog1" in loaded
            assert loaded["prog1"].prog_type == "xdp"
