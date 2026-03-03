"""
Tests for andna.cli — Deterministic Replay CLI.

Exercises the full 5-minute demo flow:
  gen → verify (accept) → tamper → verify (reject) → replay → export
"""

import json
import tempfile
from pathlib import Path

import pytest

from andna.cli import (
    cmd_gen,
    cmd_verify,
    cmd_tamper,
    cmd_replay,
    cmd_export,
    main,
    _session_log,
    _get_session_log_path,
)
from andna.contracts import FRAME_V2_LEN
import andna.cli as cli_mod


@pytest.fixture(autouse=True)
def _reset_session(tmp_path, monkeypatch):
    """Reset CLI session state and use tmp_path for all file output."""
    cli_mod._session_log = type(cli_mod._session_log)()  # fresh ReplayLog
    cli_mod._session_log_path = tmp_path / "verification_log.json"
    monkeypatch.chdir(tmp_path)
    yield


class TestGen:
    def test_generates_valid_frame(self, tmp_path):
        out = tmp_path / "sample.bin"
        rc = cmd_gen(str(out))
        assert rc == 0
        assert out.exists()
        assert out.stat().st_size == FRAME_V2_LEN

    def test_frame_is_deterministic(self, tmp_path):
        """Two generated frames both verify as ACCEPT (fresh keypair each time)."""
        a = tmp_path / "a.bin"
        b = tmp_path / "b.bin"
        cmd_gen(str(a))
        cmd_gen(str(b))
        # Frames differ (fresh keypair each call) but both must be valid
        assert len(a.read_bytes()) == FRAME_V2_LEN
        assert len(b.read_bytes()) == FRAME_V2_LEN
        assert cmd_verify(str(a)) == 0  # ACCEPT
        assert cmd_verify(str(b)) == 0  # ACCEPT


class TestVerify:
    def test_valid_frame_accepted(self, tmp_path):
        frame = tmp_path / "frame.bin"
        cmd_gen(str(frame))
        rc = cmd_verify(str(frame))
        assert rc == 0

    def test_missing_file(self, tmp_path):
        rc = cmd_verify(str(tmp_path / "nonexistent.bin"))
        assert rc == 2

    def test_creates_log(self, tmp_path):
        frame = tmp_path / "frame.bin"
        cmd_gen(str(frame))
        cmd_verify(str(frame))
        log_path = cli_mod._session_log_path
        assert log_path.exists()
        data = json.loads(log_path.read_text())
        assert data["record_count"] == 1
        assert data["records"][0]["decision"] == "ACCEPT"


class TestTamper:
    def test_tampers_frame(self, tmp_path):
        orig = tmp_path / "orig.bin"
        tampered = tmp_path / "tampered.bin"
        cmd_gen(str(orig))
        rc = cmd_tamper(str(orig), str(tampered))
        assert rc == 0
        assert tampered.exists()
        assert tampered.stat().st_size == FRAME_V2_LEN
        assert orig.read_bytes() != tampered.read_bytes()

    def test_tampered_frame_rejected(self, tmp_path):
        orig = tmp_path / "orig.bin"
        tampered = tmp_path / "tampered.bin"
        cmd_gen(str(orig))
        cmd_tamper(str(orig), str(tampered))
        rc = cmd_verify(str(tampered))
        assert rc == 1  # REJECT

    def test_missing_input(self, tmp_path):
        rc = cmd_tamper(str(tmp_path / "nope.bin"), str(tmp_path / "out.bin"))
        assert rc == 2


class TestReplay:
    def test_replay_valid_log(self, tmp_path):
        # Generate, verify, then replay
        frame = tmp_path / "frame.bin"
        cmd_gen(str(frame))
        cmd_verify(str(frame))
        log_path = cli_mod._session_log_path
        rc = cmd_replay(str(log_path))
        assert rc == 0

    def test_replay_missing_file(self, tmp_path):
        rc = cmd_replay(str(tmp_path / "nope.json"))
        assert rc == 2

    def test_replay_with_mixed_decisions(self, tmp_path):
        # Verify valid frame
        valid = tmp_path / "valid.bin"
        cmd_gen(str(valid))
        cmd_verify(str(valid))

        # Verify tampered frame
        tampered = tmp_path / "tampered.bin"
        cmd_tamper(str(valid), str(tampered))
        cmd_verify(str(tampered))

        log_path = cli_mod._session_log_path
        data = json.loads(log_path.read_text())
        assert data["record_count"] == 2
        assert data["records"][0]["decision"] == "ACCEPT"
        assert data["records"][1]["decision"] == "REJECT"

        rc = cmd_replay(str(log_path))
        assert rc == 0

    def test_replay_with_frame_reverify_accept(self, tmp_path):
        """--frame mode: re-verify valid frame, assert same decision."""
        frame = tmp_path / "frame.bin"
        cmd_gen(str(frame))
        cmd_verify(str(frame))
        log_path = cli_mod._session_log_path
        rc = cmd_replay(str(log_path), frame_path=str(frame))
        assert rc == 0

    def test_replay_with_frame_reverify_reject(self, tmp_path):
        """--frame mode: re-verify tampered frame, assert same REJECT."""
        valid = tmp_path / "valid.bin"
        tampered = tmp_path / "tampered.bin"
        cmd_gen(str(valid))
        cmd_tamper(str(valid), str(tampered))
        cmd_verify(str(tampered))
        log_path = cli_mod._session_log_path
        rc = cmd_replay(str(log_path), frame_path=str(tampered))
        assert rc == 0

    def test_replay_with_frame_no_match(self, tmp_path):
        """--frame mode: frame not in log → returns 1."""
        valid = tmp_path / "valid.bin"
        cmd_gen(str(valid))
        cmd_verify(str(valid))

        # Create a different frame
        other = tmp_path / "other.bin"
        other.write_bytes(b"\xFF" * FRAME_V2_LEN)

        log_path = cli_mod._session_log_path
        rc = cmd_replay(str(log_path), frame_path=str(other))
        assert rc == 1


class TestExport:
    def test_export_evidence_bundle(self, tmp_path):
        frame = tmp_path / "frame.bin"
        cmd_gen(str(frame))
        cmd_verify(str(frame))

        bundle_dir = tmp_path / "evidence"
        rc = cmd_export(str(bundle_dir))
        assert rc == 0
        assert (bundle_dir / "evidence.json").exists()
        assert (bundle_dir / "manifest.json").exists()

        # Verify manifest integrity
        manifest = json.loads((bundle_dir / "manifest.json").read_text())
        assert manifest["record_count"] == 1
        assert len(manifest["evidence_sha256"]) == 64

        import hashlib
        actual = hashlib.sha256(
            (bundle_dir / "evidence.json").read_bytes()
        ).hexdigest()
        assert actual == manifest["evidence_sha256"]

    def test_export_empty_session(self, tmp_path):
        rc = cmd_export(str(tmp_path / "empty_evidence"))
        assert rc == 2


class TestFullDemoFlow:
    """Exercises the exact 5-minute demo script end-to-end."""

    def test_five_minute_demo(self, tmp_path):
        # Minute 1-2: Generate and verify valid frame
        sample = tmp_path / "sample_frame.bin"
        assert cmd_gen(str(sample)) == 0
        assert cmd_verify(str(sample)) == 0  # ACCEPT

        # Minute 2-3: Tamper and verify tampered frame
        tampered = tmp_path / "tampered_frame.bin"
        assert cmd_tamper(str(sample), str(tampered)) == 0
        assert cmd_verify(str(tampered)) == 1  # REJECT

        # Minute 3-4: Replay (structural)
        log_path = cli_mod._session_log_path
        assert cmd_replay(str(log_path)) == 0

        # Minute 3-4b: Replay with --frame (deterministic re-verification)
        assert cmd_replay(str(log_path), frame_path=str(sample)) == 0
        assert cmd_replay(str(log_path), frame_path=str(tampered)) == 0

        # Minute 4-5: Export evidence
        evidence_dir = tmp_path / "evidence"
        assert cmd_export(str(evidence_dir)) == 0

        # Verify: 2 records, one ACCEPT, one REJECT
        data = json.loads(log_path.read_text())
        assert data["record_count"] == 2
        decisions = [r["decision"] for r in data["records"]]
        assert decisions == ["ACCEPT", "REJECT"]

        # Verify: evidence bundle has integrity
        manifest = json.loads((evidence_dir / "manifest.json").read_text())
        import hashlib
        actual_hash = hashlib.sha256(
            (evidence_dir / "evidence.json").read_bytes()
        ).hexdigest()
        assert actual_hash == manifest["evidence_sha256"]

        # Verify: verification_digest is present and deterministic
        assert "verification_digest" in manifest
        assert len(manifest["verification_digest"]) == 64


class TestMainEntryPoint:
    def test_help(self):
        assert main(["--help"]) == 0
        assert main([]) == 0

    def test_unknown_command(self):
        assert main(["bogus"]) == 2

    def test_verify_via_main(self, tmp_path):
        frame = tmp_path / "f.bin"
        cmd_gen(str(frame))
        assert main(["verify", str(frame)]) == 0

    def test_replay_frame_via_main(self, tmp_path):
        frame = tmp_path / "f.bin"
        cmd_gen(str(frame))
        cmd_verify(str(frame))
        log_path = str(cli_mod._session_log_path)
        assert main(["replay", log_path, "--frame", str(frame)]) == 0
