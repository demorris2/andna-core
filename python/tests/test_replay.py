"""
Tests for andna.replay — evidence capture and replay verification.
"""

import json
import tempfile
from pathlib import Path

import pytest

from andna.contracts import AndnaErr
from andna.engine import VerifyResult
from andna.replay import ReplayLog, VerificationRecord, EVIDENCE_SCHEMA_VERSION


class TestVerificationRecord:
    def test_record_fields(self):
        record = VerificationRecord(
            run_id="run-123",
            timestamp="2026-02-27T12:00:00.000Z",
            frame_hash="abc123",
            frame_len=4030,
            decision="ACCEPT",
            error_code=0,
            error_msg=None,
            engine="python",
        )
        assert record.decision == "ACCEPT"
        assert record.error_code == 0
        assert record.contract_version == "vNext-Phase1-R1"
        assert record.schema_version == EVIDENCE_SCHEMA_VERSION

    def test_record_is_frozen(self):
        record = VerificationRecord(
            run_id="run-123",
            timestamp="2026-02-27T12:00:00.000Z",
            frame_hash="abc123",
            frame_len=4030,
            decision="ACCEPT",
            error_code=0,
            error_msg=None,
            engine="python",
        )
        with pytest.raises(AttributeError):
            record.decision = "REJECT"  # type: ignore


class TestReplayLog:
    def test_capture_accept(self):
        log = ReplayLog()
        frame = b"\x42" * 4030
        result = VerifyResult(ok=True, error_code=AndnaErr.OK)

        record = log.capture(frame, result, "python")

        assert record.decision == "ACCEPT"
        assert record.error_code == 0
        assert record.engine == "python"
        assert record.frame_len == 4030
        assert len(record.frame_hash) == 64  # SHA-256 hex
        assert record.run_id.startswith("run-")
        assert len(log.records) == 1

    def test_capture_reject(self):
        log = ReplayLog()
        frame = b"\x00" * 100
        result = VerifyResult(
            ok=False,
            error_code=AndnaErr.ERR_LENGTH,
            error_msg="wrong length",
        )

        record = log.capture(frame, result, "python")

        assert record.decision == "REJECT"
        assert record.error_code == AndnaErr.ERR_LENGTH
        assert record.error_msg == "wrong length"

    def test_multiple_captures(self):
        log = ReplayLog()
        for i in range(5):
            frame = bytes([i]) * 100
            result = VerifyResult(ok=True, error_code=0)
            log.capture(frame, result, "python")

        assert len(log.records) == 5
        # Each should have unique run_id
        run_ids = {r.run_id for r in log.records}
        assert len(run_ids) == 5

    def test_verify_replay_matching(self):
        log = ReplayLog()
        frame = b"\xDE\xAD\xBE\xEF" * 1000
        result = VerifyResult(ok=True, error_code=0)

        record = log.capture(frame, result, "python")

        # Same frame should replay-match
        assert log.verify_replay(frame, record) is True

    def test_verify_replay_mismatching(self):
        log = ReplayLog()
        frame = b"\xDE\xAD\xBE\xEF" * 1000
        result = VerifyResult(ok=True, error_code=0)

        record = log.capture(frame, result, "python")

        # Different frame should not match
        tampered = b"\xFF" + frame[1:]
        assert log.verify_replay(tampered, record) is False

    def test_export_json(self):
        log = ReplayLog()
        frame = b"\x42" * 4030
        result = VerifyResult(ok=True, error_code=0)
        log.capture(frame, result, "python")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)

        try:
            log.export_json(path)
            data = json.loads(path.read_text())

            assert data["schema_version"] == EVIDENCE_SCHEMA_VERSION
            assert data["contract_version"] == "vNext-Phase1-R1"
            assert data["record_count"] == 1
            assert len(data["records"]) == 1
            assert data["records"][0]["decision"] == "ACCEPT"
        finally:
            path.unlink(missing_ok=True)

    def test_export_evidence_bundle(self):
        log = ReplayLog()
        frame = b"\x42" * 4030
        result = VerifyResult(ok=True, error_code=0)
        log.capture(frame, result, "python")

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = log.export_evidence_bundle(tmpdir)

            # Check evidence.json exists
            evidence_path = bundle_dir / "evidence.json"
            assert evidence_path.exists()

            # Check manifest.json exists
            manifest_path = bundle_dir / "manifest.json"
            assert manifest_path.exists()

            manifest = json.loads(manifest_path.read_text())
            assert manifest["record_count"] == 1
            assert manifest["evidence_file"] == "evidence.json"
            assert len(manifest["evidence_sha256"]) == 64
            assert len(manifest["verification_digest"]) == 64

            # Verify integrity hash
            import hashlib
            actual_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            assert actual_hash == manifest["evidence_sha256"]

    def test_verification_digest_deterministic(self):
        """Same frames + same decisions = same digest, regardless of time."""
        frame_a = b"\x42" * 4030
        frame_b = b"\xFF" * 100

        # Run 1
        log1 = ReplayLog()
        log1.capture(frame_a, VerifyResult(ok=True, error_code=0), "python")
        log1.capture(frame_b, VerifyResult(ok=False, error_code=5), "python")
        digest1 = log1.compute_verification_digest()

        # Run 2 (different engine name, different time — should not matter)
        log2 = ReplayLog()
        log2.capture(frame_a, VerifyResult(ok=True, error_code=0), "rust")
        log2.capture(frame_b, VerifyResult(ok=False, error_code=5), "rust")
        digest2 = log2.compute_verification_digest()

        assert digest1 == digest2

    def test_verification_digest_differs_on_different_decision(self):
        """Different decision = different digest."""
        frame = b"\x42" * 4030

        log1 = ReplayLog()
        log1.capture(frame, VerifyResult(ok=True, error_code=0), "python")

        log2 = ReplayLog()
        log2.capture(frame, VerifyResult(ok=False, error_code=5), "python")

        assert log1.compute_verification_digest() != log2.compute_verification_digest()
