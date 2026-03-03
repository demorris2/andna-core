"""
Tests for andna.api — FastAPI verifier routes.

Uses httpx TestClient (comes with FastAPI) for synchronous testing.
All tests use the Python engine (no native lib required).
"""

import json
import pytest

try:
    from fastapi.testclient import TestClient
    from andna.api import create_app
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

from andna.contracts import (
    AndnaErr, FRAME_V2_LEN, MU_PRE_LEN, TE_LEN, SIG_LEN,
    TE_DEVICE_ID16_OFF, TE_DEVICE_ID16_LEN,
    DOMAIN_SEP, DOMAIN_SEP_LEN, MU_PRE_DOMAIN_SEP_OFF,
    MU_PRE_VERSION_OFF, MU_PRE_VERSION_VAL,
)
from andna.frame_packer import build_mu_pre, pack_frame_v2, device_id32_from_id16

pytestmark = pytest.mark.skipif(
    not _FASTAPI_AVAILABLE,
    reason="FastAPI not installed (pip install 'andna[server]')",
)


# ── Helpers ──


def _make_valid_frame() -> bytes:
    """Build a frame satisfying all directives."""
    te = bytes(TE_LEN)
    device_id16 = te[TE_DEVICE_ID16_OFF:TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN]
    device_id32 = device_id32_from_id16(device_id16)
    mp = build_mu_pre(
        te=te, device_id32=device_id32, epoch=0,
        sid=b"\x00" * 32, n_d=b"\x00" * 32,
        n_s=b"\x00" * 32, ctx_hash=b"\x00" * 32,
    )
    return pack_frame_v2(mu_pre=mp, te=te, sig=bytes(SIG_LEN))


def _make_bad_pk_hash_frame() -> bytes:
    """Frame with correct domain sep but wrong pk_hash."""
    mu_pre = bytearray(MU_PRE_LEN)
    mu_pre[MU_PRE_DOMAIN_SEP_OFF:MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN] = DOMAIN_SEP
    mu_pre[MU_PRE_VERSION_OFF] = MU_PRE_VERSION_VAL
    return bytes(mu_pre) + bytes(TE_LEN) + bytes(SIG_LEN)


@pytest.fixture
def client():
    """Fresh TestClient for each test (isolates replay log)."""
    import andna.api as api_mod
    from andna.replay import ReplayLog
    from andna.engine import reset_engine

    # Reset shared state
    api_mod._replay_log = ReplayLog()
    reset_engine()

    app = create_app()
    with TestClient(app) as c:
        yield c


# ── Health endpoint ──


class TestHealth:
    def test_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["engine"] == "python"
        assert data["contract_version"] == "vNext-Phase1-R1"


# ── Verify endpoint ──


class TestVerifyVnext:
    def test_valid_frame_accepted(self, client):
        frame = _make_valid_frame()
        resp = client.post(
            "/verify/vnext",
            content=frame,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["engine"] == "python"
        assert "run_id" in data

    def test_empty_body_rejected(self, client):
        resp = client.post(
            "/verify/vnext",
            content=b"",
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False
        assert data["error_code"] == AndnaErr.ERR_LENGTH

    def test_short_body_rejected(self, client):
        resp = client.post(
            "/verify/vnext",
            content=b"\x00" * 100,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False
        assert data["error_code"] == AndnaErr.ERR_LENGTH

    def test_pk_hash_mismatch_rejected(self, client):
        frame = _make_bad_pk_hash_frame()
        resp = client.post(
            "/verify/vnext",
            content=frame,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 403
        data = resp.json()
        assert data["ok"] is False
        assert data["error_code"] == AndnaErr.ERR_PK_HASH_MISMATCH

    def test_response_includes_run_id(self, client):
        frame = _make_valid_frame()
        resp = client.post(
            "/verify/vnext",
            content=frame,
            headers={"Content-Type": "application/octet-stream"},
        )
        data = resp.json()
        assert "run_id" in data
        assert data["run_id"].startswith("run-")

    def test_zeroed_frame_fails_directive_a(self, client):
        """All-zero frame: domain sep wrong → ERR_MU_PRE."""
        frame = b"\x00" * FRAME_V2_LEN
        resp = client.post(
            "/verify/vnext",
            content=frame,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 403
        data = resp.json()
        assert data["ok"] is False
        assert data["error_code"] == AndnaErr.ERR_MU_PRE


# ── Evidence endpoint ──


class TestEvidence:
    def test_empty_evidence(self, client):
        resp = client.get("/evidence")
        assert resp.status_code == 200
        data = resp.json()
        assert data["record_count"] == 0
        assert data["records"] == []

    def test_evidence_after_verify(self, client):
        # Submit a valid frame
        frame = _make_valid_frame()
        client.post(
            "/verify/vnext",
            content=frame,
            headers={"Content-Type": "application/octet-stream"},
        )

        # Check evidence
        resp = client.get("/evidence")
        data = resp.json()
        assert data["record_count"] == 1
        record = data["records"][0]
        assert record["decision"] == "ACCEPT"
        assert record["error_code"] == 0
        assert record["engine"] == "python"
        assert record["contract_version"] == "vNext-Phase1-R1"
        assert len(record["frame_hash"]) == 64  # SHA-256 hex

    def test_evidence_captures_rejections(self, client):
        # Submit an invalid frame
        client.post(
            "/verify/vnext",
            content=b"\x00" * 100,
            headers={"Content-Type": "application/octet-stream"},
        )

        resp = client.get("/evidence")
        data = resp.json()
        assert data["record_count"] == 1
        record = data["records"][0]
        assert record["decision"] == "REJECT"
        assert record["error_code"] == AndnaErr.ERR_LENGTH
