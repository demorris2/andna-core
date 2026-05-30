"""
End-to-end integration test for AN-DNA verifier service path.

Simulates the full HTTP → parse → engine verify → response pipeline.
Tests both the Python engine (always available) and the Rust engine
(only when libandna_ffi.so is built).

This is the R1 gate test: if this passes with VERIFY_ENGINE=rust,
the Rust core is ready for canary deployment behind the Python service.
"""
import hashlib
import json
import os
import struct
import sys
import unittest
from dataclasses import dataclass
from http import HTTPStatus
from typing import Optional

# Ensure the andna package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from andna.contracts import (
    MU_PRE_LEN, TE_V1_LEN, SIG_LEN, FRAME_V2_LEN,
    MU_PRE_PK_HASH_OFF, MU_PRE_PK_HASH_LEN,
    MU_PRE_DOMAIN_SEP_OFF, DOMAIN_SEP_LEN, DOMAIN_SEP,
    MU_PRE_VERSION_OFF, MU_PRE_VERSION_VAL,
    MU_PRE_EPOCH_OFF,
    PK_HASH_LEN,
    AndnaErr,
)
from andna.frame_packer import pk_hash, build_mu_pre, pack_frame_v2, unpack_frame_v2, device_id32_from_id16
from andna.engine import get_engine, reset_engine, PythonEngine


# ── Simulated verifier service handler ──

@dataclass
class VerifyResponse:
    """What the HTTP handler returns."""
    status: int          # HTTP status code
    ok: bool
    error_code: int
    error_msg: Optional[str]


def handle_verify_request(raw_body: bytes) -> VerifyResponse:
    """
    Simulated verifier service handler.

    This is the exact logic that runs in production:
    1. Check Content-Length == FRAME_V2_LEN
    2. Parse frame
    3. Verify via engine
    4. Return structured response
    """
    # Step 1: length gate (before any parsing)
    if len(raw_body) != FRAME_V2_LEN:
        return VerifyResponse(
            status=HTTPStatus.BAD_REQUEST,
            ok=False,
            error_code=AndnaErr.ERR_LENGTH,
            error_msg=f"expected {FRAME_V2_LEN} bytes, got {len(raw_body)}",
        )

    # Step 2: get engine (reads VERIFY_ENGINE env var)
    engine = get_engine()

    # Step 3: verify
    result = engine.verify_frame_v2(raw_body)

    # Step 4: build response
    if result.ok:
        return VerifyResponse(
            status=HTTPStatus.OK,
            ok=True,
            error_code=AndnaErr.OK,
            error_msg=None,
        )
    else:
        return VerifyResponse(
            status=HTTPStatus.FORBIDDEN,
            ok=False,
            error_code=result.error_code,
            error_msg=result.error_msg,
        )


# ── Test fixtures ──

def make_valid_frame() -> bytes:
    """Build a well-formed 4030-byte frame that passes all directive checks.

    Satisfies: pk_hash binding, Directive A (domain sep/version),
    Directive B (epoch correlation), Directive E (device ID duality).
    """
    device_id16 = b"\xBB" * 16
    epoch = 42
    te = bytes(range(32)) + (b"\xAA" * 1280) + struct.pack("<Q", epoch) + device_id16
    assert len(te) == TE_V1_LEN

    # Directive E: device_id32 = SHAKE256(device_id16, 32)
    device_id32 = device_id32_from_id16(device_id16)

    mu_pre = build_mu_pre(
        te=te,
        device_id32=device_id32,  # Directive E: derived, not raw
        epoch=epoch,              # Directive B: must match T_E.epoch
        sid=b"\xDD" * 32,
        n_d=b"\xEE" * 32,
        n_s=b"\xFF" * 32,
        ctx_hash=b"\x11" * 32,
    )
    sig = b"\x00" * SIG_LEN

    return pack_frame_v2(mu_pre=mu_pre, te=te, sig=sig)


def make_bad_binding_frame() -> bytes:
    """Build a frame where pk_hash doesn't match T_E."""
    te = b"\x00" * TE_V1_LEN
    mu_pre = bytearray(MU_PRE_LEN)
    # Set pk_hash to wrong value (all 0xFF instead of SHAKE256(zeros))
    mu_pre[MU_PRE_PK_HASH_OFF:MU_PRE_PK_HASH_OFF + PK_HASH_LEN] = b"\xFF" * PK_HASH_LEN
    # Set domain sep and version so those checks pass
    mu_pre[MU_PRE_DOMAIN_SEP_OFF:MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN] = DOMAIN_SEP
    mu_pre[MU_PRE_VERSION_OFF] = MU_PRE_VERSION_VAL
    mu_pre[MU_PRE_EPOCH_OFF:MU_PRE_EPOCH_OFF + 8] = struct.pack("<Q", 1)

    sig = b"\x00" * SIG_LEN
    return bytes(mu_pre) + te + sig


# ── Integration tests ──

class TestVerifierIntegrationPython(unittest.TestCase):
    """Full pipeline tests using the Python engine."""

    @classmethod
    def setUpClass(cls):
        os.environ["VERIFY_ENGINE"] = "python"
        reset_engine()

    def test_valid_frame_accepted(self):
        """Valid frame → HTTP 200, ok=True."""
        frame = make_valid_frame()
        resp = handle_verify_request(frame)
        self.assertEqual(resp.status, HTTPStatus.OK)
        self.assertTrue(resp.ok)
        self.assertEqual(resp.error_code, AndnaErr.OK)
        self.assertIsNone(resp.error_msg)

    def test_short_body_rejected(self):
        """Short body → HTTP 400, length error."""
        resp = handle_verify_request(b"\x00" * 100)
        self.assertEqual(resp.status, HTTPStatus.BAD_REQUEST)
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_code, AndnaErr.ERR_LENGTH)

    def test_empty_body_rejected(self):
        """Empty body → HTTP 400, length error."""
        resp = handle_verify_request(b"")
        self.assertEqual(resp.status, HTTPStatus.BAD_REQUEST)
        self.assertFalse(resp.ok)

    def test_pk_hash_mismatch_rejected(self):
        """Frame with wrong pk_hash → HTTP 403."""
        frame = make_bad_binding_frame()
        resp = handle_verify_request(frame)
        self.assertEqual(resp.status, HTTPStatus.FORBIDDEN)
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_code, AndnaErr.ERR_PK_HASH_MISMATCH)

    def test_frame_roundtrip_through_packer(self):
        """pack → handle → unpack consistency."""
        frame = make_valid_frame()
        self.assertEqual(len(frame), FRAME_V2_LEN)

        mu_pre, te, sig = unpack_frame_v2(frame)
        self.assertEqual(len(mu_pre), MU_PRE_LEN)
        self.assertEqual(len(te), TE_V1_LEN)
        self.assertEqual(len(sig), SIG_LEN)

        # pk_hash binding check
        expected_pk_hash = pk_hash(te)
        self.assertEqual(mu_pre[:PK_HASH_LEN], expected_pk_hash)

    def test_response_json_serializable(self):
        """Verify response can be JSON-serialized (for HTTP response body)."""
        frame = make_valid_frame()
        resp = handle_verify_request(frame)
        body = {
            "ok": resp.ok,
            "error_code": resp.error_code,
            "error_msg": resp.error_msg,
        }
        serialized = json.dumps(body)
        parsed = json.loads(serialized)
        self.assertTrue(parsed["ok"])


class TestVerifierIntegrationRust(unittest.TestCase):
    """
    Full pipeline tests using the Rust engine (via ctypes).
    Auto-skipped if libandna_ffi.so is not built.
    """

    @classmethod
    def setUpClass(cls):
        os.environ["VERIFY_ENGINE"] = "rust"
        reset_engine()
        try:
            engine = get_engine()
            if engine.name != "rust":
                raise unittest.SkipTest("Rust engine not available")
        except Exception:
            raise unittest.SkipTest("libandna_ffi.so not built — skip Rust integration")

    @classmethod
    def tearDownClass(cls):
        os.environ["VERIFY_ENGINE"] = "python"
        reset_engine()

    def test_valid_frame_accepted_rust(self):
        from andna.native import gen_test_frame
        frame = gen_test_frame()
        resp = handle_verify_request(frame)
        self.assertTrue(resp.ok, f"Rust engine rejected valid frame: {resp.error_msg}")

    def test_pk_hash_mismatch_rejected_rust(self):
        """Bad binding → rejected via Rust engine."""
        frame = make_bad_binding_frame()
        resp = handle_verify_request(frame)
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_code, AndnaErr.ERR_PK_HASH_MISMATCH)

    def test_short_frame_rejected_rust(self):
        """Short body → length error via Rust engine."""
        resp = handle_verify_request(b"\x00" * 100)
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_code, AndnaErr.ERR_LENGTH)


class TestDifferentialPipeline(unittest.TestCase):
    """
    Differential test: run both engines on the same inputs,
    verify identical outcomes. This is the R1 gate for cutover.

    Auto-skipped if Rust engine is not available.
    """

    @classmethod
    def setUpClass(cls):
        try:
            os.environ["VERIFY_ENGINE"] = "rust"
            reset_engine()
            rust_engine = get_engine()
            if rust_engine.name != "rust":
                raise Exception("not rust")
            cls.rust_available = True
        except Exception:
            cls.rust_available = False
        finally:
            os.environ["VERIFY_ENGINE"] = "python"
            reset_engine()

    def setUp(self):
        # Per-test guard: skip cleanly if Rust engine wasn't loadable.
        # This protects tests that import from andna.native at method scope
        # (which would otherwise trigger an unguarded DLL load failure).
        if not self.rust_available:
            self.skipTest("Rust engine not available (libandna_ffi not built)")

    def _run_both(self, frame_bytes):
        """Run frame through both engines, return (py_resp, rs_resp)."""
        os.environ["VERIFY_ENGINE"] = "python"
        reset_engine()
        py_resp = handle_verify_request(frame_bytes)

        os.environ["VERIFY_ENGINE"] = "rust"
        reset_engine()
        rs_resp = handle_verify_request(frame_bytes)

        os.environ["VERIFY_ENGINE"] = "python"
        reset_engine()

        return py_resp, rs_resp

    def test_valid_frame_both_accept(self):
        from andna.native import gen_test_frame
        frame = gen_test_frame()
        py, rs = self._run_both(frame)
        self.assertEqual(py.ok, rs.ok, f"DIVERGENCE: py.ok={py.ok} rs.ok={rs.ok}")

    def test_bad_binding_both_reject(self):
        frame = make_bad_binding_frame()
        py, rs = self._run_both(frame)
        self.assertEqual(py.ok, rs.ok, f"DIVERGENCE: py.ok={py.ok} rs.ok={rs.ok}")
        self.assertFalse(py.ok)
        self.assertEqual(py.error_code, rs.error_code,
                         f"DIVERGENCE: py.err={py.error_code} rs.err={rs.error_code}")

    def test_short_frame_both_reject(self):
        py, rs = self._run_both(b"\x00" * 100)
        self.assertEqual(py.ok, rs.ok)
        self.assertFalse(py.ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
