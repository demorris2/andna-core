"""
Tests for andna.engine — Python engine (always) + Rust engine (if lib built).

Run with:
    VERIFY_ENGINE=python pytest tests/test_engine.py
    VERIFY_ENGINE=rust   pytest tests/test_engine.py    # requires cargo build --release -p andna-ffi
"""

import hashlib
import os
import struct

import pytest
from andna.contracts import (
    FRAME_V2_LEN,
    MU_PRE_LEN,
    PK_HASH_LEN,
    SIG_LEN,
    TE_LEN,
    AndnaErr,
    DOMAIN_SEP,
    DOMAIN_SEP_LEN,
    MU_PRE_DOMAIN_SEP_OFF,
    MU_PRE_VERSION_OFF,
    MU_PRE_VERSION_VAL,
    MU_PRE_EPOCH_OFF,
    MU_PRE_EPOCH_LEN,
    TE_DEVICE_ID16_LEN,
)
from andna.engine import PythonEngine, VerifyResult, get_engine, reset_engine
from andna.frame_packer import build_mu_pre, pack_frame_v2, device_id32_from_id16


# ── Helpers ──


def _make_valid_frame() -> bytes:
    """Build a frame that passes ALL checks (Directives A, B, E, pk_hash)."""
    te = bytes(TE_LEN)  # all zeros (device_id16 = 16 zeros, epoch = 0)
    device_id16 = te[1320:1336]  # zeros
    device_id32 = device_id32_from_id16(device_id16)  # Directive E
    mp = build_mu_pre(
        te=te,
        device_id32=device_id32,   # Directive E: derived
        epoch=0,                   # Directive B: must match te epoch (0)
        sid=b"\x00" * 32,
        n_d=b"\x00" * 32,
        n_s=b"\x00" * 32,
        ctx_hash=b"\x00" * 32,
    )
    sig = b"\x00" * SIG_LEN
    return pack_frame_v2(mu_pre=mp, te=te, sig=sig)

def _make_real_frame():
    """Generate a real ML-DSA-44 signed frame via Rust FFI."""
    from andna.native import gen_test_frame
    return gen_test_frame()


def _make_bad_binding_frame() -> bytes:
    """Build a frame where pk_hash does NOT match T_E.

    Domain sep and version are set correctly so Directive A passes,
    ensuring pk_hash mismatch is what triggers the reject.
    """
    te = bytes(TE_LEN)
    mu_pre = bytearray(MU_PRE_LEN)
    # pk_hash = zeros, which != SHAKE256(zeros_te, 64)
    # Set domain sep and version so Directive A passes
    mu_pre[MU_PRE_DOMAIN_SEP_OFF:MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN] = DOMAIN_SEP
    mu_pre[MU_PRE_VERSION_OFF] = MU_PRE_VERSION_VAL
    sig = b"\x00" * SIG_LEN
    return bytes(mu_pre) + te + sig


# ── Python Engine Tests (always run) ──


class TestPythonEngine:
    def setup_method(self):
        self.engine = PythonEngine()

    def test_name(self):
        assert self.engine.name == "python"

    def test_valid_frame_passes(self):
        frame = _make_valid_frame()
        result = self.engine.verify_frame_v2(frame)
        assert result.ok is True
        assert result.error_code == AndnaErr.OK

    def test_wrong_length_rejected(self):
        result = self.engine.verify_frame_v2(b"\x00" * 100)
        assert result.ok is False
        assert result.error_code == AndnaErr.ERR_LENGTH

    def test_pk_hash_mismatch_rejected(self):
        frame = _make_bad_binding_frame()
        result = self.engine.verify_frame_v2(frame)
        assert result.ok is False
        assert result.error_code == AndnaErr.ERR_PK_HASH_MISMATCH

    def test_verify_vnext_components(self):
        te = bytes(TE_LEN)
        device_id16 = te[1320:1336]  # zeros
        device_id32 = device_id32_from_id16(device_id16)
        mp = build_mu_pre(
            te=te,
            device_id32=device_id32,  # Directive E: derived
            epoch=0,                  # Directive B: must match T_E epoch (0)
            sid=b"\xDD" * 32,
            n_d=b"\xEE" * 32,
            n_s=b"\xFF" * 32,
            ctx_hash=b"\x11" * 32,
        )
        sig = b"\x00" * SIG_LEN
        result = self.engine.verify_vnext(mp, te, sig)
        assert result.ok is True

    def test_verify_vnext_wrong_mu_pre_len(self):
        result = self.engine.verify_vnext(
            b"\x00" * 100, bytes(TE_LEN), bytes(SIG_LEN)
        )
        assert result.ok is False
        assert result.error_code == AndnaErr.ERR_MU_PRE

    def test_verify_vnext_wrong_te_len(self):
        result = self.engine.verify_vnext(
            bytes(MU_PRE_LEN), b"\x00" * 100, bytes(SIG_LEN)
        )
        assert result.ok is False
        assert result.error_code == AndnaErr.ERR_TE

    def test_verify_vnext_wrong_sig_len(self):
        result = self.engine.verify_vnext(
            bytes(MU_PRE_LEN), bytes(TE_LEN), b"\x00" * 100
        )
        assert result.ok is False
        assert result.error_code == AndnaErr.ERR_SIG


# ── Rust Engine Tests (only if lib is available) ──


def _rust_available() -> bool:
    """Check if libandna_ffi is available."""
    try:
        from andna.native import version
        version()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _rust_available(), reason="libandna_ffi not built")
class TestRustEngine:
    def setup_method(self):
        reset_engine()
        self.engine = get_engine(force="rust")

    def teardown_method(self):
        reset_engine()

    def test_name(self):
        assert self.engine.name == "rust"

    def test_valid_frame_passes(self):
        frame = _make_real_frame()
        result = self.engine.verify_frame_v2(frame)
        assert result.ok is True

    def test_wrong_length_rejected(self):
        result = self.engine.verify_frame_v2(b"\x00" * 100)
        assert result.ok is False
        assert result.error_code == AndnaErr.ERR_LENGTH

    def test_pk_hash_mismatch_rejected(self):
        frame = _make_bad_binding_frame()
        result = self.engine.verify_frame_v2(frame)
        assert result.ok is False
        assert result.error_code == AndnaErr.ERR_PK_HASH_MISMATCH


# ── Engine Factory Tests ──


class TestEngineFactory:
    def setup_method(self):
        reset_engine()

    def teardown_method(self):
        reset_engine()

    def test_default_is_python(self):
        # Clear env var to get default
        old = os.environ.pop("VERIFY_ENGINE", None)
        try:
            engine = get_engine()
            assert engine.name == "python"
        finally:
            if old is not None:
                os.environ["VERIFY_ENGINE"] = old

    def test_force_python(self):
        engine = get_engine(force="python")
        assert engine.name == "python"

    def test_invalid_engine_raises(self):
        with pytest.raises(ValueError, match="Unknown"):
            get_engine(force="bogus")


# ── Differential Tests (Python vs Rust, if available) ──


@pytest.mark.skipif(not _rust_available(), reason="libandna_ffi not built")
class TestDifferential:
    """Ensure Python and Rust engines produce the same result for the same inputs."""

    def setup_method(self):
        reset_engine()
        self.py_engine = PythonEngine()
        self.rs_engine = get_engine(force="rust")

    def teardown_method(self):
        reset_engine()

    def test_valid_frame_both_pass(self):
        frame = _make_real_frame()
        py_result = self.py_engine.verify_frame_v2(frame)
        rs_result = self.rs_engine.verify_frame_v2(frame)
        assert py_result.ok == rs_result.ok == True

    def test_bad_binding_both_reject(self):
        frame = _make_bad_binding_frame()
        py_result = self.py_engine.verify_frame_v2(frame)
        rs_result = self.rs_engine.verify_frame_v2(frame)
        assert py_result.ok == rs_result.ok == False
        assert py_result.error_code == rs_result.error_code == AndnaErr.ERR_PK_HASH_MISMATCH

    def test_short_frame_both_reject(self):
        short = b"\x00" * 100
        py_result = self.py_engine.verify_frame_v2(short)
        rs_result = self.rs_engine.verify_frame_v2(short)
        assert py_result.ok == rs_result.ok == False
