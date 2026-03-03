"""
Tests for andna.native — direct ctypes binding to libandna_ffi.

These tests are skipped if the Rust library hasn't been built.
Run 'cargo build --release -p andna-ffi' first.
"""

import pytest

# Safe imports that do not depend on the DLL
from andna.contracts import AndnaErr, FRAME_V2_LEN, MU_PRE_LEN, TE_LEN, SIG_LEN
from andna.frame_packer import build_mu_pre, pack_frame_v2, device_id32_from_id16

try:
    from andna.native import (
        AndnaLibNotFound,
        AndnaVerifyError,
        MuPreHeader,
        parse_mu_pre_header,
        strerror,
        verify_frame_v2,
        verify_vnext,
        version,
    )

    _LIB_AVAILABLE = True
    try:
        version()
    except Exception:
        _LIB_AVAILABLE = False
except Exception:
    _LIB_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _LIB_AVAILABLE, reason="libandna_ffi not built")


class TestVersion:
    def test_returns_semver(self):
        v = version()
        assert "." in v
        parts = v.split(".")
        assert len(parts) >= 2

    def test_non_empty(self):
        assert len(version()) > 0


class TestStrerror:
    def test_ok_message(self):
        assert "ok" in strerror(AndnaErr.OK).lower()

    def test_length_message(self):
        assert "length" in strerror(AndnaErr.ERR_LENGTH).lower()

    def test_pk_hash_message(self):
        assert "pk_hash" in strerror(AndnaErr.ERR_PK_HASH_MISMATCH).lower()

    def test_sig_invalid_message(self):
        msg = strerror(AndnaErr.ERR_SIG_INVALID)
        assert "signature" in msg.lower()


class TestVerifyFrameV2:
# test_valid_frame — replace the whole method body:
    def test_valid_frame(self):
        from andna.native import gen_test_frame
        frame = gen_test_frame()
        code = verify_frame_v2(frame)
        assert code == AndnaErr.OK

    def test_short_frame(self):
        code = verify_frame_v2(b"\x00" * 100)
        assert code == AndnaErr.ERR_LENGTH

    def test_empty_frame(self):
        code = verify_frame_v2(b"")
        assert code == AndnaErr.ERR_LENGTH

    def test_pk_hash_mismatch(self):
        te = bytes(TE_LEN)
        # Create a valid payload (Domain Sep + Epoch + ID) but corrupt the PK Hash
        valid_id32 = device_id32_from_id16(te[1320:1336])
        mp = build_mu_pre(
            te=te, device_id32=valid_id32, epoch=0,
            sid=b"\x00" * 32, n_d=b"\x00" * 32, n_s=b"\x00" * 32,
            ctx_hash=b"\x00" * 32,
        )
        # Tamper with the first 32 bytes (which is the PK Hash)
        tampered_mp = b"\xFF" * 32 + mp[32:]
        frame = pack_frame_v2(mu_pre=tampered_mp, te=te, sig=bytes(SIG_LEN))
        
        code = verify_frame_v2(frame)
        assert code == AndnaErr.ERR_PK_HASH_MISMATCH


class TestVerifyVnext:
    def test_valid_components(self):
        from andna.native import gen_test_frame
        frame = gen_test_frame()
        mu_pre = frame[:MU_PRE_LEN]
        te = frame[MU_PRE_LEN:MU_PRE_LEN + TE_LEN]
        sig = frame[MU_PRE_LEN + TE_LEN:]
        code = verify_vnext(mu_pre, te, sig)
        assert code == AndnaErr.OK

    def test_wrong_mu_pre_len(self):
        code = verify_vnext(b"\x00" * 100, bytes(TE_LEN), bytes(SIG_LEN))
        assert code == AndnaErr.ERR_LENGTH

    def test_wrong_te_len(self):
        code = verify_vnext(bytes(MU_PRE_LEN), b"\x00" * 100, bytes(SIG_LEN))
        assert code == AndnaErr.ERR_LENGTH


class TestParseMuPreHeader:
    def test_extracts_fields(self):
        te = bytes(TE_LEN)
        dev_id = b"\xCC" * 32
        sid = b"\xDD" * 32
        mp = build_mu_pre(
            te=te, device_id32=dev_id, epoch=42,
            sid=sid, n_d=b"\xEE" * 32, n_s=b"\xFF" * 32,
            ctx_hash=b"\x11" * 32,
        )
        hdr = parse_mu_pre_header(mp)
        assert isinstance(hdr, MuPreHeader)
        assert hdr.device_id32 == dev_id
        assert hdr.epoch == 42
        assert hdr.sid == sid

    def test_wrong_len_raises(self):
        with pytest.raises(AndnaVerifyError):
            parse_mu_pre_header(b"\x00" * 100)
