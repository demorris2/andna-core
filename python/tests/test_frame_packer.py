"""
Tests for andna.frame_packer — mu_pre construction, frame pack/unpack,
and KAT parity with the Rust transcript tests.
"""

import hashlib

import pytest
from andna.contracts import (
    DOMAIN_SEP,
    FRAME_V2_LEN,
    MU_PRE_DEVICE_ID32_OFF,
    MU_PRE_DEVICE_ID32_LEN,
    MU_PRE_DOMAIN_SEP_OFF,
    MU_PRE_DOMAIN_SEP_LEN,
    MU_PRE_EPOCH_OFF,
    MU_PRE_EPOCH_LEN,
    MU_PRE_LEN,
    MU_PRE_PK_HASH_OFF,
    MU_PRE_VERSION_OFF,
    MU_PRE_VERSION_VAL,
    PK_HASH_LEN,
    SIG_LEN,
    TE_LEN,
)
from andna.frame_packer import (
    build_mu_pre,
    pack_frame_v2,
    pk_hash,
    unpack_frame_v2,
)


# ── Fixtures ──

def _make_te_patterned() -> bytes:
    """Build KAT-T1 T_E: rho=01..20, t1=0xAA×1280, epoch=5 LE, id16=0xBB×16."""
    te = bytearray(TE_LEN)
    for i in range(32):
        te[i] = i + 1
    te[32:32 + 1280] = bytes([0xAA] * 1280)
    te[1312:1312 + 8] = (5).to_bytes(8, "little")
    te[1320:1320 + 16] = bytes([0xBB] * 16)
    return bytes(te)


# ── pk_hash tests ──

class TestPkHash:
    def test_pk_hash_zeros(self):
        """KAT-T0: pk_hash(zeros) must match Rust KAT vector."""
        te = bytes(TE_LEN)
        h = pk_hash(te)
        assert len(h) == PK_HASH_LEN
        assert h[:8] == bytes.fromhex("0f32d8b356852704")

    def test_pk_hash_patterned(self):
        """KAT-T1: pk_hash(patterned_te) must match Rust KAT vector."""
        te = _make_te_patterned()
        h = pk_hash(te)
        assert h[:8] == bytes.fromhex("f4338086d8c1148d")

    def test_pk_hash_deterministic(self):
        te = bytes([0x42] * TE_LEN)
        assert pk_hash(te) == pk_hash(te)

    def test_pk_hash_wrong_len(self):
        with pytest.raises(ValueError, match="te length"):
            pk_hash(b"\x00" * 100)


# ── build_mu_pre tests ──

class TestBuildMuPre:
    def test_length(self):
        te = bytes(TE_LEN)
        mp = build_mu_pre(
            te=te,
            device_id32=b"\xCC" * 32,
            epoch=5,
            sid=b"\xDD" * 32,
            n_d=b"\xEE" * 32,
            n_s=b"\xFF" * 32,
            ctx_hash=b"\x11" * 32,
        )
        assert len(mp) == MU_PRE_LEN

    def test_pk_hash_binding(self):
        """mu_pre[0:64] must equal SHAKE256(te, 64)."""
        te = _make_te_patterned()
        mp = build_mu_pre(
            te=te,
            device_id32=b"\xCC" * 32,
            epoch=5,
            sid=b"\xDD" * 32,
            n_d=b"\xEE" * 32,
            n_s=b"\xFF" * 32,
            ctx_hash=b"\x11" * 32,
        )
        expected = hashlib.shake_256(te).digest(PK_HASH_LEN)
        assert mp[MU_PRE_PK_HASH_OFF : MU_PRE_PK_HASH_OFF + PK_HASH_LEN] == expected

    def test_domain_sep(self):
        te = bytes(TE_LEN)
        mp = build_mu_pre(
            te=te,
            device_id32=b"\x00" * 32,
            epoch=0,
            sid=b"\x00" * 32,
            n_d=b"\x00" * 32,
            n_s=b"\x00" * 32,
            ctx_hash=b"\x00" * 32,
        )
        assert mp[MU_PRE_DOMAIN_SEP_OFF : MU_PRE_DOMAIN_SEP_OFF + MU_PRE_DOMAIN_SEP_LEN] == DOMAIN_SEP

    def test_version_byte(self):
        te = bytes(TE_LEN)
        mp = build_mu_pre(
            te=te,
            device_id32=b"\x00" * 32,
            epoch=0,
            sid=b"\x00" * 32,
            n_d=b"\x00" * 32,
            n_s=b"\x00" * 32,
            ctx_hash=b"\x00" * 32,
        )
        assert mp[MU_PRE_VERSION_OFF] == MU_PRE_VERSION_VAL

    def test_epoch_le_encoding(self):
        te = bytes(TE_LEN)
        mp = build_mu_pre(
            te=te,
            device_id32=b"\x00" * 32,
            epoch=0x0102030405060708,
            sid=b"\x00" * 32,
            n_d=b"\x00" * 32,
            n_s=b"\x00" * 32,
            ctx_hash=b"\x00" * 32,
        )
        epoch_bytes = mp[MU_PRE_EPOCH_OFF : MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN]
        assert epoch_bytes == bytes([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01])

    def test_kat_t2_mu(self):
        """KAT-T2: mu from patterned mu_pre must match Rust KAT vector."""
        te = _make_te_patterned()
        mp = build_mu_pre(
            te=te,
            device_id32=b"\xCC" * 32,
            epoch=5,
            sid=b"\xDD" * 32,
            n_d=b"\xEE" * 32,
            n_s=b"\xFF" * 32,
            ctx_hash=b"\x11" * 32,
            policy_hash=b"\x00" * 32,
        )
        mu = hashlib.shake_256(mp).digest(64)
        assert mu[:8] == bytes.fromhex("a508efbf680d8c7f")

    def test_policy_hash_default_zeros(self):
        te = bytes(TE_LEN)
        mp = build_mu_pre(
            te=te,
            device_id32=b"\x00" * 32,
            epoch=0,
            sid=b"\x00" * 32,
            n_d=b"\x00" * 32,
            n_s=b"\x00" * 32,
            ctx_hash=b"\x00" * 32,
        )
        from andna.contracts import MU_PRE_POLICY_HASH_OFF, MU_PRE_POLICY_HASH_LEN
        assert mp[MU_PRE_POLICY_HASH_OFF:MU_PRE_POLICY_HASH_OFF + MU_PRE_POLICY_HASH_LEN] == b"\x00" * 32


# ── pack/unpack roundtrip tests ──

class TestPackUnpack:
    def test_roundtrip(self):
        te = _make_te_patterned()
        mp = build_mu_pre(
            te=te,
            device_id32=b"\xCC" * 32,
            epoch=5,
            sid=b"\xDD" * 32,
            n_d=b"\xEE" * 32,
            n_s=b"\xFF" * 32,
            ctx_hash=b"\x11" * 32,
        )
        sig = b"\xAA" * SIG_LEN
        frame = pack_frame_v2(mu_pre=mp, te=te, sig=sig)
        assert len(frame) == FRAME_V2_LEN

        mp2, te2, sig2 = unpack_frame_v2(frame)
        assert mp2 == mp
        assert te2 == te
        assert sig2 == sig

    def test_pack_wrong_mu_pre_len(self):
        with pytest.raises(ValueError, match="mu_pre"):
            pack_frame_v2(mu_pre=b"\x00" * 100, te=bytes(TE_LEN), sig=bytes(SIG_LEN))

    def test_pack_wrong_te_len(self):
        with pytest.raises(ValueError, match="te"):
            pack_frame_v2(mu_pre=bytes(MU_PRE_LEN), te=b"\x00" * 100, sig=bytes(SIG_LEN))

    def test_pack_wrong_sig_len(self):
        with pytest.raises(ValueError, match="sig"):
            pack_frame_v2(mu_pre=bytes(MU_PRE_LEN), te=bytes(TE_LEN), sig=b"\x00" * 100)

    def test_unpack_wrong_len(self):
        with pytest.raises(ValueError, match="frame"):
            unpack_frame_v2(b"\x00" * 100)
