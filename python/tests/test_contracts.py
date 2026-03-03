"""
Tests for andna.contracts — validates Python constants match Rust.

These tests import the module (which runs _check() on import) and
verify specific values that are most likely to drift.
"""

import pytest
from andna.contracts import (
    DOMAIN_SEP,
    DOMAIN_SEP_LEN,
    FRAME_V2_LEN,
    MU_PRE_LEN,
    MU_PRE_VERSION_VAL,
    PK_HASH_LEN,
    SIG_LEN,
    TE_LEN,
    TE_V1_LEN,
    TE_V2_LEN,
    AndnaErr,
)


class TestContractsValues:
    """Locked constant values — canary tests for drift."""

    def test_mu_pre_len(self):
        assert MU_PRE_LEN == 274

    def test_te_v1_len(self):
        assert TE_V1_LEN == 1336

    def test_te_v2_len(self):
        assert TE_V2_LEN == 1352

    def test_te_len_is_v1(self):
        assert TE_LEN == TE_V1_LEN, "TE_LEN must be V1 for Phase 1"

    def test_sig_len(self):
        assert SIG_LEN == 2420

    def test_frame_v2_len(self):
        assert FRAME_V2_LEN == 4030

    def test_frame_v2_is_sum(self):
        assert MU_PRE_LEN + TE_LEN + SIG_LEN == FRAME_V2_LEN

    def test_pk_hash_len(self):
        assert PK_HASH_LEN == 64


class TestDomainSeparator:
    def test_domain_sep_value(self):
        assert DOMAIN_SEP == b"ANDNAAUTH"

    def test_domain_sep_no_hyphen(self):
        assert b"-" not in DOMAIN_SEP

    def test_domain_sep_no_nul(self):
        assert b"\x00" not in DOMAIN_SEP

    def test_domain_sep_len(self):
        assert len(DOMAIN_SEP) == DOMAIN_SEP_LEN == 9

    def test_domain_sep_hex(self):
        expected = bytes([0x41, 0x4E, 0x44, 0x4E, 0x41, 0x41, 0x55, 0x54, 0x48])
        assert DOMAIN_SEP == expected


class TestVersionByte:
    def test_version_val(self):
        assert MU_PRE_VERSION_VAL == 0x01


class TestAndnaErr:
    def test_ok_is_zero(self):
        assert AndnaErr.OK == 0

    def test_all_codes_have_names(self):
        for code in [0, 1, 2, 3, 4, 5, 6, 7, 8, 100]:
            name = AndnaErr.name(code)
            assert name != f"Unknown({code})", f"code {code} has no name"

    def test_unknown_code(self):
        assert "Unknown" in AndnaErr.name(999)
