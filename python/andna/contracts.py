"""
AN-DNA vNext Phase 1 — Contracts (Python mirror)

These constants MUST stay in sync with crates/contracts/src/lib.rs.
The test suite cross-validates against the Rust-generated C header.

DO NOT edit these values without updating the Rust contracts crate first.
"""

from __future__ import annotations

# ── Frame structure ──
MU_PRE_LEN: int = 274
TE_V1_LEN: int = 1336
TE_V2_LEN: int = 1352  # defined, NOT enabled (Phase 2+)
TE_LEN: int = TE_V1_LEN  # active alias
SIG_LEN: int = 2420
FRAME_V2_LEN: int = 4030
PK_HASH_LEN: int = 64
MU_LEN: int = 64

# ── mu_pre field offsets + lengths ──
MU_PRE_PK_HASH_OFF: int = 0
MU_PRE_PK_HASH_LEN: int = 64
MU_PRE_DOMAIN_SEP_OFF: int = 64
MU_PRE_DOMAIN_SEP_LEN: int = 9
MU_PRE_VERSION_OFF: int = 73
MU_PRE_VERSION_LEN: int = 1
MU_PRE_DEVICE_ID32_OFF: int = 74
MU_PRE_DEVICE_ID32_LEN: int = 32
MU_PRE_EPOCH_OFF: int = 106
MU_PRE_EPOCH_LEN: int = 8
MU_PRE_SID_OFF: int = 114
MU_PRE_SID_LEN: int = 32
MU_PRE_ND_OFF: int = 146
MU_PRE_ND_LEN: int = 32
MU_PRE_NS_OFF: int = 178
MU_PRE_NS_LEN: int = 32
MU_PRE_CTX_HASH_OFF: int = 210
MU_PRE_CTX_HASH_LEN: int = 32
MU_PRE_POLICY_HASH_OFF: int = 242
MU_PRE_POLICY_HASH_LEN: int = 32

# ── T_E field offsets + lengths ──
TE_RHO_OFF: int = 0
TE_RHO_LEN: int = 32
TE_T1_OFF: int = 32
TE_T1_LEN: int = 1280
TE_EPOCH_OFF: int = 1312
TE_EPOCH_LEN: int = 8
TE_DEVICE_ID16_OFF: int = 1320
TE_DEVICE_ID16_LEN: int = 16

# ── Signature field offsets + lengths ──
SIG_Z_OFF: int = 0
SIG_Z_LEN: int = 2304
SIG_H_OFF: int = 2304
SIG_H_LEN: int = 84
SIG_C_TILDE_OFF: int = 2388
SIG_C_TILDE_LEN: int = 32

# ── Domain separator ──
DOMAIN_SEP: bytes = b"ANDNAAUTH"  # 9 bytes, no hyphen, no NUL
DOMAIN_SEP_LEN: int = 9
MU_PRE_VERSION_VAL: int = 0x01

# ── Frame offsets (for unpacking) ──
FRAME_MU_PRE_OFF: int = 0
FRAME_TE_OFF: int = MU_PRE_LEN  # 274
FRAME_SIG_OFF: int = MU_PRE_LEN + TE_LEN  # 274 + 1336 = 1610

# ── FFI error codes (must match AndnaErr in crates/ffi) ──
class AndnaErr:
    OK: int = 0
    ERR_LENGTH: int = 1
    ERR_MU_PRE: int = 2
    ERR_TE: int = 3
    ERR_SIG: int = 4
    ERR_PK_HASH_MISMATCH: int = 5
    ERR_SIG_INVALID: int = 6
    ERR_EPOCH_MISMATCH: int = 7       # Directive B
    ERR_DEVICE_ID_MISMATCH: int = 8   # Directive E
    ERR_INTERNAL: int = 100

    _NAMES = {
        0: "Ok",
        1: "ErrLength",
        2: "ErrMuPre",
        3: "ErrTe",
        4: "ErrSig",
        5: "ErrPkHashMismatch",
        6: "ErrSigInvalid",
        7: "ErrEpochMismatch",
        8: "ErrDeviceIdMismatch",
        100: "ErrInternal",
    }

    @classmethod
    def name(cls, code: int) -> str:
        return cls._NAMES.get(code, f"Unknown({code})")


# ── Compile-time-equivalent assertions ──
# These mirror the const _: () assertions in the Rust contracts crate.
# If any of these fail, the Python contracts are out of sync.

def _check() -> None:
    # mu_pre field sum
    assert (
        MU_PRE_PK_HASH_LEN + MU_PRE_DOMAIN_SEP_LEN + MU_PRE_VERSION_LEN
        + MU_PRE_DEVICE_ID32_LEN + MU_PRE_EPOCH_LEN + MU_PRE_SID_LEN
        + MU_PRE_ND_LEN + MU_PRE_NS_LEN + MU_PRE_CTX_HASH_LEN
        + MU_PRE_POLICY_HASH_LEN
    ) == MU_PRE_LEN, "mu_pre field sum != MU_PRE_LEN"

    # T_E field sum
    assert (
        TE_RHO_LEN + TE_T1_LEN + TE_EPOCH_LEN + TE_DEVICE_ID16_LEN
    ) == TE_V1_LEN, "TE field sum != TE_V1_LEN"

    # Sig field sum
    assert (
        SIG_Z_LEN + SIG_H_LEN + SIG_C_TILDE_LEN
    ) == SIG_LEN, "sig field sum != SIG_LEN"

    # Frame sum
    assert MU_PRE_LEN + TE_LEN + SIG_LEN == FRAME_V2_LEN, "frame sum != FRAME_V2_LEN"

    # Offset contiguity chain (mu_pre)
    assert MU_PRE_PK_HASH_OFF == 0
    assert MU_PRE_DOMAIN_SEP_OFF == MU_PRE_PK_HASH_OFF + MU_PRE_PK_HASH_LEN
    assert MU_PRE_VERSION_OFF == MU_PRE_DOMAIN_SEP_OFF + MU_PRE_DOMAIN_SEP_LEN
    assert MU_PRE_DEVICE_ID32_OFF == MU_PRE_VERSION_OFF + MU_PRE_VERSION_LEN
    assert MU_PRE_EPOCH_OFF == MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN
    assert MU_PRE_SID_OFF == MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN
    assert MU_PRE_ND_OFF == MU_PRE_SID_OFF + MU_PRE_SID_LEN
    assert MU_PRE_NS_OFF == MU_PRE_ND_OFF + MU_PRE_ND_LEN
    assert MU_PRE_CTX_HASH_OFF == MU_PRE_NS_OFF + MU_PRE_NS_LEN
    assert MU_PRE_POLICY_HASH_OFF == MU_PRE_CTX_HASH_OFF + MU_PRE_CTX_HASH_LEN
    assert MU_PRE_POLICY_HASH_OFF + MU_PRE_POLICY_HASH_LEN == MU_PRE_LEN

    # Domain separator
    assert len(DOMAIN_SEP) == DOMAIN_SEP_LEN
    assert DOMAIN_SEP == b"ANDNAAUTH"


_check()
