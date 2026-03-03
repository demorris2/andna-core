"""
AN-DNA vNext Phase 1 — Frame Packer

Assembles v2 wire frames from constituent parts. This is the Python
equivalent of andna_codec::pack_frame_v2() in the Rust crate.

Usage:
    from andna.frame_packer import pack_frame_v2, build_mu_pre

    mu_pre = build_mu_pre(
        te=te_bytes,
        device_id32=device_id,
        epoch=42,
        sid=session_id,
        n_d=device_nonce,
        n_s=server_nonce,
        ctx_hash=ctx_hash,
        policy_hash=b"\\x00" * 32,
    )

    frame = pack_frame_v2(mu_pre=mu_pre, te=te_bytes, sig=sig_bytes)
"""

from __future__ import annotations

import hashlib
import struct
from typing import Optional

from .contracts import (
    DOMAIN_SEP,
    FRAME_V2_LEN,
    MU_PRE_LEN,
    MU_PRE_CTX_HASH_LEN,
    MU_PRE_CTX_HASH_OFF,
    MU_PRE_DEVICE_ID32_LEN,
    MU_PRE_DEVICE_ID32_OFF,
    MU_PRE_DOMAIN_SEP_LEN,
    MU_PRE_DOMAIN_SEP_OFF,
    MU_PRE_EPOCH_LEN,
    MU_PRE_EPOCH_OFF,
    MU_PRE_ND_LEN,
    MU_PRE_ND_OFF,
    MU_PRE_NS_LEN,
    MU_PRE_NS_OFF,
    MU_PRE_PK_HASH_LEN,
    MU_PRE_PK_HASH_OFF,
    MU_PRE_POLICY_HASH_LEN,
    MU_PRE_POLICY_HASH_OFF,
    MU_PRE_SID_LEN,
    MU_PRE_SID_OFF,
    MU_PRE_VERSION_OFF,
    MU_PRE_VERSION_VAL,
    PK_HASH_LEN,
    SIG_LEN,
    TE_LEN,
)


def pk_hash(te: bytes) -> bytes:
    """Compute pk_hash = SHAKE256(Encode(T_E), 64)."""
    if len(te) != TE_LEN:
        raise ValueError(f"te length {len(te)} != {TE_LEN}")
    return hashlib.shake_256(te).digest(PK_HASH_LEN)


def device_id32_from_id16(device_id16: bytes) -> bytes:
    """Directive E: Derive device_id32 = SHAKE256(device_id16, 32).

    The 16-byte UUID in T_E is the native hardware root.
    The 32-byte ID in mu_pre is the mathematically expanded payload slot.
    """
    if len(device_id16) != 16:
        raise ValueError(f"device_id16 must be 16 bytes, got {len(device_id16)}")
    return hashlib.shake_256(device_id16).digest(32)


def build_mu_pre(
    *,
    te: bytes,
    device_id32: bytes,
    epoch: int,
    sid: bytes,
    n_d: bytes,
    n_s: bytes,
    ctx_hash: bytes,
    policy_hash: Optional[bytes] = None,
) -> bytes:
    """
    Build a 274-byte mu_pre buffer.

    Args:
        te: Full T_E bytes (1336 bytes). Used to compute pk_hash.
        device_id32: 32-byte device identity (hash to 32 if native is shorter).
        epoch: uint64 epoch index.
        sid: 32-byte session identifier.
        n_d: 32-byte device nonce.
        n_s: 32-byte server nonce.
        ctx_hash: 32-byte context hash (SHAKE256(Encode(ctx), 32)).
        policy_hash: 32-byte policy hash. Defaults to zeros (Phase 1).

    Returns:
        274-byte mu_pre buffer.
    """
    if len(te) != TE_LEN:
        raise ValueError(f"te must be {TE_LEN} bytes, got {len(te)}")
    if len(device_id32) != MU_PRE_DEVICE_ID32_LEN:
        raise ValueError(f"device_id32 must be {MU_PRE_DEVICE_ID32_LEN} bytes")
    if len(sid) != MU_PRE_SID_LEN:
        raise ValueError(f"sid must be {MU_PRE_SID_LEN} bytes")
    if len(n_d) != MU_PRE_ND_LEN:
        raise ValueError(f"n_d must be {MU_PRE_ND_LEN} bytes")
    if len(n_s) != MU_PRE_NS_LEN:
        raise ValueError(f"n_s must be {MU_PRE_NS_LEN} bytes")
    if len(ctx_hash) != MU_PRE_CTX_HASH_LEN:
        raise ValueError(f"ctx_hash must be {MU_PRE_CTX_HASH_LEN} bytes")

    if policy_hash is None:
        policy_hash = b"\x00" * MU_PRE_POLICY_HASH_LEN
    if len(policy_hash) != MU_PRE_POLICY_HASH_LEN:
        raise ValueError(f"policy_hash must be {MU_PRE_POLICY_HASH_LEN} bytes")

    buf = bytearray(MU_PRE_LEN)

    # pk_hash = SHAKE256(te, 64)
    h = pk_hash(te)
    buf[MU_PRE_PK_HASH_OFF : MU_PRE_PK_HASH_OFF + MU_PRE_PK_HASH_LEN] = h

    # domain separator
    buf[MU_PRE_DOMAIN_SEP_OFF : MU_PRE_DOMAIN_SEP_OFF + MU_PRE_DOMAIN_SEP_LEN] = (
        DOMAIN_SEP
    )

    # version
    buf[MU_PRE_VERSION_OFF] = MU_PRE_VERSION_VAL

    # device_id32
    buf[MU_PRE_DEVICE_ID32_OFF : MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN] = (
        device_id32
    )

    # epoch (uint64 LE)
    buf[MU_PRE_EPOCH_OFF : MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN] = struct.pack(
        "<Q", epoch
    )

    # sid
    buf[MU_PRE_SID_OFF : MU_PRE_SID_OFF + MU_PRE_SID_LEN] = sid

    # N_d
    buf[MU_PRE_ND_OFF : MU_PRE_ND_OFF + MU_PRE_ND_LEN] = n_d

    # N_s
    buf[MU_PRE_NS_OFF : MU_PRE_NS_OFF + MU_PRE_NS_LEN] = n_s

    # ctx_hash
    buf[MU_PRE_CTX_HASH_OFF : MU_PRE_CTX_HASH_OFF + MU_PRE_CTX_HASH_LEN] = ctx_hash

    # policy_hash
    buf[MU_PRE_POLICY_HASH_OFF : MU_PRE_POLICY_HASH_OFF + MU_PRE_POLICY_HASH_LEN] = (
        policy_hash
    )

    assert len(buf) == MU_PRE_LEN
    return bytes(buf)


def pack_frame_v2(*, mu_pre: bytes, te: bytes, sig: bytes) -> bytes:
    """
    Assemble a v2 wire frame: mu_pre || T_E || sig = 4030 bytes.

    All three components must be exactly the correct lengths.
    """
    if len(mu_pre) != MU_PRE_LEN:
        raise ValueError(f"mu_pre must be {MU_PRE_LEN} bytes, got {len(mu_pre)}")
    if len(te) != TE_LEN:
        raise ValueError(f"te must be {TE_LEN} bytes, got {len(te)}")
    if len(sig) != SIG_LEN:
        raise ValueError(f"sig must be {SIG_LEN} bytes, got {len(sig)}")

    frame = mu_pre + te + sig
    assert len(frame) == FRAME_V2_LEN
    return frame


def unpack_frame_v2(frame: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Unpack a v2 wire frame into (mu_pre, te, sig).

    Returns:
        Tuple of (mu_pre[274], te[1336], sig[2420]).

    Raises:
        ValueError if frame length != 4030.
    """
    if len(frame) != FRAME_V2_LEN:
        raise ValueError(f"frame must be {FRAME_V2_LEN} bytes, got {len(frame)}")

    mu_pre = frame[0:MU_PRE_LEN]
    te = frame[MU_PRE_LEN : MU_PRE_LEN + TE_LEN]
    sig = frame[MU_PRE_LEN + TE_LEN : MU_PRE_LEN + TE_LEN + SIG_LEN]

    return mu_pre, te, sig
