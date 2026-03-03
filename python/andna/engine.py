"""
AN-DNA vNext Phase 1 — Verify Engine Router

Selects the verification backend based on the VERIFY_ENGINE environment variable:

    VERIFY_ENGINE=python  (default)  Pure Python implementation
    VERIFY_ENGINE=rust               Rust FFI via ctypes (libandna_ffi.so)

Usage:
    from andna.engine import get_engine

    engine = get_engine()
    result = engine.verify_frame_v2(frame_bytes)
    # result.ok: bool, result.error: Optional[str]

The engine interface is a thin protocol so the verifier service doesn't
need to know which backend is active. Feature flag change requires no
code change — just set the env var and restart.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Optional, Protocol

from .contracts import (
    FRAME_V2_LEN,
    MU_PRE_LEN,
    PK_HASH_LEN,
    SIG_LEN,
    TE_LEN,
    AndnaErr,
    FRAME_MU_PRE_OFF,
    FRAME_TE_OFF,
    FRAME_SIG_OFF,
    DOMAIN_SEP,
    DOMAIN_SEP_LEN,
    MU_PRE_DOMAIN_SEP_OFF,
    MU_PRE_VERSION_OFF,
    MU_PRE_VERSION_VAL,
    MU_PRE_EPOCH_OFF,
    MU_PRE_EPOCH_LEN,
    MU_PRE_DEVICE_ID32_OFF,
    MU_PRE_DEVICE_ID32_LEN,
    TE_EPOCH_OFF,
    TE_EPOCH_LEN,
    TE_DEVICE_ID16_OFF,
    TE_DEVICE_ID16_LEN,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Uniform result type for both engines."""

    ok: bool
    error_code: int = 0  # AndnaErr code
    error_msg: Optional[str] = None


class VerifyEngine(Protocol):
    """Protocol that both Python and Rust backends implement."""

    def verify_frame_v2(self, frame: bytes) -> VerifyResult: ...

    def verify_vnext(
        self, mu_pre: bytes, te: bytes, sig: bytes
    ) -> VerifyResult: ...

    @property
    def name(self) -> str: ...


# ── Python Engine (pure, no native deps) ──


class PythonEngine:
    """Pure-Python verification engine.

    Performs transcript checks (pk_hash binding, mu computation) in Python.
    ML-DSA-44 signature verification is stubbed (always passes) until a
    pure-Python or native implementation is wired in.
    """

    @property
    def name(self) -> str:
        return "python"

    def verify_frame_v2(self, frame: bytes) -> VerifyResult:
        if len(frame) != FRAME_V2_LEN:
            return VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_LENGTH,
                error_msg=f"frame length {len(frame)} != {FRAME_V2_LEN}",
            )

        mu_pre = frame[FRAME_MU_PRE_OFF : FRAME_MU_PRE_OFF + MU_PRE_LEN]
        te = frame[FRAME_TE_OFF : FRAME_TE_OFF + TE_LEN]
        sig = frame[FRAME_SIG_OFF : FRAME_SIG_OFF + SIG_LEN]

        return self.verify_vnext(mu_pre, te, sig)

    def verify_vnext(
        self, mu_pre: bytes, te: bytes, sig: bytes
    ) -> VerifyResult:
        # Length checks
        if len(mu_pre) != MU_PRE_LEN:
            return VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_MU_PRE,
                error_msg=f"mu_pre length {len(mu_pre)} != {MU_PRE_LEN}",
            )
        if len(te) != TE_LEN:
            return VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_TE,
                error_msg=f"te length {len(te)} != {TE_LEN}",
            )
        if len(sig) != SIG_LEN:
            return VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_SIG,
                error_msg=f"sig length {len(sig)} != {SIG_LEN}",
            )

        # Step 0 (Directive A): Validate mu_pre structure
        ds = mu_pre[MU_PRE_DOMAIN_SEP_OFF : MU_PRE_DOMAIN_SEP_OFF + DOMAIN_SEP_LEN]
        if ds != DOMAIN_SEP:
            return VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_MU_PRE,
                error_msg=f"domain separator mismatch: {ds!r} != {DOMAIN_SEP!r}",
            )
        if mu_pre[MU_PRE_VERSION_OFF] != MU_PRE_VERSION_VAL:
            return VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_MU_PRE,
                error_msg=f"version byte {mu_pre[MU_PRE_VERSION_OFF]:#04x} != {MU_PRE_VERSION_VAL:#04x}",
            )

        # Step 1: pk_hash binding check
        expected_pk_hash = hashlib.shake_256(te).digest(PK_HASH_LEN)
        embedded_pk_hash = mu_pre[0:PK_HASH_LEN]
        if expected_pk_hash != embedded_pk_hash:
            return VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_PK_HASH_MISMATCH,
                error_msg="pk_hash binding mismatch",
            )

        # Step 2 (Directive B): Epoch correlation
        mp_epoch = mu_pre[MU_PRE_EPOCH_OFF : MU_PRE_EPOCH_OFF + MU_PRE_EPOCH_LEN]
        te_epoch = te[TE_EPOCH_OFF : TE_EPOCH_OFF + TE_EPOCH_LEN]
        if mp_epoch != te_epoch:
            return VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_EPOCH_MISMATCH,
                error_msg="mu_pre.epoch != T_E.epoch",
            )

        # Step 3 (Directive E): Device ID duality
        embedded_id32 = mu_pre[MU_PRE_DEVICE_ID32_OFF : MU_PRE_DEVICE_ID32_OFF + MU_PRE_DEVICE_ID32_LEN]
        device_id16 = te[TE_DEVICE_ID16_OFF : TE_DEVICE_ID16_OFF + TE_DEVICE_ID16_LEN]
        expected_id32 = hashlib.shake_256(device_id16).digest(MU_PRE_DEVICE_ID32_LEN)
        if embedded_id32 != expected_id32:
            return VerifyResult(
                ok=False,
                error_code=AndnaErr.ERR_DEVICE_ID_MISMATCH,
                error_msg="device_id32 != SHAKE256(device_id16, 32)",
            )

        # Step 4: ML-DSA-44 verify — STUB (always passes in Python engine)
        # TODO: wire real ML-DSA-44 verify here
        logger.debug("ML-DSA-44 verify: STUB (always passes)")

        return VerifyResult(ok=True, error_code=AndnaErr.OK)


# ── Rust Engine (native FFI via ctypes) ──


class RustEngine:
    """Rust FFI verification engine via ctypes."""

    def __init__(self) -> None:
        # Import lazily so we don't fail at import time if lib not built
        from . import native

        self._native = native
        logger.info("Rust engine initialized: libandna_ffi %s", native.version())

    @property
    def name(self) -> str:
        return "rust"

    def verify_frame_v2(self, frame: bytes) -> VerifyResult:
        code = self._native.verify_frame_v2(frame)
        if code == AndnaErr.OK:
            return VerifyResult(ok=True)
        return VerifyResult(
            ok=False,
            error_code=code,
            error_msg=self._native.strerror(code),
        )

    def verify_vnext(
        self, mu_pre: bytes, te: bytes, sig: bytes
    ) -> VerifyResult:
        code = self._native.verify_vnext(mu_pre, te, sig)
        if code == AndnaErr.OK:
            return VerifyResult(ok=True)
        return VerifyResult(
            ok=False,
            error_code=code,
            error_msg=self._native.strerror(code),
        )


# ── Engine Factory ──

_ENGINE_MAP = {
    "python": PythonEngine,
    "rust": RustEngine,
}

_cached_engine: Optional[VerifyEngine] = None


def get_engine(force: Optional[str] = None) -> VerifyEngine:
    """
    Return the configured verification engine.

    Args:
        force: Override VERIFY_ENGINE for testing. One of "python" or "rust".

    The engine is cached after first call (singleton per process).
    """
    global _cached_engine
    if _cached_engine is not None and force is None:
        return _cached_engine

    engine_name = force or os.environ.get("VERIFY_ENGINE", "python")
    engine_name = engine_name.lower().strip()

    if engine_name not in _ENGINE_MAP:
        raise ValueError(
            f"Unknown VERIFY_ENGINE={engine_name!r}. "
            f"Valid: {', '.join(_ENGINE_MAP.keys())}"
        )

    engine = _ENGINE_MAP[engine_name]()
    logger.info("Verify engine: %s", engine.name)

    if force is None:
        _cached_engine = engine
    return engine


def reset_engine() -> None:
    """Clear cached engine (for testing)."""
    global _cached_engine
    _cached_engine = None
