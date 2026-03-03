"""
AN-DNA vNext Phase 1 — Native FFI bindings via ctypes

Loads libandna_ffi.so and exposes:
  - verify_frame_v2(frame: bytes) -> int  (AndnaErr code)
  - verify_vnext(mu_pre: bytes, te: bytes, sig: bytes) -> int
  - parse_mu_pre_header(mu_pre: bytes) -> MuPreHeader
  - gen_test_frame() -> bytes  (validly-signed 4030-byte frame)
  - strerror(code: int) -> str
  - version() -> str

Library search order:
  1. ANDNA_LIB_PATH environment variable (explicit path to .so/.dylib)
  2. ./target/release/libandna_ffi.so  (workspace dev)
  3. System ldconfig / DYLD_LIBRARY_PATH

DIRECTIVE D: All binary cryptographic buffers use POINTER(c_uint8), NOT c_char_p.
c_char_p treats bytes as null-terminated C strings, silently truncating at any
embedded 0x00 byte. This causes silent verification failures on real cryptographic
data. Only andna_strerror/andna_version use c_char_p (they return actual C strings).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .contracts import (
    FRAME_V2_LEN,
    MU_PRE_LEN,
    SIG_LEN,
    TE_LEN,
    AndnaErr,
)

logger = logging.getLogger(__name__)

# ── Type aliases for clarity ──
_uint8_p = ctypes.POINTER(ctypes.c_uint8)

# ── Library name by platform ──
_LIB_NAMES = {
    "linux": "libandna_ffi.so",
    "darwin": "libandna_ffi.dylib",
    "win32": "andna_ffi.dll",
}


class AndnaVerifyError(Exception):
    """Raised when Rust verification returns a non-Ok error code."""

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{AndnaErr.name(code)}: {message}")


class AndnaLibNotFound(Exception):
    """Raised when the native library cannot be located."""

    pass


@dataclass(frozen=True, slots=True)
class MuPreHeader:
    """Hot-path fields extracted from mu_pre for pre-crypto gating."""

    device_id32: bytes  # 32 bytes
    epoch: int  # u64
    sid: bytes  # 32 bytes


def _find_library() -> str:
    """Locate libandna_ffi using the search order documented above."""

    # 1. Explicit env var
    explicit = os.environ.get("ANDNA_LIB_PATH")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        raise AndnaLibNotFound(
            f"ANDNA_LIB_PATH={explicit} does not exist or is not a file"
        )

    # 2. Workspace dev path (relative to this file)
    import sys

    platform = sys.platform
    lib_name = _LIB_NAMES.get(platform, "libandna_ffi.so")

    # Try common relative paths from the python/ directory
    candidates = [
        Path(__file__).parent.parent.parent / "target" / "release" / lib_name,
        Path(__file__).parent.parent.parent / "target" / "debug" / lib_name,
        Path.cwd() / "target" / "release" / lib_name,
        Path.cwd() / "target" / "debug" / lib_name,
        # CI dist layout
        Path.cwd() / "dist" / "lib" / lib_name,
    ]
    for p in candidates:
        if p.is_file():
            logger.debug("Found library at %s", p)
            return str(p)

    # 3. System search
    found = ctypes.util.find_library("andna_ffi")
    if found:
        return found

    raise AndnaLibNotFound(
        f"Cannot find {lib_name}. Set ANDNA_LIB_PATH or run "
        f"'cargo build --release -p andna-ffi' first."
    )


# ── bytes → c_uint8 array conversion ──
# This is the Directive D fix: we NEVER pass raw bytes to c_char_p for
# cryptographic data. Instead we create a proper uint8 array that preserves
# all bytes including embedded NUL (0x00).

def _to_uint8_array(data: bytes) -> ctypes.Array:
    """Convert Python bytes to a ctypes c_uint8 array (safe for binary data)."""
    return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)


class _Lib:
    """Lazy-loaded singleton for the native library."""

    _instance: Optional[ctypes.CDLL] = None

    @classmethod
    def get(cls) -> ctypes.CDLL:
        if cls._instance is None:
            path = _find_library()
            logger.info("Loading andna-ffi from %s", path)
            lib = ctypes.CDLL(path)
            cls._bind(lib)
            cls._instance = lib
        return cls._instance

    @staticmethod
    def _bind(lib: ctypes.CDLL) -> None:
        """Declare argtypes/restype for all exported functions.

        DIRECTIVE D: Binary data uses POINTER(c_uint8), not c_char_p.
        Only andna_strerror/andna_version use c_char_p (actual C strings).
        """

        # int32 andna_verify_frame_v2(const uint8_t* frame, size_t len)
        lib.andna_verify_frame_v2.argtypes = [_uint8_p, ctypes.c_size_t]
        lib.andna_verify_frame_v2.restype = ctypes.c_int32

        # int32 andna_verify_vnext(
        #   const uint8_t* mu_pre, size_t mu_pre_len,
        #   const uint8_t* te, size_t te_len,
        #   const uint8_t* sig, size_t sig_len)
        lib.andna_verify_vnext.argtypes = [
            _uint8_p, ctypes.c_size_t,
            _uint8_p, ctypes.c_size_t,
            _uint8_p, ctypes.c_size_t,
        ]
        lib.andna_verify_vnext.restype = ctypes.c_int32

        # int32 andna_parse_mu_pre_header(
        #   const uint8_t* mu_pre, size_t mu_pre_len,
        #   uint8_t* out_device_id32, uint64_t* out_epoch, uint8_t* out_sid)
        lib.andna_parse_mu_pre_header.argtypes = [
            _uint8_p, ctypes.c_size_t,
            _uint8_p,
            ctypes.POINTER(ctypes.c_uint64),
            _uint8_p,
        ]
        lib.andna_parse_mu_pre_header.restype = ctypes.c_int32

        # int32 andna_gen_test_frame(uint8_t* out_ptr, uint32_t out_len)
        # Optional: only present after Phase 1.1 rebuild with real signer
        try:
            lib.andna_gen_test_frame.argtypes = [_uint8_p, ctypes.c_uint32]
            lib.andna_gen_test_frame.restype = ctypes.c_int32
        except AttributeError:
            pass  # Old DLL without gen support; gen_test_frame() will fail gracefully

        # const char* andna_strerror(int32 err)
        # This IS a C string (NUL-terminated ASCII), so c_char_p is correct here.
        lib.andna_strerror.argtypes = [ctypes.c_int32]
        lib.andna_strerror.restype = ctypes.c_char_p

        # const char* andna_version()
        # This IS a C string (NUL-terminated ASCII), so c_char_p is correct here.
        lib.andna_version.argtypes = []
        lib.andna_version.restype = ctypes.c_char_p


# ── Public API ──


def verify_frame_v2(frame: bytes) -> int:
    """
    Verify a packed v2 frame (4030 bytes).

    Returns AndnaErr code (0 = Ok).
    """
    lib = _Lib.get()
    buf = _to_uint8_array(frame)
    code = lib.andna_verify_frame_v2(buf, len(frame))
    return code


def verify_vnext(mu_pre: bytes, te: bytes, sig: bytes) -> int:
    """
    Verify mu_pre + T_E + signature individually.

    Returns AndnaErr code (0 = Ok).
    """
    lib = _Lib.get()
    mp_buf = _to_uint8_array(mu_pre)
    te_buf = _to_uint8_array(te)
    sig_buf = _to_uint8_array(sig)
    code = lib.andna_verify_vnext(
        mp_buf, len(mu_pre),
        te_buf, len(te),
        sig_buf, len(sig),
    )
    return code


def gen_test_frame() -> bytes:
    """
    Generate a validly-signed 4030-byte test frame via Rust FFI.

    The Rust side does: keygen → build T_E → build mu_pre → sign μ → pack.
    Each call produces a fresh keypair, but the frame is self-consistent
    and will pass verify_frame_v2.

    Raises RuntimeError if the native library is unavailable or gen fails.
    """
    lib = _Lib.get()
    buf = (ctypes.c_uint8 * FRAME_V2_LEN)()
    rc = lib.andna_gen_test_frame(buf, FRAME_V2_LEN)
    if rc != AndnaErr.OK:
        msg = strerror(rc) if rc > 0 else f"error code {rc}"
        raise RuntimeError(f"andna_gen_test_frame failed: {msg}")
    return bytes(buf)


def parse_mu_pre_header(mu_pre: bytes) -> MuPreHeader:
    """
    Extract hot-path fields from mu_pre for pre-crypto gating.

    Returns MuPreHeader(device_id32, epoch, sid).
    Raises AndnaVerifyError if mu_pre is malformed.
    """
    lib = _Lib.get()
    mp_buf = _to_uint8_array(mu_pre)
    out_dev = (ctypes.c_uint8 * 32)()
    out_epoch = ctypes.c_uint64(0)
    out_sid = (ctypes.c_uint8 * 32)()

    code = lib.andna_parse_mu_pre_header(
        mp_buf, len(mu_pre),
        out_dev,
        ctypes.byref(out_epoch),
        out_sid,
    )

    if code != AndnaErr.OK:
        raise AndnaVerifyError(code, strerror(code))

    return MuPreHeader(
        device_id32=bytes(out_dev),
        epoch=out_epoch.value,
        sid=bytes(out_sid),
    )


def strerror(code: int) -> str:
    """Return human-readable error string from the Rust library."""
    lib = _Lib.get()
    raw = lib.andna_strerror(code)
    return raw.decode("utf-8") if raw else f"unknown error ({code})"


def version() -> str:
    """Return the Rust library version string."""
    lib = _Lib.get()
    raw = lib.andna_version()
    return raw.decode("utf-8") if raw else "unknown"
