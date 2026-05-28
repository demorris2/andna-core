#!/usr/bin/env python3
"""
Extract one known-pass ACVP vector and emit Rust constants suitable for
embedding into crates/ffi/src/lib.rs as the init-time ML-DSA-44 KAT.

Run AFTER tests/download_nist_acvp.py has populated the JSON.
Picks the smallest pass vector (by msg + ctx length) to minimize binary size.

Usage:
    py tests/extract_kat_for_ffi.py > kat_substitution.rs.txt
"""

import json
import sys
from pathlib import Path

VECTORS_PATH = Path(__file__).resolve().parent.parent / \
    "crates" / "mldsa44" / "tests" / "vectors" / "acvp_mldsa44_sigver.json"


def emit_const(name: str, data: bytes, indent: str = "    ") -> str:
    """Emit a Rust const array, 16 bytes per line."""
    lines = [f"const {name}: [u8; {len(data)}] = ["]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_strs = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"{indent}{hex_strs},")
    lines.append("];")
    return "\n".join(lines)


def main() -> int:
    if not VECTORS_PATH.exists():
        print(f"ERROR: {VECTORS_PATH} not found.", file=sys.stderr)
        print("Run tests/download_nist_acvp.py first.", file=sys.stderr)
        return 1

    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    if not vectors:
        print("ERROR: vector file is empty.", file=sys.stderr)
        return 1

    # Pick the smallest pass vector (minimize binary size).
    pass_vecs = [v for v in vectors if v.get("expected") is True]
    if not pass_vecs:
        print("ERROR: no pass vectors found.", file=sys.stderr)
        return 1

    pass_vecs.sort(key=lambda v: len(v["message"]) + len(v.get("context", "")))
    chosen = pass_vecs[0]

    tc_id = chosen["tcId"]
    pk = bytes.fromhex(chosen["pk"])
    msg = bytes.fromhex(chosen["message"])
    ctx = bytes.fromhex(chosen.get("context", ""))
    sig = bytes.fromhex(chosen["signature"])

    print(f"// Source:   NIST ACVP-Server FIPS 204 sigVer (external/pure)")
    print(f"// Path:     gen-val/json-files/ML-DSA-sigVer-FIPS204/")
    print(f"// tcId:     {tc_id}")
    print(f"// Expected: testPassed = true")
    print(f"// Vendored: crates/mldsa44/tests/vectors/acvp_mldsa44_sigver.json")
    print(f"// Lengths:  pk={len(pk)} msg={len(msg)} ctx={len(ctx)} sig={len(sig)}")
    print()
    print('#[cfg(feature = "oqs-backend")]')
    print(emit_const("KAT_PK", pk))
    print()
    print('#[cfg(feature = "oqs-backend")]')
    print(emit_const("KAT_MSG", msg))
    print()
    print('#[cfg(feature = "oqs-backend")]')
    print(emit_const("KAT_CTX", ctx))
    print()
    print('#[cfg(feature = "oqs-backend")]')
    print(emit_const("KAT_SIG", sig))

    return 0


if __name__ == "__main__":
    sys.exit(main())