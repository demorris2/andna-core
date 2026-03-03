#!/usr/bin/env python3
"""
Generate ACVP-format ML-DSA-44 sigVer test vectors using liboqs.

Prerequisites:
    pip install liboqs-python   (or ensure liboqs C lib is installed)

Usage:
    python generate_acvp_vectors.py > crates/mldsa44/tests/vectors/acvp_mldsa44_sigver.json

Generates 10 test vectors:
    - 5 valid (sign with correct sk, verify with correct pk → expect true)
    - 3 tampered signature (flip bytes → expect false)
    - 1 wrong public key (sign with sk1, verify with pk2 → expect false)
    - 1 wrong message (sign msg1, verify msg2 → expect false)
"""

import json
import os
import sys

try:
    import oqs
except ImportError:
    print("ERROR: liboqs-python not installed. Run: pip install liboqs-python", file=sys.stderr)
    sys.exit(1)


def generate_vectors():
    signer = oqs.Signature("ML-DSA-44")
    pk1 = signer.generate_keypair()

    # Second keypair for cross-key test
    signer2 = oqs.Signature("ML-DSA-44")
    pk2 = signer2.generate_keypair()

    vectors = []
    tc_id = 1

    # ── 5 valid vectors with different message lengths ──
    test_messages = [
        b"",                          # empty
        b"\x42" * 64,                 # 64 bytes (μ-length)
        b"ANDNA-ACVP-TEST-MESSAGE",   # ASCII
        os.urandom(128),              # 128 random bytes
        os.urandom(1000),             # 1000 random bytes
    ]

    for msg in test_messages:
        sig = signer.sign(msg)
        vectors.append({
            "tcId": tc_id,
            "pk": pk1.hex(),
            "message": msg.hex(),
            "signature": sig.hex(),
            "expected": True,
        })
        tc_id += 1

    # ── 3 tampered signature vectors ──
    msg_for_tamper = b"\xDE" * 64
    good_sig = signer.sign(msg_for_tamper)

    # Tamper byte 0
    tampered = bytearray(good_sig)
    tampered[0] ^= 0xFF
    vectors.append({
        "tcId": tc_id,
        "pk": pk1.hex(),
        "message": msg_for_tamper.hex(),
        "signature": bytes(tampered).hex(),
        "expected": False,
    })
    tc_id += 1

    # Tamper byte 100
    tampered = bytearray(good_sig)
    tampered[100] ^= 0xFF
    vectors.append({
        "tcId": tc_id,
        "pk": pk1.hex(),
        "message": msg_for_tamper.hex(),
        "signature": bytes(tampered).hex(),
        "expected": False,
    })
    tc_id += 1

    # Tamper last byte
    tampered = bytearray(good_sig)
    tampered[-1] ^= 0xFF
    vectors.append({
        "tcId": tc_id,
        "pk": pk1.hex(),
        "message": msg_for_tamper.hex(),
        "signature": bytes(tampered).hex(),
        "expected": False,
    })
    tc_id += 1

    # ── 1 wrong public key ──
    msg_cross = b"cross-key verification test"
    sig_cross = signer.sign(msg_cross)  # signed with sk1
    vectors.append({
        "tcId": tc_id,
        "pk": pk2.hex(),               # verify with pk2 → should fail
        "message": msg_cross.hex(),
        "signature": sig_cross.hex(),
        "expected": False,
    })
    tc_id += 1

    # ── 1 wrong message ──
    msg_a = b"message A"
    sig_a = signer.sign(msg_a)
    vectors.append({
        "tcId": tc_id,
        "pk": pk1.hex(),
        "message": b"message B".hex(),  # wrong message
        "signature": sig_a.hex(),
        "expected": False,
    })
    tc_id += 1

    return vectors


def main():
    vectors = generate_vectors()
    print(json.dumps(vectors, indent=2))
    print(f"\nGenerated {len(vectors)} vectors ({sum(1 for v in vectors if v['expected'])} pass, "
          f"{sum(1 for v in vectors if not v['expected'])} fail)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
