#!/usr/bin/env python3
"""
Download official NIST ACVP ML-DSA-44 sigVer vectors (external/pure mode)
and convert to the simplified JSON format consumed by our Rust test harness.

Source:
  https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204

Target interface:
  parameterSet     = ML-DSA-44
  signatureInterface = external   (raw message; IUT applies FIPS 204 wrapper)
  preHash          = pure         (not HashML-DSA)

Usage:
  python3 tests/download_nist_acvp.py
  python3 tests/download_nist_acvp.py --local /path/to/ML-DSA-sigVer-FIPS204/

Output:
  crates/mldsa44/tests/vectors/acvp_mldsa44_sigver.json
  Each entry: {tcId, pk, message, context, signature, expected}
"""

import json
import os
import sys
import argparse
from pathlib import Path
from urllib.request import urlopen, Request

REPO_RAW_BASE = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
    "master/gen-val/json-files/ML-DSA-sigVer-FIPS204"
)

OUTPUT_PATH = Path(__file__).resolve().parent.parent / \
    "crates" / "mldsa44" / "tests" / "vectors" / "acvp_mldsa44_sigver.json"


def fetch_json(url: str) -> dict:
    """Download and parse JSON from a URL."""
    print(f"  Fetching: {url}")
    req = Request(url, headers={"User-Agent": "andna-acvp-downloader/1.0"})
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def load_local_json(path: str) -> dict:
    """Load JSON from a local file."""
    print(f"  Loading: {path}")
    with open(path) as f:
        return json.load(f)


def parse_nist_vectors(prompt_data, expected_data) -> list:
    """
    Parse NIST ACVP format into our simplified vector format.

    We target ML-DSA-44 external interface, pure mode (not preHash).
    This matches liboqs's standard sign()/verify() API: the IUT receives
    raw message + context and applies the FIPS 204 wrapper internally.

    History: an earlier attempt filtered for signatureInterface=internal
    + externalMu=false, which provides messages in a different format
    that liboqs's public API does not accept directly. See
    fips/acvp_sigver_deferral.md (now historical).
    """
    expected_map = {}
    expected_body = expected_data[1] if isinstance(expected_data, list) else expected_data
    for group in expected_body.get("testGroups", []):
        for test in group.get("tests", []):
            expected_map[test["tcId"]] = test["testPassed"]

    vectors = []
    prompt_body = prompt_data[1] if isinstance(prompt_data, list) else prompt_data
    for group in prompt_body.get("testGroups", []):
        param_set = group.get("parameterSet", "")
        sig_interface = group.get("signatureInterface", "")
        pre_hash = group.get("preHash", "")

        if param_set != "ML-DSA-44":
            continue
        if sig_interface != "external":
            continue
        if pre_hash != "pure":
            continue

        for test in group.get("tests", []):
            tc_id = test["tcId"]
            if tc_id not in expected_map:
                print(f"  WARNING: tcId {tc_id} has no expected result, skipping")
                continue

            vectors.append({
                "tcId": tc_id,
                "pk": test["pk"],
                "message": test.get("message", ""),
                "context": test.get("context", ""),
                "signature": test["signature"],
                "expected": expected_map[tc_id],
            })

    return vectors


def main():
    parser = argparse.ArgumentParser(
        description="Download NIST ACVP ML-DSA-44 sigVer vectors"
    )
    parser.add_argument(
        "--local", type=str, default=None,
        help="Path to local directory containing prompt.json + expectedResults.json"
    )
    parser.add_argument(
        "--max-vectors", type=int, default=10,
        help="Maximum number of vectors to include (default: 10)"
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output path (default: auto-detected relative to script)"
    )
    args = parser.parse_args()

    output_path = Path(args.output) if args.output else OUTPUT_PATH

    print("=" * 60)
    print("NIST ACVP ML-DSA-44 sigVer Vector Downloader")
    print("=" * 60)

    # Load vectors
    if args.local:
        local_dir = Path(args.local)
        prompt_data = load_local_json(local_dir / "prompt.json")
        expected_data = load_local_json(local_dir / "expectedResults.json")
    else:
        try:
            prompt_data = fetch_json(f"{REPO_RAW_BASE}/prompt.json")
            expected_data = fetch_json(f"{REPO_RAW_BASE}/expectedResults.json")
        except Exception as e:
            print(f"\n  ERROR: Could not download from GitHub: {e}")
            print("\n  Alternative: Download manually and use --local flag:")
            print("    1. git clone https://github.com/usnistgov/ACVP-Server.git")
            print("    2. python3 tests/download_nist_acvp.py --local \\")
            print("         ACVP-Server/gen-val/json-files/ML-DSA-sigVer-FIPS204/")
            sys.exit(1)

    # Parse and filter
    vectors = parse_nist_vectors(prompt_data, expected_data)

    if not vectors:
        print("\n  ERROR: No ML-DSA-44 internal sigVer vectors found!")
        print("  Check that the NIST files contain ML-DSA-44 test groups.")
        sys.exit(1)

    # Balance: try to get a mix of pass/fail
    pass_vecs = [v for v in vectors if v["expected"]]
    fail_vecs = [v for v in vectors if not v["expected"]]

    max_n = args.max_vectors
    if len(pass_vecs) > 0 and len(fail_vecs) > 0:
        # Balanced selection
        n_pass = min(len(pass_vecs), max_n // 2 + 1)
        n_fail = min(len(fail_vecs), max_n - n_pass)
        selected = pass_vecs[:n_pass] + fail_vecs[:n_fail]
    else:
        selected = vectors[:max_n]

    # Sort by tcId for stability
    selected.sort(key=lambda v: v["tcId"])

    print(f"\n  Found {len(vectors)} ML-DSA-44 internal sigVer vectors")
    print(f"  Selected {len(selected)} ({len([v for v in selected if v['expected']])} pass, "
          f"{len([v for v in selected if not v['expected']])} fail)")

    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(selected, f, indent=2)

    print(f"\n  Written to: {output_path}")
    print(f"  File size:  {output_path.stat().st_size:,} bytes")
    print(f"\n  Run tests:  cargo test -p andna-mldsa44 --test acvp_sigver")
    print("=" * 60)


if __name__ == "__main__":
    main()
