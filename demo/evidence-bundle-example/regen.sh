#!/usr/bin/env bash
set -euo pipefail

# AN-DNA evidence bundle verification and regeneration script.
# Style rule: NO backslash line continuations anywhere in this script.
#
# DEFAULT MODE (no flags):
#   Verifies the committed artifacts and demonstrates the replay property.
#   (a) verify-file -> ACCEPT for the file seal
#   (b) verify-file -> ACCEPT for the evidence attestation
#   (c) a freshly produced evidence record's deterministic section and
#       evidence_digest_hex match the committed sample.verify.json
#
# FROM-SCRATCH MODE (--from-scratch):
#   Regenerates all artifacts using the fixed TEST seeds below.
#   New artifacts are VALID but BYTE-DIFFERENT from the committed ones:
#   ML-DSA-44 signing is hedged (randomized) and the registry stamps the
#   current time, so frame bytes, seal bytes, and evidence digest all change.
#   This does not represent a tamper -- a fresh verify-file on the new
#   artifacts still returns ACCEPT.
#
# TEST SEEDS (hardcoded below, demo only -- provide no security):
#   Sealer:   seed = 0x42 x32, device_id16 = 0xd0 x16, epoch 7
#   Verifier: seed = 0xa5 x32, device_id16 = 0xe3 x16, epoch 3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUNDLE_DIR="$SCRIPT_DIR"

if [ -n "${ANDNA_BIN:-}" ]; then
  BIN="$ANDNA_BIN"
elif [ -f "$REPO_ROOT/target/debug/andna.exe" ]; then
  BIN="$REPO_ROOT/target/debug/andna.exe"
elif [ -f "$REPO_ROOT/target/debug/andna" ]; then
  BIN="$REPO_ROOT/target/debug/andna"
else
  echo "error: andna CLI binary not found. Build with:"
  echo "  cargo build -p ffi-cli --locked --features \"oqs-backend fips-integrity-stub\""
  exit 2
fi

PYTHON=""
for _py in python3 py python; do
  if command -v "$_py" >/dev/null 2>&1 && "$_py" -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
    PYTHON="$_py"
    break
  fi
done
if [ -z "$PYTHON" ]; then
  echo "error: a working python3, py, or python interpreter is required for replay comparison"
  exit 2
fi

if [ "${1:-}" = "--from-scratch" ]; then
  echo "== FROM-SCRATCH mode: regenerating all artifacts with fixed TEST seeds =="
  echo "   New artifacts will be valid but byte-different (hedged signing + registry timestamp)."

  TMPDIR_FRESH="$(mktemp -d)"
  cat > "$TMPDIR_FRESH/verifier-demo-profile.json" << 'PROF_EOF'
{
  "schema_version": "andna-sealer-profile-v0",
  "profile_type": "software-profile",
  "seed_hex": "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
  "device_id16_hex": "e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3",
  "epoch": 3,
  "created_at_unix_ms": 0,
  "warning": "TEST SEED -- demo only, provides no security"
}
PROF_EOF

  echo "--- seal-file ---"
  "$BIN" seal-file "$BUNDLE_DIR/sample.txt" --seed-hex 4242424242424242424242424242424242424242424242424242424242424242 --device-id16-hex d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0 --epoch 7 --out "$BUNDLE_DIR/sample.txt.andna-seal.json" --content-type text/plain --registry-out "$BUNDLE_DIR/sample.registry.json"

  echo "--- verify-file with evidence + attestation ---"
  "$BIN" verify-file "$BUNDLE_DIR/sample.txt" --seal "$BUNDLE_DIR/sample.txt.andna-seal.json" --registry "$BUNDLE_DIR/sample.registry.json" --evidence-out "$BUNDLE_DIR/sample.verify.json" --attest-profile "$TMPDIR_FRESH/verifier-demo-profile.json" --attest-registry-out "$BUNDLE_DIR/verifier.registry.json"

  rm -rf "$TMPDIR_FRESH"

  echo "--- verify evidence attestation ---"
  "$BIN" verify-file "$BUNDLE_DIR/sample.verify.json" --seal "$BUNDLE_DIR/sample.verify.json.andna-seal.json" --registry "$BUNDLE_DIR/verifier.registry.json"

  echo ""
  echo "== FROM-SCRATCH complete =="
  echo "   Artifacts replaced with valid but byte-different content."
  echo "   Evidence digest will differ from the committed baseline."
  echo "   Both file seal and evidence attestation verify as ACCEPT."
  exit 0
fi

echo "== DEFAULT mode: verifying committed artifacts and replay property =="

echo "--- verify file seal ---"
"$BIN" verify-file "$BUNDLE_DIR/sample.txt" --seal "$BUNDLE_DIR/sample.txt.andna-seal.json" --registry "$BUNDLE_DIR/sample.registry.json"

echo "--- verify evidence attestation ---"
"$BIN" verify-file "$BUNDLE_DIR/sample.verify.json" --seal "$BUNDLE_DIR/sample.verify.json.andna-seal.json" --registry "$BUNDLE_DIR/verifier.registry.json"

echo "--- replay property: compare fresh evidence with committed record ---"
TMPDIR_REPLAY="$(mktemp -d)"
"$BIN" verify-file "$BUNDLE_DIR/sample.txt" --seal "$BUNDLE_DIR/sample.txt.andna-seal.json" --registry "$BUNDLE_DIR/sample.registry.json" --evidence-out "$TMPDIR_REPLAY/fresh.verify.json" > /dev/null

cat > "$TMPDIR_REPLAY/compare.py" << 'PYEOF'
import json, sys
committed = json.load(open(sys.argv[1]))
fresh = json.load(open(sys.argv[2]))
det_ok = committed['deterministic'] == fresh['deterministic']
dig_ok = committed['evidence_digest_hex'] == fresh['evidence_digest_hex']
if det_ok and dig_ok:
    print("PASS: deterministic section + evidence_digest_hex match committed record (replay property confirmed)")
    sys.exit(0)
print("FAIL: mismatch between fresh and committed evidence")
if not det_ok:
    print("  deterministic sections differ")
if not dig_ok:
    print("  evidence_digest_hex differs: committed=" + committed['evidence_digest_hex'])
    print("                               fresh=    " + fresh['evidence_digest_hex'])
sys.exit(1)
PYEOF

"$PYTHON" "$TMPDIR_REPLAY/compare.py" "$BUNDLE_DIR/sample.verify.json" "$TMPDIR_REPLAY/fresh.verify.json"
rm -rf "$TMPDIR_REPLAY"

echo ""
echo "PASS: regen.sh default mode"
