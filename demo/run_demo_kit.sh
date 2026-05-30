#!/usr/bin/env bash
set -euo pipefail

BIN=${BIN:-andna}
FIXTURE=${FIXTURE:-demo/fixtures/sample_frame.bin}
OUTDIR=${OUTDIR:-evidence}

echo "== AN-DNA R1 Demo Kit =="
echo "BIN: $BIN"
echo "FIXTURE: $FIXTURE"

rm -f verification_log.json andna_audit.jsonl audit_validate.json tampered_frame.bin
rm -rf evidence hostb_out
rm -rf "$OUTDIR" tampered_frame.bin || true

echo "\n[1/5] Verify fixture"
"$BIN" verify "$FIXTURE"

echo "\n[2/5] Tamper + verify reject"
cp "$FIXTURE" tampered_frame.bin
"$BIN" tamper tampered_frame.bin tampered_frame.bin
"$BIN" verify tampered_frame.bin || true

echo "\n[3/5] Replay + re-verify fixture"
"$BIN" replay verification_log.json --frame "$FIXTURE"

echo "\n[4/5] Export evidence bundle"
"$BIN" export "$OUTDIR"

echo "\n[5/5] Red-failure mode (optional): tamper authoritative audit log then validate"
if [ -f "$OUTDIR/andna_audit.jsonl" ]; then
  cp "$OUTDIR/andna_audit.jsonl" "$OUTDIR/andna_audit.jsonl.bak"
  # flip 1 byte deterministically (replace first occurrence of '"decision":1' with '"decision":0')
  perl -pe 's/"decision":1/"decision":0/ if $.==1' "$OUTDIR/andna_audit.jsonl.bak" > "$OUTDIR/andna_audit.jsonl.tampered" || true
  echo "Tampered copy written to: $OUTDIR/andna_audit.jsonl.tampered"
  echo "Run your validator against it; expected: FAIL."
else
  echo "No $OUTDIR/andna_audit.jsonl found; skipping."
fi

echo "\nDone. Baseline parity anchor (fixture verification_digest):"
echo "85f4dc18777bc2122cf671dce6c2d69d92c80b5d0dbd78a83a644afa1159818d"
