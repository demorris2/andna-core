#!/usr/bin/env bash
# =============================================================================
# AN-DNA vNext — 5-Minute Demo Script
#
# This script runs inside the Docker container and executes the full
# deterministic replay demonstration.
#
# Usage (from host):
#   mkdir -p output
#   docker run --rm -v $(pwd)/output:/workspace andna-verifier demo
#
# Or run each step manually:
#   docker run --rm -v $(pwd)/output:/workspace andna-verifier gen sample.bin
#   docker run --rm -v $(pwd)/output:/workspace andna-verifier verify sample.bin
#   ...
# =============================================================================
set -euo pipefail

echo "═══════════════════════════════════════════════════════════"
echo "  AN-DNA vNext Phase 1 — Deterministic Replay Demo"
echo "═══════════════════════════════════════════════════════════"
echo ""

cd /workspace

# ── Step 1: Generate a valid sample frame ──
echo "┌─ Step 1: Generate valid frame ─────────────────────────"
python3 -m andna gen sample_frame.bin
echo ""

# ── Step 2: Verify it (expect ACCEPT) ──
echo "┌─ Step 2: Verify valid frame ──────────────────────────"
python3 -m andna verify sample_frame.bin
echo ""

# ── Step 3: Tamper one byte ──
echo "┌─ Step 3: Tamper frame ────────────────────────────────"
python3 -m andna tamper sample_frame.bin tampered_frame.bin
echo ""

# ── Step 4: Verify tampered frame (expect REJECT) ──
echo "┌─ Step 4: Verify tampered frame ──────────────────────"
python3 -m andna verify tampered_frame.bin || true
echo ""

# ── Step 5: Replay verification log ──
echo "┌─ Step 5: Replay (structural) ────────────────────────"
python3 -m andna replay verification_log.json
echo ""

# ── Step 6: Replay with --frame (deterministic re-verification) ──
echo "┌─ Step 6: Replay with --frame (determinism proof) ────"
python3 -m andna replay verification_log.json --frame sample_frame.bin
echo ""

# ── Step 7: Export evidence bundle ──
echo "┌─ Step 7: Export evidence bundle ─────────────────────"
python3 -m andna export evidence/
echo ""

# ── Summary ──
echo "═══════════════════════════════════════════════════════════"
echo "  Demo complete. Artifacts in /workspace:"
echo ""
ls -la /workspace/ 2>/dev/null || true
echo ""
if [ -d /workspace/evidence ]; then
    echo "  Evidence bundle:"
    ls -la /workspace/evidence/
    echo ""
    echo "  Evidence SHA-256:"
    sha256sum /workspace/evidence/evidence.json
fi
echo ""
echo "  To prove determinism: run this demo on a second machine"
echo "  and compare evidence/evidence.json SHA-256 hashes."
echo "═══════════════════════════════════════════════════════════"
