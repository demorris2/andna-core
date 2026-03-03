#!/usr/bin/env bash
# =============================================================================
# AN-DNA vNext — Reproducibility Verification
#
# Runs the demo twice and compares verification digests.
# If they match, determinism holds. If they don't, stop and investigate.
#
# Usage:
#   ./docker/verify-reproducibility.sh
#   ./docker/verify-reproducibility.sh andna-verifier  # custom image tag
#
# For cross-host comparison:
#   Host A: ./docker/verify-reproducibility.sh --export /tmp/host-a.txt
#   Host B: ./docker/verify-reproducibility.sh --export /tmp/host-b.txt
#   diff /tmp/host-a.txt /tmp/host-b.txt
# =============================================================================
set -euo pipefail

IMAGE="${1:-andna-verifier}"
EXPORT_FILE="${2:-}"

echo "═══════════════════════════════════════════════════════════"
echo "  AN-DNA vNext — Reproducibility Verification"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Image: ${IMAGE}"
echo ""

# ── Helper: run demo and extract verification digest ──
run_demo() {
    local run_dir="$1"
    local label="$2"

    mkdir -p "${run_dir}"

    echo "  Running ${label}..."

    # Generate frame
    docker run --rm -v "${run_dir}:/workspace" "${IMAGE}" gen sample_frame.bin \
        > /dev/null 2>&1

    # Verify valid frame
    docker run --rm -v "${run_dir}:/workspace" "${IMAGE}" verify sample_frame.bin \
        > /dev/null 2>&1

    # Tamper
    docker run --rm -v "${run_dir}:/workspace" "${IMAGE}" tamper sample_frame.bin tampered_frame.bin \
        > /dev/null 2>&1

    # Verify tampered frame (will fail, that's expected)
    docker run --rm -v "${run_dir}:/workspace" "${IMAGE}" verify tampered_frame.bin \
        > /dev/null 2>&1 || true

    # Export evidence
    docker run --rm -v "${run_dir}:/workspace" "${IMAGE}" export evidence/ \
        > /dev/null 2>&1

    # Extract digest
    local digest
    digest=$(python3 -c "
import json, sys
m = json.load(open('${run_dir}/evidence/manifest.json'))
print(m.get('verification_digest', 'MISSING'))
" 2>/dev/null || echo "PARSE_ERROR")

    echo "    verification_digest: ${digest}"
    echo "${digest}"
}

# ── Create temp directories ──
TMPDIR_BASE=$(mktemp -d)
RUN_A="${TMPDIR_BASE}/run-a"
RUN_B="${TMPDIR_BASE}/run-b"

trap "rm -rf ${TMPDIR_BASE}" EXIT

# ── Run A ──
echo ""
DIGEST_A=$(run_demo "${RUN_A}" "Run A")
echo ""

# ── Run B ──
DIGEST_B=$(run_demo "${RUN_B}" "Run B")
echo ""

# ── Compare ──
echo "───────────────────────────────────────────────────────────"
echo ""

# Also compare frame hashes
FRAME_HASH_A=$(sha256sum "${RUN_A}/sample_frame.bin" | awk '{print $1}')
FRAME_HASH_B=$(sha256sum "${RUN_B}/sample_frame.bin" | awk '{print $1}')

echo "  Frame SHA-256 A:          ${FRAME_HASH_A}"
echo "  Frame SHA-256 B:          ${FRAME_HASH_B}"
echo ""
echo "  Verification digest A:    ${DIGEST_A}"
echo "  Verification digest B:    ${DIGEST_B}"
echo ""

PASS=true

if [ "${FRAME_HASH_A}" != "${FRAME_HASH_B}" ]; then
    echo "  ✗ FRAME HASH MISMATCH"
    PASS=false
fi

if [ "${DIGEST_A}" != "${DIGEST_B}" ]; then
    echo "  ✗ VERIFICATION DIGEST MISMATCH — DETERMINISM BROKEN"
    PASS=false
fi

if [ "${PASS}" = true ]; then
    echo "  ✓ DETERMINISM VERIFIED"
    echo "    Same frames → same decisions → same digest"
    echo ""
    echo "═══════════════════════════════════════════════════════════"

    # Export for cross-host comparison if requested
    if [ -n "${EXPORT_FILE}" ]; then
        cat > "${EXPORT_FILE}" <<EOF
# AN-DNA Reproducibility Report
# Host: $(hostname)
# Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Image: ${IMAGE}
frame_sha256=${FRAME_HASH_A}
verification_digest=${DIGEST_A}
EOF
        echo "  Exported to: ${EXPORT_FILE}"
    fi

    exit 0
else
    echo ""
    echo "  STOP. Investigate before proceeding."
    echo "  Check: Cargo.lock committed? Base image pinned? Rust version pinned?"
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    exit 1
fi
