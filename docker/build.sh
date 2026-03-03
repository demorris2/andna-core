#!/usr/bin/env bash
# =============================================================================
# AN-DNA vNext — Docker Build Script
#
# Usage:
#   ./docker/build.sh              # Build with default tag
#   ./docker/build.sh v1.0         # Build with custom tag
# =============================================================================
set -euo pipefail

TAG="${1:-andna-verifier}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "═══════════════════════════════════════════════════════"
echo "  AN-DNA vNext — Docker Build"
echo "═══════════════════════════════════════════════════════"

# ── Pre-flight checks ──

if ! command -v docker &>/dev/null; then
    echo "Error: docker not found" >&2
    exit 1
fi

if [ ! -f "$PROJECT_ROOT/Cargo.lock" ]; then
    echo "WARNING: Cargo.lock not found!"
    echo "  Reproducible builds require a committed Cargo.lock."
    echo "  Run: cargo generate-lockfile && git add Cargo.lock"
    echo ""
    read -p "  Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# ── Build ──

echo ""
echo "  Tag:     ${TAG}"
echo "  Context: ${PROJECT_ROOT}"
echo ""

docker build \
    --tag "${TAG}" \
    --progress=plain \
    "${PROJECT_ROOT}" 2>&1

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Build complete: ${TAG}"
echo ""
echo "  Quick test:"
echo "    docker run --rm ${TAG} --help"
echo ""
echo "  Run demo:"
echo "    docker run --rm -v \$(pwd)/output:/workspace ${TAG} gen sample.bin"
echo "    docker run --rm -v \$(pwd)/output:/workspace ${TAG} verify sample.bin"
echo "═══════════════════════════════════════════════════════"
