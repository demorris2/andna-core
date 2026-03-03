#!/usr/bin/env bash
# =============================================================================
# AN-DNA vNext — Pin Docker Base Image Digest
#
# Pulls debian:bookworm-slim, extracts the digest, and updates
# the Dockerfile to use the pinned digest instead of the tag.
#
# Usage:
#   ./docker/pin-digest.sh
# =============================================================================
set -euo pipefail

IMAGE="debian:bookworm-slim"
DOCKERFILE="$(cd "$(dirname "$0")/.." && pwd)/Dockerfile"

echo "Pulling ${IMAGE}..."
docker pull "${IMAGE}"

DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}")

echo ""
echo "  Image:  ${IMAGE}"
echo "  Digest: ${DIGEST}"
echo ""

# Extract just the sha256 part
SHA=$(echo "${DIGEST}" | sed 's/.*@//')

# Update Dockerfile
if grep -q "FROM debian:bookworm-slim AS builder" "${DOCKERFILE}"; then
    sed -i "s|FROM debian:bookworm-slim AS builder|FROM debian:bookworm-slim@${SHA} AS builder|" "${DOCKERFILE}"
    echo "  ✓ Updated builder stage in Dockerfile"
fi

if grep -q "FROM debian:bookworm-slim AS runtime" "${DOCKERFILE}"; then
    sed -i "s|FROM debian:bookworm-slim AS runtime|FROM debian:bookworm-slim@${SHA} AS runtime|" "${DOCKERFILE}"
    echo "  ✓ Updated runtime stage in Dockerfile"
fi

# Remove the placeholder comments
sed -i '/# -- Pin your digest here/d' "${DOCKERFILE}"
sed -i '/# FROM debian:bookworm-slim@sha256:<DIGEST>/d' "${DOCKERFILE}"

echo ""
echo "  Dockerfile updated. Commit the change:"
echo "    git add Dockerfile"
echo "    git commit -m 'pin: docker base image digest'"
echo ""
