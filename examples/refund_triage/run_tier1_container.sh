#!/usr/bin/env bash
# Build + run the Tier-1 structural harness (Linux container, two uids). Requires a Linux-container
# Docker daemon (on macOS: Docker Desktop). See examples/refund_triage/README.md.
set -euo pipefail
cd "$(dirname "$0")/../.."          # repo root (build context)

IMAGE="${SIGNET_REFUND_IMAGE:-signet-refund-tier1}"
echo "===== building ${IMAGE} ====="
docker build -f examples/refund_triage/Dockerfile -t "$IMAGE" .

echo
echo "===== TIER-1 STRUCTURAL TRIAD + VERDICTS (container, two uids) ====="
docker run --rm "$IMAGE" test

echo
echo "===== TIER-1 SHOWCASE PANELS (tier=1 structural) ====="
docker run --rm "$IMAGE" showcase
