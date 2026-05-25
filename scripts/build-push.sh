#!/usr/bin/env bash
# Build kotoba image via remote BuildKit (gftd-vke) and push to GHCR.
# Usage: ./scripts/build-push.sh [tag]
set -euo pipefail

TAG="${1:-latest}"
IMAGE="ghcr.io/gftdcojp/kotoba:${TAG}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KOTOBA_DIR="${REPO_ROOT}/60-apps/ai-gftd-project-kotoba"

GIT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "Building ${IMAGE} (sha=${GIT_SHA})"
echo "Context: ${KOTOBA_DIR}"

docker buildx build \
    --builder gftd-vke \
    --platform linux/amd64 \
    --cache-from type=registry,ref=ghcr.io/gftdcojp/build-cache:kotoba \
    --cache-to   type=registry,ref=ghcr.io/gftdcojp/build-cache:kotoba,mode=max \
    --build-arg GIT_SHA="${GIT_SHA}" \
    --build-arg BUILD_DATE="${BUILD_DATE}" \
    --tag "${IMAGE}" \
    --push \
    "${KOTOBA_DIR}"

echo "Pushed ${IMAGE}"
