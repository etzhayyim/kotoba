#!/usr/bin/env bash
# Deploy kotoba to Vultr VKE (SJC cluster).
#
# Usage:
#   ./scripts/deploy.sh [tag]          # deploy (default tag: latest)
#   ./scripts/deploy.sh --build [tag]  # build+push then deploy
#   ./scripts/deploy.sh --delete       # teardown (keeps PVC)
#
# Prerequisites:
#   - kubectl configured for vke-31d5f7dc-* context
#   - ghcr-pull-secret in kotoba namespace (see step 0 below)
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../deploy" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TAG="latest"
BUILD=false
DELETE=false

for arg in "$@"; do
  case "$arg" in
    --build)  BUILD=true ;;
    --delete) DELETE=true ;;
    *)        TAG="$arg" ;;
  esac
done

# ── teardown ──────────────────────────────────────────────────────────────────
if $DELETE; then
  echo "Deleting kotoba deployment (PVC preserved)..."
  kubectl delete -f "${DEPLOY_DIR}/service.yaml"    --ignore-not-found
  kubectl delete -f "${DEPLOY_DIR}/deployment.yaml" --ignore-not-found
  kubectl delete -f "${DEPLOY_DIR}/configmap.yaml"  --ignore-not-found
  echo "Done. PVC kotoba-sled preserved. To also delete PVC:"
  echo "  kubectl delete pvc kotoba-sled -n kotoba"
  exit 0
fi

# ── build & push (optional) ───────────────────────────────────────────────────
if $BUILD; then
  echo "Building & pushing ghcr.io/gftdcojp/kotoba:${TAG}..."
  "${SCRIPT_DIR}/build-push.sh" "${TAG}"
fi

# ── 0. Pull secret (idempotent — skip if exists) ──────────────────────────────
# Creates ghcr-pull-secret from local docker credentials.
# Requires: docker login ghcr.io -u <github-user> -p <PAT>
if ! kubectl get secret ghcr-pull-secret -n kotoba &>/dev/null; then
  echo "Creating ghcr-pull-secret..."
  kubectl create namespace kotoba --dry-run=client -o yaml | kubectl apply -f -
  kubectl create secret docker-registry ghcr-pull-secret \
    --docker-server=ghcr.io \
    --docker-username="${GHCR_USER:-gftdcojp}" \
    --docker-password="${GHCR_TOKEN:?set GHCR_TOKEN env var}" \
    --namespace=kotoba
fi

# ── 1. Namespace + PVC ────────────────────────────────────────────────────────
kubectl apply -f "${DEPLOY_DIR}/namespace.yaml"
kubectl apply -f "${DEPLOY_DIR}/pvc.yaml"

# ── 2. ConfigMap ──────────────────────────────────────────────────────────────
kubectl apply -f "${DEPLOY_DIR}/configmap.yaml"

# ── 3. Deployment (patch image tag if not latest) ─────────────────────────────
if [[ "${TAG}" != "latest" ]]; then
  sed "s|ghcr.io/gftdcojp/kotoba:latest|ghcr.io/gftdcojp/kotoba:${TAG}|g" \
    "${DEPLOY_DIR}/deployment.yaml" | kubectl apply -f -
else
  kubectl apply -f "${DEPLOY_DIR}/deployment.yaml"
fi

# ── 4. Service ────────────────────────────────────────────────────────────────
kubectl apply -f "${DEPLOY_DIR}/service.yaml"

# ── 5. Wait for rollout ───────────────────────────────────────────────────────
echo "Waiting for rollout..."
kubectl rollout status deployment/kotoba -n kotoba --timeout=120s

# ── 6. Health check ───────────────────────────────────────────────────────────
POD=$(kubectl get pods -n kotoba -l app=kotoba -o jsonpath='{.items[0].metadata.name}')
echo ""
echo "Pod: ${POD}"
echo "Logs (last 20 lines):"
kubectl logs -n kotoba "${POD}" --tail=20

echo ""
echo "Port-forward to verify locally:"
echo "  kubectl port-forward -n kotoba svc/kotoba 8080:8080 &"
echo "  curl http://localhost:8080/health"
