#!/usr/bin/env bash
# Bootstrap a lightweight kind cluster with postgres, redis, metrics-server, and authsvc.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-authsvc}"
export DOCKER_HOST="${DOCKER_HOST:-unix://${HOME}/.colima/default/docker.sock}"

echo "==> Docker host: $DOCKER_HOST"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "==> Creating kind cluster '$CLUSTER_NAME'"
  kind create cluster --name "$CLUSTER_NAME" --config "$ROOT/deploy/kind/cluster.yaml"
else
  echo "==> Kind cluster '$CLUSTER_NAME' already exists"
fi

kubectl cluster-info --context "kind-${CLUSTER_NAME}"

echo "==> Building authsvc image"
docker build -t authsvc:local "$ROOT"

echo "==> Loading image into kind"
kind load docker-image authsvc:local --name "$CLUSTER_NAME"

echo "==> Applying base manifests"
kubectl apply -f "$ROOT/deploy/kind/namespace.yaml"
kubectl apply -f "$ROOT/deploy/kind/postgres.yaml"
kubectl apply -f "$ROOT/deploy/kind/redis.yaml"

echo "==> Installing metrics-server"
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
kubectl patch deployment metrics-server -n kube-system --type='json' \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]' \
  2>/dev/null || true

echo "==> Waiting for postgres + redis"
kubectl wait --for=condition=available deployment/postgres -n authsvc --timeout=180s
kubectl wait --for=condition=available deployment/redis -n authsvc --timeout=120s

echo "==> Installing authsvc via Helm"
helm upgrade --install authsvc "$ROOT/deploy/helm/authsvc" \
  -n authsvc \
  -f "$ROOT/deploy/kind/values-local.yaml" \
  --wait --timeout 180s

kubectl wait --for=condition=available deployment/authsvc -n authsvc --timeout=180s

echo "==> Waiting for metrics-server"
for i in $(seq 1 30); do
  if kubectl top pods -n authsvc >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo ""
echo "Cluster ready."
echo "  Base URL: http://127.0.0.1:18080"
echo "  Context:  kind-${CLUSTER_NAME}"
kubectl get pods -n authsvc -o wide
kubectl top pods -n authsvc 2>/dev/null || echo "(metrics-server still warming up)"
