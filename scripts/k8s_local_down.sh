#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-authsvc}"
export DOCKER_HOST="${DOCKER_HOST:-unix://${HOME}/.colima/default/docker.sock}"

helm uninstall authsvc -n authsvc 2>/dev/null || true
kubectl delete namespace authsvc --ignore-not-found
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

echo "Kind cluster '$CLUSTER_NAME' removed."
