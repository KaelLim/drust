#!/usr/bin/env bash
# Offline chart test harness. Requires helm + kubeconform on PATH.
set -uo pipefail
CHART="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$CHART/tests/fixtures"
FAILS=0
_render() { helm template testrel "$CHART" -f "$FIX/$1" --namespace testns 2>/tmp/helmerr || { echo "RENDER-ERROR ($1):"; cat /tmp/helmerr; return 1; }; }

assert_contains() { # <fixture> <needle> <label>
  if _render "$1" | grep -qF -- "$2"; then echo "ok: $3"; else echo "FAIL: $3 — '$2' absent in $1"; FAILS=$((FAILS+1)); fi; }
assert_absent() {
  if _render "$1" | grep -qF -- "$2"; then echo "FAIL: $3 — '$2' present in $1 (should be absent)"; FAILS=$((FAILS+1)); else echo "ok: $3"; fi; }
assert_kubeconform() { # <fixture>
  local out; out=$(_render "$1" | kubeconform -strict -summary -ignore-missing-schemas 2>&1)
  if echo "$out" | grep -q "Invalid: 0" && echo "$out" | grep -q "Errors: 0"; then echo "ok: kubeconform $1"; else echo "FAIL: kubeconform $1"; echo "$out"; FAILS=$((FAILS+1)); fi; }

echo "== lint =="; helm lint "$CHART" || FAILS=$((FAILS+1))

# --- Task 1 assertions ---
assert_contains minimal.yaml "kind: Namespace" "namespace rendered when createNamespace=true"
assert_absent   full.yaml    "kind: Namespace" "namespace absent when createNamespace=false"
assert_kubeconform minimal.yaml

# --- Task 2 assertions ---
assert_contains minimal.yaml "kind: StatefulSet"        "drust StatefulSet rendered"
assert_contains minimal.yaml "replicas: 1"              "replicas pinned to 1"
assert_contains minimal.yaml "runAsUser: 10001"         "runAsUser 10001"
assert_contains minimal.yaml "readOnlyRootFilesystem: true" "readOnlyRootFilesystem"
assert_contains minimal.yaml "seccompProfile"           "seccomp profile set"
assert_contains minimal.yaml "path: /health"            "health probe path"
assert_contains minimal.yaml "name: DRUST_DATA_DIR"     "DRUST_DATA_DIR env"
assert_contains minimal.yaml 'value: /data'             "DRUST_DATA_DIR=/data"
assert_contains minimal.yaml "name: DRUST_BASE_PATH"    "DRUST_BASE_PATH env present"
assert_contains full.yaml    "name: GARAGE_S3_ENDPOINT" "storage endpoint when enabled"
assert_absent   minimal.yaml "name: GARAGE_S3_ENDPOINT" "no storage endpoint when disabled"
assert_contains minimal.yaml "port: 47826"              "drust service port"

# --- Task 3 assertions ---
assert_contains minimal.yaml "kind: Secret"                  "Secret rendered when create=true"
assert_contains minimal.yaml "name: DRUST_INIT_ADMIN_PASSWORD" "admin password env wired"
assert_contains minimal.yaml "secretKeyRef"                   "admin password via secretKeyRef"
assert_contains full.yaml    "name: GARAGE_ADMIN_ENDPOINT"    "admin endpoint placeholder env present when storage on"
assert_contains full.yaml    "name: GARAGE_S3_ACCESS_KEY"     "s3 access key env present when storage on"
assert_absent   minimal.yaml "name: GARAGE_ADMIN_ENDPOINT"    "no admin endpoint env when storage off"

# --- Task 4 assertions ---
assert_contains full.yaml    "minio/minio"          "minio image when storage on"
assert_contains full.yaml    "MINIO_ROOT_USER"      "minio root user env"
assert_contains full.yaml    "port: 9000"           "minio service port"
assert_absent   minimal.yaml "minio/minio"          "no minio when storage off"

# --- Task 5 assertions ---
assert_contains full.yaml "name: minio-init"                    "minio-init job rendered"
assert_contains full.yaml "helm.sh/hook: post-install,post-upgrade" "job is a post hook"
assert_contains full.yaml "mc mb --ignore-existing"             "buckets created idempotently"
assert_contains full.yaml "anonymous set download"              "public bucket anon read when publicFiles on"
assert_absent   minimal.yaml "name: minio-init"                 "no init job when storage off"
assert_absent storage-noPublic.yaml "anonymous set download" "no anon policy when publicFiles off"

# --- Task 6 assertions ---
assert_contains minimal.yaml "kind: Ingress"                          "ingress rendered"
assert_contains minimal.yaml "127.0.0.1:47826"                        "host rewrite value present"
assert_contains minimal.yaml "kind: Middleware"                       "traefik middleware for host rewrite"
assert_contains full.yaml    "cert-manager.io/cluster-issuer: letsencrypt" "cert-manager issuer when tls.enabled"
assert_contains full.yaml    "path: /public"                          "public path when publicFiles on"
assert_absent   minimal.yaml "path: /public"                          "no public path when publicFiles off"
assert_contains nginx.yaml "nginx.ingress.kubernetes.io/upstream-vhost: 127.0.0.1:47826" "nginx upstream-vhost host rewrite"
assert_absent   nginx.yaml "kind: Middleware" "no traefik middleware for nginx controller"

echo "== $FAILS failure(s) =="
exit $((FAILS>0))
