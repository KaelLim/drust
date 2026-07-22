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
# Default MUST stay false: a release-owned Namespace makes `helm uninstall`
# delete the namespace and reap every PVC (all tenant SQLite data).
if helm template testrel "$CHART" --namespace testns 2>/dev/null | grep -qF "kind: Namespace"; then
  echo "FAIL: default values render a release-owned Namespace"; FAILS=$((FAILS+1));
else echo "ok: default values render no Namespace"; fi
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

# --- Task 7 assertions ---
assert_contains minimal.yaml "kind: NetworkPolicy"      "networkpolicy rendered"
assert_contains minimal.yaml "port: 53"                 "DNS egress allowed"
assert_contains full.yaml    "10.42.0.0/16"             "cluster pod CIDR in egress except"
assert_contains full.yaml    "port: 9000"               "drust->minio egress allowed when storage on"

# --- Task 8 assertions ---
assert_contains full.yaml    "name: maintenance"        "maintenance sidecar rendered when enabled"
assert_contains full.yaml    "drust_session_janitor"    "sidecar runs session janitor"
assert_absent no-sidecar.yaml "name: maintenance" "no sidecar when disabled"

# --- Task 9 assertions ---
assert_contains full.yaml    "kind: CronJob"                    "backup cronjob when snapshot class set"
assert_contains full.yaml    "kind: VolumeSnapshot"             "cronjob creates a VolumeSnapshot manifest"
assert_contains full.yaml    "csi-hostpath-snapclass"           "snapshot class wired"
assert_contains full.yaml    'schedule: "0 3 * * *"'            "backup schedule wired"
assert_absent   minimal.yaml "kind: CronJob"                    "no backup cronjob when class empty"

# --- Review-fix regression guards ---
# HIGH: backup RoleBinding subject must carry a namespace (else RBAC never matches the SA)
if _render full.yaml | awk '/kind: RoleBinding/{r=1} r&&/kind: ServiceAccount/{s=1} r&&s&&/^[[:space:]]*namespace:/{print "OK"; exit}' | grep -q OK; then
  echo "ok: backup RoleBinding subject has namespace"; else echo "FAIL: backup RoleBinding subject missing namespace"; FAILS=$((FAILS+1)); fi
assert_contains full.yaml "MC_CONFIG_DIR"          "minio-init mc has a writable config dir"
assert_contains full.yaml "runAsGroup: 1000"       "minio runAsGroup pinned"
assert_contains full.yaml "public-file GETs arrive" "minio NetworkPolicy admits ingress-controller when publicFiles on"
assert_absent storage-noPublic.yaml "public-file GETs arrive" "no ingress-controller MinIO rule when publicFiles off"
assert_contains full.yaml "/data/_trash"           "maintenance sidecar sweeps trash"
assert_contains full.yaml "mc mb --ignore-existing drust/public" "minio-init creates the literal public bucket"

# --- Task 10: full-matrix kubeconform ---
for f in minimal full nginx storage-noPublic no-sidecar; do assert_kubeconform "$f.yaml"; done
# README exists
[ -f "$CHART/README.md" ] && echo "ok: README present" || { echo "FAIL: README missing"; FAILS=$((FAILS+1)); }

echo "== $FAILS failure(s) =="
exit $((FAILS>0))
