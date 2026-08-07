#!/usr/bin/env bash
# Offline chart test harness. Requires helm + kubeconform on PATH.
set -uo pipefail
CHART="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$CHART/tests/fixtures"
FAILS=0
RENDER_DIR="$(mktemp -d)"
trap 'rm -rf "$RENDER_DIR"' EXIT
# Pre-render every fixture ONCE (fast: no re-render per assertion) and HARD-ABORT loudly on any render
# error, so a transient/real helm failure can never masquerade as a silent "needle absent" assertion.
_prerender() {
  local f
  for f in "$@"; do
    if ! helm template testrel "$CHART" -f "$FIX/$f" --namespace testns >"$RENDER_DIR/$f" 2>"$RENDER_DIR/$f.err"; then
      echo "RENDER-ERROR ($f):"; cat "$RENDER_DIR/$f.err"; echo "== ABORT: fixture failed to render =="; exit 2
    fi
  done
}
_render() { cat "$RENDER_DIR/$1"; }

assert_contains() { # <fixture> <needle> <label>
  if _render "$1" | grep -qF -- "$2"; then echo "ok: $3"; else echo "FAIL: $3 — '$2' absent in $1"; FAILS=$((FAILS+1)); fi; }
assert_absent() {
  if _render "$1" | grep -qF -- "$2"; then echo "FAIL: $3 — '$2' present in $1 (should be absent)"; FAILS=$((FAILS+1)); else echo "ok: $3"; fi; }
assert_kubeconform() { # <fixture>
  local out; out=$(_render "$1" | kubeconform -strict -summary -ignore-missing-schemas 2>&1)
  if echo "$out" | grep -q "Invalid: 0" && echo "$out" | grep -q "Errors: 0"; then echo "ok: kubeconform $1"; else echo "FAIL: kubeconform $1"; echo "$out"; FAILS=$((FAILS+1)); fi; }

echo "== lint =="; helm lint "$CHART" || FAILS=$((FAILS+1))
_prerender minimal.yaml full.yaml nginx.yaml storage-noPublic.yaml no-sidecar.yaml notls.yaml litestream.yaml backup-mirror.yaml placement.yaml hostnetwork-ingress.yaml

# --- version sync: appVersion IS the deployed image tag ---
# values.yaml ships image.tag:"" so both drust containers fall back to
# .Chart.AppVersion. That makes appVersion load-bearing rather than decorative:
# `helm install` pulls whatever it says. It read 1.49.4 for nine releases while
# 1.58.x shipped, because the real tag was a second hardcoded field nobody
# thought to bump. These two assertions are the whole automation — without them
# the fallback just moves the drift to one field instead of two.
REPO_ROOT="$(cd "$CHART/../../.." && pwd)"
APPV="$(awk -F'"' '/^appVersion:/{print $2; exit}' "$CHART/Chart.yaml")"
CARGOV="$(awk -F'"' '/^version *=/{print $2; exit}' "$REPO_ROOT/Cargo.toml")"
if [ -n "$APPV" ] && [ "$APPV" = "$CARGOV" ]; then
  echo "ok: Chart appVersion ($APPV) matches Cargo.toml"
else
  echo "FAIL: Chart appVersion '$APPV' != Cargo.toml version '$CARGOV' — helm install would deploy the wrong binary"
  FAILS=$((FAILS+1))
fi
assert_contains minimal.yaml "drust:$APPV" "image tag follows appVersion when values.image.tag is empty"
assert_absent   minimal.yaml "drust:\"\""  "empty image.tag never renders literally"

# --- Task 1 / Issue #2: namespace lifecycle (default OFF; opt-in Namespace is deletion-protected) ---
assert_absent   minimal.yaml "kind: Namespace" "no Namespace by default (createNamespace omitted => false)"
assert_absent   full.yaml    "kind: Namespace" "no Namespace when createNamespace=false"
assert_contains nginx.yaml   "kind: Namespace" "Namespace rendered when createNamespace=true (opt-in)"
assert_contains nginx.yaml   "helm.sh/resource-policy: keep" "opt-in Namespace is deletion-protected (uninstall won't reap PVCs)"
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
# #935 — sidecar no longer hardcodes _trash retention; the in-process janitor
# (DRUST_TRASH_RETENTION_DAYS) is the sole sweeper on every target.
assert_absent full.yaml "/data/_trash" "sidecar no longer sweeps _trash by path (#935)"
assert_absent full.yaml "-mtime"       "sidecar has no hardcoded trash retention flag (#935)"
assert_contains full.yaml "mc mb --ignore-existing drust/public" "minio-init creates the literal public bucket"

# --- Issue #1: minio-init Job must not break install (env order) or eat live traffic (labels) ---
# defect 1 — kubelet $(VAR) expansion is order-sensitive: BOTH AK AND SK must precede
# MC_HOST_drust, else the container sees a literal "$(AK)"/"$(SK)" and mc auth loops forever.
if _render full.yaml | awk '/name: AK$/{a=NR} /name: SK$/{s=NR} /name: MC_HOST_drust$/{m=NR} END{exit (a&&s&&m&&a<m&&s<m)?0:1}'; then
  echo "ok: minio-init defines AK and SK before MC_HOST_drust"; else echo "FAIL: AK/SK do not both precede MC_HOST_drust — kubelet leaves a literal \$(AK)/\$(SK) in the URL"; FAILS=$((FAILS+1)); fi
# defect 2 — the Job POD TEMPLATE must not wear drust.selectorLabels (the top-level Job
# metadata legitimately carries them; only the pod-template copy adopts it into the Service).
if _render full.yaml | awk '/^kind: Job$/{j=1} j&&/^  template:/{t=1} t&&/app.kubernetes.io\/name: drust/{bad=1} /^---$/{j=0;t=0} END{exit (bad)?1:0}'; then
  echo "ok: minio-init pod template does not wear drust selector labels"; else echo "FAIL: minio-init pod template carries drust.selectorLabels — it joins the drust Service endpoints"; FAILS=$((FAILS+1)); fi
assert_contains full.yaml "app.kubernetes.io/name: minio-init"   "minio-init pod carries dedicated labels"
# the MinIO ingress NP must admit the EXACT minio-init label — scope to the minio NP doc, not a
# whole-file grep of a comment/label that also appears on the Job pod template (a podSelector typo
# like minio-init-x would otherwise still pass).
if _render full.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-minio\n/{print}' | grep -qE '^[[:space:]]+app\.kubernetes\.io/name: minio-init$'; then
  echo "ok: minio NetworkPolicy admits the exact minio-init label to port 9000"; else echo "FAIL: minio NP ingress does not admit the exact minio-init podSelector"; FAILS=$((FAILS+1)); fi
# the minio-init pod is itself NP-governed (dedicated egress-only policy), not left unrestricted.
assert_contains full.yaml    "testrel-minio-init" "minio-init pod has its own NetworkPolicy (scoped egress)"
assert_absent   minimal.yaml "minio-init"         "no minio-init Job/NP when storage off"

# --- Issue #3: file URLs + non-TLS admin login must actually work on k8s ---
assert_contains full.yaml   "name: DRUST_PUBLIC_BASE_URL"       "public base URL wired (file URLs use the ingress host, not localhost:8793)"
# scope the scheme check to the DRUST_PUBLIC_BASE_URL VALUE — full.yaml's https://full.example.test
# also appears as DRUST_PUBLIC_URL, so a whole-file grep would miss a scheme regression on this env.
if _render full.yaml | awk '/name: DRUST_PUBLIC_BASE_URL$/{getline; if($0 ~ /https:\/\/full\.example\.test/) ok=1} END{exit ok?0:1}'; then
  echo "ok: DRUST_PUBLIC_BASE_URL uses https when TLS on"; else echo "FAIL: DRUST_PUBLIC_BASE_URL is not https on a TLS deployment"; FAILS=$((FAILS+1)); fi
assert_contains notls.yaml  "name: DRUST_DEV_NO_SECURE_COOKIES" "secure-cookie escape hatch wired when tls.enabled=false"
if _render notls.yaml | awk '/name: DRUST_PUBLIC_BASE_URL$/{getline; if($0 ~ /"http:\/\/notls\.example\.test"$/) ok=1} END{exit ok?0:1}'; then
  echo "ok: DRUST_PUBLIC_BASE_URL uses http (exact value) when TLS off"; else echo "FAIL: DRUST_PUBLIC_BASE_URL wrong value/scheme when TLS off"; FAILS=$((FAILS+1)); fi
assert_absent   full.yaml   "name: DRUST_DEV_NO_SECURE_COOKIES" "no dev-cookie env when TLS on"

# --- B1: Litestream sidecar + restore init (opt-in; default OFF) ---
assert_contains litestream.yaml "name: litestream"                              "litestream sidecar rendered"
assert_contains litestream.yaml "litestream/litestream"                         "litestream image wired"
assert_contains litestream.yaml "replicate -config /etc/litestream/litestream.yml" "sidecar runs native dir-mode replicate"
assert_contains litestream.yaml "kind: ConfigMap"                               "litestream config ConfigMap rendered"
assert_contains litestream.yaml "dir: /data/tenants"                            "config covers tenants dir (dynamic discovery)"
assert_contains litestream.yaml "watch: true"                                   "directory watcher on (post-boot tenants, no restart)"
# CRITICAL regression guard — the tenant glob MUST be a basename pattern. VERIFIED against the real
# litestream 0.5.15 binary: a slash-form ("*/data.sqlite" / "**/data.sqlite") enrolls ZERO tenant DBs,
# so every tenant's data.sqlite is silently unbacked while meta.sqlite still ships (restore looks
# healthy but every tenant comes back empty — worst-case disaster recovery).
assert_contains litestream.yaml 'pattern: "*.sqlite"'      "tenant glob is basename *.sqlite (enrolls tenant DBs)"
assert_absent   litestream.yaml 'pattern: "*/data.sqlite"' "tenant glob is NOT the broken slash-form"
assert_contains litestream.yaml "name: litestream-restore"                      "restore initContainer rendered"
assert_contains litestream.yaml "name: litestream-enumerate"                    "enumerate initContainer rendered"
assert_contains litestream.yaml "LITESTREAM_ACCESS_KEY_ID"                      "litestream creds via env (secretKeyRef)"
assert_contains litestream.yaml "backup-s3-access-key"                          "backup Secret creds key present"
# scope RO-root to the litestream SIDECAR container (not the always-present drust container / init
# containers) — a whole-file grep would stay green even if the sidecar alone lost readOnlyRootFilesystem.
if _render litestream.yaml | awk '/^[[:space:]]*- name: litestream$/{s=1;next} s&&/^[[:space:]]*- name: [a-z]/{s=0} s&&/readOnlyRootFilesystem: true/{f=1} END{exit f?0:1}'; then
  echo "ok: litestream SIDECAR container has readOnlyRootFilesystem"; else echo "FAIL: litestream sidecar container missing readOnlyRootFilesystem"; FAILS=$((FAILS+1)); fi
# creds must NOT leak into the ConfigMap — scope to the ConfigMap doc
if _render litestream.yaml | awk 'BEGIN{RS="---\n"} /kind: ConfigMap/{print}' | grep -q "LSAK"; then
  echo "FAIL: backup creds leaked into litestream ConfigMap"; FAILS=$((FAILS+1)); else echo "ok: no creds in litestream ConfigMap"; fi
# NP egress present EVEN WITH allowInternetEgress:false (decoupling) — scope to drust NP doc. With
# egress OFF the fixture sets destinationCIDRs, so the rule must be SCOPED to that CIDR and must NOT
# punch a 0.0.0.0/0 hole on the drust pod (which shares netns with the sidecar / WASM / webhooks).
assert_contains litestream.yaml "external backup S3"                            "litestream egress rule present"
if _render litestream.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-drust\n/{print}' | grep -q "port: 443"; then
  echo "ok: litestream egress opens 443 with internet egress OFF"; else echo "FAIL: litestream egress missing 443"; FAILS=$((FAILS+1)); fi
if _render litestream.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-drust\n/{print}' | grep -q "203.0.113.0/24"; then
  echo "ok: litestream egress SCOPED to destinationCIDRs when egress off"; else echo "FAIL: litestream egress not scoped to destinationCIDRs"; FAILS=$((FAILS+1)); fi
if _render litestream.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-drust\n/{print}' | grep -q "cidr: 0.0.0.0/0"; then
  echo "FAIL: drust NP punches 0.0.0.0/0 egress with allowInternetEgress:false (SSRF surface reopened)"; FAILS=$((FAILS+1)); else echo "ok: no 0.0.0.0/0 egress hole on drust pod when egress off"; fi
# fail-closed POSITIVE tests: these insecure configs MUST refuse to render (helm template must fail).
if helm template testrel "$CHART" -f "$FIX/litestream.yaml" --set-json 'backup.external.destinationCIDRs=[]' --namespace testns >/dev/null 2>&1; then
  echo "FAIL: litestream + egress off + no destinationCIDRs was accepted (should fail-closed)"; FAILS=$((FAILS+1)); else echo "ok: fail-closed — litestream + egress off + no CIDRs is refused"; fi
if helm template testrel "$CHART" -f "$FIX/litestream.yaml" --set-json 'backup.external.destinationCIDRs=["0.0.0.0/0"]' --namespace testns >/dev/null 2>&1; then
  echo "FAIL: destinationCIDRs=[0.0.0.0/0] was accepted (unrestricted egress, defeats scoping)"; FAILS=$((FAILS+1)); else echo "ok: destinationCIDRs=0.0.0.0/0 is refused"; fi
assert_absent minimal.yaml "name: litestream"          "no litestream sidecar by default"
assert_absent full.yaml    "name: litestream"          "no litestream in full fixture (default off)"
assert_absent minimal.yaml "backup-s3-access-key"      "no backup Secret keys by default"
assert_absent full.yaml    "name: litestream-restore"  "no restore init in full fixture (default off)"

# --- B2: upload-backup mc-mirror CronJob (opt-in; needs storage) ---
assert_contains backup-mirror.yaml "kind: CronJob"                             "objectMirror CronJob rendered"
assert_contains backup-mirror.yaml "mc mirror --overwrite"                     "mc mirror command present"
assert_contains backup-mirror.yaml 'schedule: "0 * * * *"'                     "hourly mirror schedule"
assert_contains backup-mirror.yaml "until mc ls src"                           "first-connect retry loop (CNI NP lag)"
assert_contains backup-mirror.yaml "backup-s3-access-key"                      "dest creds via backup Secret"
assert_contains backup-mirror.yaml "app.kubernetes.io/name: backup-mirror"     "mirror Job carries dedicated labels"
assert_contains backup-mirror.yaml "automountServiceAccountToken: false"       "mirror pod drops SA token"
# env order: SRC_AK/SRC_SK before MC_HOST_src (kubelet $(VAR) gotcha)
if _render backup-mirror.yaml | awk '/name: SRC_AK$/{a=NR} /name: SRC_SK$/{s=NR} /name: MC_HOST_src$/{m=NR} END{exit (a&&s&&m&&a<m&&s<m)?0:1}'; then
  echo "ok: SRC_AK/SRC_SK precede MC_HOST_src"; else echo "FAIL: SRC creds not before MC_HOST_src"; FAILS=$((FAILS+1)); fi
# mirror POD TEMPLATE must not wear drust/minio selector labels (would join a Service). The CronJob's
# OWN metadata legitimately carries drust.labels, and the drust STS (also in this render) has its own
# pod template — so isolate the CronJob record, then walk ONLY its pod template (template: -> spec:).
if _render backup-mirror.yaml | awk 'BEGIN{RS="---\n"} /kind: CronJob/{
    n=split($0,L,"\n"); t=0;
    for(i=1;i<=n;i++){
      if(L[i] ~ /^[[:space:]]*template:[[:space:]]*$/){t=1; continue}
      if(t && L[i] ~ /^[[:space:]]*spec:[[:space:]]*$/){t=0}
      if(t && L[i] ~ /app\.kubernetes\.io\/name: (drust|minio)([[:space:]]|$)/){bad=1}
    }
  } END{exit bad?1:0}'; then
  echo "ok: mirror pod template wears only its dedicated label (not drust/minio)"; else echo "FAIL: mirror pod template carries drust/minio selector labels — joins a Service"; FAILS=$((FAILS+1)); fi
# dedicated scoped NP exists
if _render backup-mirror.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-backup-mirror\n/{f=1} END{exit f?0:1}'; then
  echo "ok: dedicated backup-mirror NetworkPolicy rendered"; else echo "FAIL: no backup-mirror NetworkPolicy"; FAILS=$((FAILS+1)); fi
# minio NP admits the EXACT backup-mirror label (scope to minio NP doc)
if _render backup-mirror.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-minio\n/{print}' | grep -qE '^[[:space:]]+app\.kubernetes\.io/name: backup-mirror$'; then
  echo "ok: minio NP admits backup-mirror label to 9000"; else echo "FAIL: minio NP does not admit backup-mirror"; FAILS=$((FAILS+1)); fi
assert_absent litestream.yaml "kind: CronJob"          "objectMirror absent when storage off"
assert_absent minimal.yaml    "backup-mirror"          "no objectMirror by default"
assert_absent full.yaml       "backup-mirror"          "no objectMirror in full fixture (default off)"

# --- B3: scheduling passthrough (default empty => absent) ---
assert_contains placement.yaml "nodeSelector"               "scheduling.nodeSelector rendered when set"
assert_contains placement.yaml "topologySpreadConstraints"  "scheduling.topologySpread rendered when set"
assert_contains placement.yaml "tolerations"                "scheduling.tolerations rendered when set"
# The drust/minio StatefulSet metadata.name renders BARE (`drust` / `minio`), but every record also
# carries `app.kubernetes.io/name: drust` (labels helper) and a `- name: drust` container. Isolate each
# STS record, then require the EXACT 2-space metadata.name line AND a nodeSelector in that same record.
if _render placement.yaml | awk 'BEGIN{RS="---\n"} /kind: StatefulSet/{
    n=split($0,L,"\n"); me=0; ns=0;
    for(i=1;i<=n;i++){ if(L[i]=="  name: drust") me=1; if(L[i] ~ /nodeSelector:/) ns=1 }
    if(me&&ns) ok=1
  } END{exit ok?0:1}'; then
  echo "ok: drust STS honors scheduling.drust"; else echo "FAIL: drust nodeSelector not wired"; FAILS=$((FAILS+1)); fi
if _render placement.yaml | awk 'BEGIN{RS="---\n"} /kind: StatefulSet/{
    n=split($0,L,"\n"); me=0; ns=0;
    for(i=1;i<=n;i++){ if(L[i]=="  name: minio") me=1; if(L[i] ~ /nodeSelector:/) ns=1 }
    if(me&&ns) ok=1
  } END{exit ok?0:1}'; then
  echo "ok: minio STS honors scheduling.minio"; else echo "FAIL: minio nodeSelector not wired"; FAILS=$((FAILS+1)); fi
assert_absent minimal.yaml "nodeSelector"               "no nodeSelector by default (empty {} => omitted)"
assert_absent full.yaml    "topologySpreadConstraints"  "no topologySpread by default"

# --- Issue #8: hostNetwork ingress controller needs an ipBlock peer ---
# A hostNetwork controller carries no pod IP, so `namespaceSelector` can never
# resolve it and every request is REJECTed — 502 that reads like the app is down.
# Two independent paths break: the admin plane (drust:47826) and /public/*
# (minio:9000). Assert BOTH policies carry the CIDRs, because fixing only the
# one you happened to test leaves the other silently black-holed.
assert_absent   minimal.yaml            "ipBlock: { cidr:" "no hostNetwork ipBlock by default (empty list => omitted)"
if _render hostnetwork-ingress.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-drust/{
    if ($0 ~ /10\.42\.0\.0\/32/ && $0 ~ /10\.0\.2\.218\/32/ && $0 ~ /port: 47826/) ok=1
  } END{exit ok?0:1}'; then
  echo "ok: drust NetworkPolicy admits hostNetworkIngressCIDRs on 47826"
else echo "FAIL: drust NetworkPolicy missing hostNetwork ipBlock peers"; FAILS=$((FAILS+1)); fi
if _render hostnetwork-ingress.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-minio/{
    if ($0 ~ /10\.42\.0\.0\/32/ && $0 ~ /10\.0\.2\.218\/32/ && $0 ~ /port: 9000/) ok=1
  } END{exit ok?0:1}'; then
  echo "ok: minio NetworkPolicy admits hostNetworkIngressCIDRs on 9000 (/public path)"
else echo "FAIL: minio NetworkPolicy missing hostNetwork ipBlock peers"; FAILS=$((FAILS+1)); fi
# The namespaceSelector peer must SURVIVE — the ipBlock widens the allowed
# sources, it does not replace them. A pod-network controller must keep working.
assert_contains hostnetwork-ingress.yaml "kubernetes.io/metadata.name: ingress-nginx" "namespaceSelector peer retained alongside the ipBlock"
# Fail-closed: this rule fronts the admin plane, so a catch-all is refused —
# same discipline as backup.external.destinationCIDRs.
if helm template t "$CHART" --namespace testns \
     --set ingress.host=x.test \
     --set 'networkPolicy.hostNetworkIngressCIDRs={0.0.0.0/0}' >/dev/null 2>&1; then
  echo "FAIL: hostNetworkIngressCIDRs accepted 0.0.0.0/0 — that admits every pod in the cluster"; FAILS=$((FAILS+1))
else echo "ok: hostNetworkIngressCIDRs rejects 0.0.0.0/0 (fail-closed)"; fi

# --- Task 10: full-matrix kubeconform ---
for f in minimal full nginx storage-noPublic no-sidecar notls litestream backup-mirror placement hostnetwork-ingress; do assert_kubeconform "$f.yaml"; done
# README exists
[ -f "$CHART/README.md" ] && echo "ok: README present" || { echo "FAIL: README missing"; FAILS=$((FAILS+1)); }

echo "== $FAILS failure(s) =="
exit $((FAILS>0))
