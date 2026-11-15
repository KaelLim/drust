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
# One NetworkPolicy record by name (testrel-<name>), and its ingress section.
_np() { _render "$1" | awk -v n="name: testrel-$2" 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && index($0, n "\n"){print}'; }
_np_ingress() { _np "$1" "$2" | awk '/^  ingress:/{on=1} /^  egress:/{on=0} on'; }
# One record by kind and 2-space metadata.name.
_rec() { _render "$1" | awk -v k="kind: $2" -v n="  name: $3" 'BEGIN{RS="---\n"} index($0, k "\n") && index($0, "\n" n "\n"){print}'; }
assert_kubeconform() { # <fixture>
  local out; out=$(_render "$1" | kubeconform -strict -summary -ignore-missing-schemas 2>&1)
  if echo "$out" | grep -q "Invalid: 0" && echo "$out" | grep -q "Errors: 0"; then echo "ok: kubeconform $1"; else echo "FAIL: kubeconform $1"; echo "$out"; FAILS=$((FAILS+1)); fi; }

echo "== lint =="; helm lint "$CHART" || FAILS=$((FAILS+1))
_prerender minimal.yaml full.yaml nginx.yaml storage-noPublic.yaml no-sidecar.yaml notls.yaml litestream.yaml backup-mirror.yaml placement.yaml hostnetwork-ingress.yaml existing-secret.yaml
ALL_FIXTURES="minimal full nginx storage-noPublic no-sidecar notls litestream backup-mirror placement hostnetwork-ingress existing-secret"

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
# drust needs no Garage admin API since v1.67.0 (both GARAGE_ADMIN_* unset = not configured);
# the chart's never-dialed placeholders are gone, from the env and from the Secret.
assert_absent   full.yaml    "GARAGE_ADMIN_"                  "no GARAGE_ADMIN_* env when storage on"
assert_absent   full.yaml    "admin-endpoint"                 "no admin-endpoint/admin-token placeholder in the Secret"
assert_contains full.yaml    "name: GARAGE_S3_ACCESS_KEY"     "s3 access key env present when storage on"
assert_absent   minimal.yaml "GARAGE_ADMIN_"                  "no GARAGE_ADMIN_* env when storage off"

# --- Task 4 assertions (the bundled RustFS) ---
assert_contains full.yaml    "port: 9000"           "store service port"
assert_absent   minimal.yaml "rustfs"               "no rustfs when storage off"

# --- Task 5 assertions (bucket/key init hook Jobs) ---
assert_contains full.yaml "name: rustfs-init"                            "rustfs-init job rendered"
# post-rollback too: RustFS holds drust's secret as rustfs-init last set it, so a rollback that
# restores an older storage.secretKey must re-run it. Exact line, so a dropped event fails.
if _rec full.yaml Job rustfs-init | grep -qx '    helm.sh/hook: post-install,post-upgrade,post-rollback'; then
  echo "ok: rustfs-init is a post-install/post-upgrade/post-rollback hook"; else echo "FAIL: rustfs-init hook events are not exactly post-install,post-upgrade,post-rollback"; FAILS=$((FAILS+1)); fi
# Without before-hook-creation the next upgrade fails on "Job already exists".
if _rec full.yaml Job rustfs-init | grep -qx '    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded'; then
  echo "ok: rustfs-init hook is deleted before re-creation and after success"; else echo "FAIL: rustfs-init hook-delete-policy is not before-hook-creation,hook-succeeded"; FAILS=$((FAILS+1)); fi
# Never keeps each failed attempt's pod, so its log outlives the Job giving up; with OnFailure
# the Job controller deletes the one pod at backoffLimit.
if _rec full.yaml Job rustfs-init | grep -qx '      restartPolicy: Never'; then
  echo "ok: rustfs-init keeps its failed pods (restartPolicy: Never)"; else echo "FAIL: rustfs-init restartPolicy is not Never"; FAILS=$((FAILS+1)); fi
assert_contains full.yaml "exec /bin/sh /init/init.sh"                   "rustfs-init runs the shared Compose init.sh"
assert_absent   minimal.yaml "name: rustfs-init"                         "no init job when storage off"
_cm() { _render "$1" | awk -v n="name: testrel-$2" 'BEGIN{RS="---\n"} /kind: ConfigMap\n/ && index($0, n "\n"){print}'; }
if _cm full.yaml rustfs-init | grep -q '^  public-read.json:'; then
  echo "ok: rustfs-init ConfigMap carries public-read.json with publicFiles on"; else echo "FAIL: rustfs-init ConfigMap lacks public-read.json"; FAILS=$((FAILS+1)); fi
if _cm storage-noPublic.yaml rustfs-init | grep -q 'public-read.json:'; then
  echo "FAIL: rustfs-init ConfigMap carries public-read.json with publicFiles off"; FAILS=$((FAILS+1)); else echo "ok: no public-read.json with publicFiles off (init.sh removes the anonymous policy)"; fi
if _cm storage-noPublic.yaml rustfs-init | grep -q '^  init.sh:'; then
  echo "ok: storage-noPublic still renders the rustfs-init ConfigMap"; else echo "FAIL: storage-noPublic has no rustfs-init ConfigMap"; FAILS=$((FAILS+1)); fi

# --- Task 6 assertions ---
assert_contains minimal.yaml "kind: Ingress"                          "ingress rendered"
assert_contains minimal.yaml "127.0.0.1:47826"                        "host rewrite value present"
assert_contains minimal.yaml "kind: Middleware"                       "traefik middleware for host rewrite"
assert_contains full.yaml    "cert-manager.io/cluster-issuer: letsencrypt" "cert-manager issuer when tls.enabled"
assert_contains full.yaml    "path: /public"                          "public path when publicFiles on"
# /public goes to the public-proxy Caddy, never to an S3 port: the store itself serves markup
# with no CSP and honours ?response-content-type= (stored XSS on the admin origin).
if _render full.yaml | awk 'BEGIN{RS="---\n"} /kind: Ingress\n/{print}' | awk '/- path: \/public$/{p=1} p&&/name: public-proxy$/{n=1} p&&n&&/number: 8080/{ok=1} p&&/- path: \/$/{exit} END{exit ok?0:1}'; then
  echo "ok: /public Ingress backend is public-proxy:8080"; else echo "FAIL: /public Ingress backend is not public-proxy:8080"; FAILS=$((FAILS+1)); fi
assert_absent   full.yaml    "number: 9000"                           "no Ingress backend on an S3 port"
assert_absent   minimal.yaml "path: /public"                          "no public path when publicFiles off"
assert_contains nginx.yaml "nginx.ingress.kubernetes.io/upstream-vhost: 127.0.0.1:47826" "nginx upstream-vhost host rewrite"
assert_absent   nginx.yaml "kind: Middleware" "no traefik middleware for nginx controller"

# --- Task 7 assertions ---
assert_contains minimal.yaml "kind: NetworkPolicy"      "networkpolicy rendered"
assert_contains minimal.yaml "port: 53"                 "DNS egress allowed"
assert_contains full.yaml    "10.42.0.0/16"             "cluster pod CIDR in egress except"
if _np full.yaml drust | awk '/^  egress:/{on=1} on' | awk '/app\.kubernetes\.io\/name: rustfs$/{r=1} r&&/port: 9000/{ok=1} END{exit ok?0:1}'; then
  echo "ok: drust NP egress reaches rustfs:9000"; else echo "FAIL: drust NP egress does not select rustfs on 9000"; FAILS=$((FAILS+1)); fi

# --- Task 8 assertions ---
assert_contains full.yaml    "name: maintenance"        "maintenance sidecar rendered when enabled"
assert_contains full.yaml    "drust_session_janitor"    "sidecar runs session janitor"
assert_absent no-sidecar.yaml "name: maintenance" "no sidecar when disabled"

# --- Task 9 assertions ---
assert_contains full.yaml    "kind: CronJob"                    "backup cronjob when snapshot class set"
assert_contains full.yaml    "kind: VolumeSnapshot"             "cronjob creates a VolumeSnapshot manifest"
assert_contains full.yaml    "csi-hostpath-snapclass"           "snapshot class wired"
assert_contains full.yaml    'schedule: "0 3 * * *"'            "backup schedule wired"
assert_contains full.yaml    "alpine/kubectl:1.36.4@sha256:a2cd8ee034cbe04d651e565b3373299b31921de5c2af86490559e21b3e197808" "snapshot CronJob uses a pullable kubectl, pinned tag+digest"
assert_absent   full.yaml    "bitnami/kubectl"                  "no unpullable bitnami/kubectl"
assert_absent   minimal.yaml "kind: CronJob"                    "no backup cronjob when class empty"

# --- Review-fix regression guards ---
# HIGH: backup RoleBinding subject must carry a namespace (else RBAC never matches the SA)
if _render full.yaml | awk '/kind: RoleBinding/{r=1} r&&/kind: ServiceAccount/{s=1} r&&s&&/^[[:space:]]*namespace:/{print "OK"; exit}' | grep -q OK; then
  echo "ok: backup RoleBinding subject has namespace"; else echo "FAIL: backup RoleBinding subject missing namespace"; FAILS=$((FAILS+1)); fi
# #935 — sidecar no longer hardcodes _trash retention; the in-process janitor
# (DRUST_TRASH_RETENTION_DAYS) is the sole sweeper on every target.
assert_absent full.yaml "/data/_trash" "sidecar no longer sweeps _trash by path (#935)"
assert_absent full.yaml "-mtime"       "sidecar has no hardcoded trash retention flag (#935)"

# --- Issue #1: init Jobs must not eat live traffic (labels) and must be NP-governed ---
# Pod-template labels, per kind: no Job, CronJob or Deployment pod template may wear drust's or
# rustfs's name label (it would join that Service's endpoints; a probeless Job pod counts as Ready
# and ate ~50% of live traffic once). Anchored, so rustfs-init does not trip on rustfs. The rustfs
# StatefulSet's pod template must not wear drust's.
_podlabels_ok() { _render "$1" | awk 'BEGIN{RS="---\n"} {
    n=split($0,L,"\n"); kind=""; name="";
    for(i=1;i<=n;i++){ if(L[i] ~ /^kind: /) kind=substr(L[i],7); if(L[i] ~ /^  name: /) name=substr(L[i],9) }
    if(kind!="Job" && kind!="CronJob" && kind!="Deployment" && !(kind=="StatefulSet" && name=="rustfs")) next;
    t=0;
    for(i=1;i<=n;i++){
      if(L[i] ~ /^[[:space:]]*template:[[:space:]]*$/){t=1; continue}
      if(t && L[i] ~ /^[[:space:]]*spec:[[:space:]]*$/){t=0}
      if(!t) continue;
      if(kind=="StatefulSet" && L[i] ~ /name: drust$/){bad=1; print "  " kind "/" name ": " L[i]}
      if(kind!="StatefulSet" && L[i] ~ /app\.kubernetes\.io\/name: (drust|rustfs)$/){bad=1; print "  " kind "/" name ": " L[i]}
    }
  } END{exit bad?1:0}'; }
for f in full.yaml backup-mirror.yaml existing-secret.yaml; do
  if out=$(_podlabels_ok "$f"); then
    echo "ok: no Job/CronJob/Deployment pod template wears a drust/rustfs label, rustfs pod not drust's ($f)"
  else echo "FAIL: a pod template wears a selector label that joins another Service ($f):"; echo "$out"; FAILS=$((FAILS+1)); fi
done
assert_contains full.yaml         "app.kubernetes.io/name: rustfs-init"  "rustfs-init pod carries dedicated labels"
# The rustfs NP must admit the EXACT init label — scoped to that NP record, not a whole-file grep
# (a podSelector typo like rustfs-init-x would otherwise still pass on the Job's own label).
if _np_ingress full.yaml rustfs | grep -qE '^[[:space:]]+app\.kubernetes\.io/name: rustfs-init$'; then
  echo "ok: rustfs NetworkPolicy admits the exact rustfs-init label to port 9000"; else echo "FAIL: rustfs NP ingress does not admit the exact rustfs-init podSelector"; FAILS=$((FAILS+1)); fi
# the init pods are themselves NP-governed (dedicated egress-only policy), not left unrestricted.
assert_contains full.yaml         "testrel-rustfs-init" "rustfs-init pod has its own NetworkPolicy (scoped egress)"
if _np full.yaml rustfs-init | awk '/^  egress:/{on=1} on' | awk '/app\.kubernetes\.io\/name: rustfs$/{r=1} r&&/port: 9000/{ok=1} END{exit ok?0:1}' &&
   ! _np full.yaml rustfs-init | grep -q '^  ingress:'; then
  echo "ok: rustfs-init NP: egress DNS + rustfs:9000, no ingress rule"; else echo "FAIL: rustfs-init NP shape wrong"; FAILS=$((FAILS+1)); fi

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

# --- DRUST_TRUSTED_PROXIES: the ingress controller is the one proxy appending to XFF ---
# Unset, the pod inherits the image's 0 and every client shares the controller pod's
# rate-limit bucket. Scoped to the env entry itself (one flow-style line), so a stray "1"
# elsewhere cannot satisfy it.
for f in minimal.yaml full.yaml; do
  if _render "$f" | awk '/name: DRUST_TRUSTED_PROXIES,/{n++; if($0 ~ /value: "1" }$/) ok++} END{exit (n==1&&ok==1)?0:1}'; then
    echo "ok: DRUST_TRUSTED_PROXIES=\"1\" on the drust container ($f)"; else echo "FAIL: DRUST_TRUSTED_PROXIES missing, duplicated or not \"1\" in $f"; FAILS=$((FAILS+1)); fi
done
# Both fixtures use the default 1, so render a non-default value: a hard-coded "1" must fail.
if helm template testrel "$CHART" -f "$FIX/minimal.yaml" --namespace testns --set ingress.trustedProxies=2 2>/dev/null \
     | awk '/name: DRUST_TRUSTED_PROXIES,/{n++; if($0 ~ /value: "2" }$/) ok++} END{exit (n==1&&ok==1)?0:1}'; then
  echo "ok: DRUST_TRUSTED_PROXIES follows ingress.trustedProxies (2)"; else echo "FAIL: DRUST_TRUSTED_PROXIES does not follow ingress.trustedProxies=2"; FAILS=$((FAILS+1)); fi
# The chart owns the variable now: the same name in extraEnv is refused, not rendered twice.
if out=$(helm template testrel "$CHART" -f "$FIX/minimal.yaml" --namespace testns \
           --set-json 'extraEnv=[{"name":"DRUST_TRUSTED_PROXIES","value":"2"}]' 2>&1); then
  echo "FAIL: extraEnv naming DRUST_TRUSTED_PROXIES was accepted"; FAILS=$((FAILS+1))
elif printf '%s' "$out" | grep -qF 'move the value there'; then echo "ok: extraEnv naming DRUST_TRUSTED_PROXIES is refused"
else echo "FAIL: extraEnv DRUST_TRUSTED_PROXIES refused without the expected message"; FAILS=$((FAILS+1)); fi

# --- B1: Litestream sidecar + restore init (opt-in; default OFF) ---
assert_contains litestream.yaml "name: litestream"                              "litestream sidecar rendered"
assert_contains litestream.yaml "litestream/litestream:0.5.15@sha256:f45ca298a567bef6edd23d43429b5f80721473a9a9719e467f11d7888999403e" "litestream image pinned tag+digest"
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
# enumerate runs rclone (the mc client images can no longer be pulled), pinned by digest: it holds
# the backup-S3 key. Remote "bk" comes from env only; the keys arrive by secretKeyRef.
assert_contains litestream.yaml "rclone/rclone:1.75.2@sha256:2687085f718d3c628f7fdfb77c52a1d344332aed543110bb88088f2c70d43eb5" "enumerate image is rclone, pinned tag+digest"
assert_contains litestream.yaml 'rclone lsf --dirs-only "bk:${DEST_BUCKET}/${REPLICA_PREFIX}/tenants/"' "enumerate lists tenant prefixes with rclone"
assert_contains litestream.yaml 'until rclone lsf "bk:${DEST_BUCKET}/${REPLICA_PREFIX}/" --max-depth 1' "enumerate probes its own prefix, not the bucket list"
assert_contains litestream.yaml "name: RCLONE_CONFIG_BK_ACCESS_KEY_ID"          "enumerate gets the backup key via env"
assert_contains litestream.yaml "name: RCLONE_CONFIG, value: /dev/null"         "enumerate reads no rclone config file"
assert_absent   litestream.yaml "mc "                                           "no mc left in the litestream render"
# the rclone init container must not inherit drust's image.pullPolicy (Never would strand it)
if _render litestream.yaml | awk '/^[[:space:]]*- name: litestream-enumerate$/{s=1;next} s&&/^[[:space:]]*- name: [a-z]/{s=0} s&&/^[[:space:]]*imagePullPolicy:/{f=1} END{exit f?1:0}'; then
  echo "ok: litestream-enumerate sets no imagePullPolicy"; else echo "FAIL: litestream-enumerate inherits an imagePullPolicy"; FAILS=$((FAILS+1)); fi
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

# --- B2: upload-backup copy CronJob (rclone; opt-in; needs storage) ---
assert_contains backup-mirror.yaml "kind: CronJob"                             "objectMirror CronJob rendered"
assert_contains backup-mirror.yaml 'rclone copy -M src:public  "$dst/objects/public"'   "mirror copies public with metadata (-M)"
assert_contains backup-mirror.yaml 'rclone copy -M src:private "$dst/objects/private"'  "mirror copies private with metadata (-M)"
assert_absent   backup-mirror.yaml "rclone sync"                               "mirror never syncs (a source delete must not reach the backup)"
assert_contains backup-mirror.yaml 'name: RCLONE_S3_NO_CHECK_BUCKET, value: "true"' "mirror skips CreateBucket (a scoped key gets 403)"
assert_contains backup-mirror.yaml 'until rclone lsf "$dst/" --max-depth 1'      "mirror probes its backup prefix, not the bucket list"
assert_contains backup-mirror.yaml "rclone/rclone:1.75.2@sha256:2687085f718d3c628f7fdfb77c52a1d344332aed543110bb88088f2c70d43eb5" "mirror image is rclone, pinned tag+digest"
# no mc in the mirror CronJob record
if _render backup-mirror.yaml | awk 'BEGIN{RS="---\n"} /kind: CronJob/ && /name: testrel-backup-mirror\n/{print}' | grep -qE 'MC_HOST|mc alias|mc ls|mc mirror'; then
  echo "FAIL: mc still used by the backup-mirror CronJob"; FAILS=$((FAILS+1)); else echo "ok: no mc in the backup-mirror CronJob"; fi
assert_contains backup-mirror.yaml 'schedule: "0 * * * *"'                     "hourly mirror schedule"
assert_contains backup-mirror.yaml "until rclone lsf src:public"               "first-connect retry loop (CNI NP lag)"
assert_contains backup-mirror.yaml "backup-s3-access-key"                      "dest creds via backup Secret"
assert_contains backup-mirror.yaml "app.kubernetes.io/name: backup-mirror"     "mirror Job carries dedicated labels"
assert_contains backup-mirror.yaml "automountServiceAccountToken: false"       "mirror pod drops SA token"
# dedicated scoped NP exists
if _render backup-mirror.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-backup-mirror\n/{f=1} END{exit f?0:1}'; then
  echo "ok: dedicated backup-mirror NetworkPolicy rendered"; else echo "FAIL: no backup-mirror NetworkPolicy"; FAILS=$((FAILS+1)); fi
# the rustfs NP admits the EXACT backup-mirror label (scoped to that NP record)
if _np_ingress backup-mirror.yaml rustfs | grep -qE '^[[:space:]]+app\.kubernetes\.io/name: backup-mirror$'; then
  echo "ok: rustfs NP admits backup-mirror label to 9000"; else echo "FAIL: rustfs NP does not admit backup-mirror"; FAILS=$((FAILS+1)); fi
if _np backup-mirror.yaml backup-mirror | awk '/^  egress:/{on=1} on' | grep -qE '^[[:space:]]+app\.kubernetes\.io/name: rustfs$'; then
  echo "ok: backup-mirror NP egress selects rustfs"; else echo "FAIL: backup-mirror NP egress does not select rustfs"; FAILS=$((FAILS+1)); fi
# source = the bundled RustFS, read with drust's own key (s3-access-key), never a root key
_mirror() { _rec "$1" CronJob testrel-backup-mirror; }
if _mirror backup-mirror.yaml | grep -q 'name: RCLONE_CONFIG_SRC_PROVIDER, value: Other }' &&
   _mirror backup-mirror.yaml | grep -q 'name: RCLONE_CONFIG_SRC_ENDPOINT, value: "http://rustfs:9000" }'; then
  echo "ok: mirror source is rustfs:9000 (provider Other)"; else echo "FAIL: mirror source is not rustfs:9000 (provider Other)"; FAILS=$((FAILS+1)); fi
if _mirror backup-mirror.yaml | grep -q 'key: s3-access-key' && ! _mirror backup-mirror.yaml | grep -qE 'key: [a-z-]*root'; then
  echo "ok: mirror reads the store with s3-access-key and no root key"; else echo "FAIL: mirror store key wrong (missing s3-access-key, or a root key)"; FAILS=$((FAILS+1)); fi
assert_absent litestream.yaml "kind: CronJob"          "objectMirror absent when storage off"
assert_absent minimal.yaml    "backup-mirror"          "no objectMirror by default"
assert_absent full.yaml       "backup-mirror"          "no objectMirror in full fixture (default off)"

# --- B3: scheduling passthrough (default empty => absent) ---
assert_contains placement.yaml "nodeSelector"               "scheduling.nodeSelector rendered when set"
assert_contains placement.yaml "topologySpreadConstraints"  "scheduling.topologySpread rendered when set"
assert_contains placement.yaml "tolerations"                "scheduling.tolerations rendered when set"
# The drust/rustfs StatefulSet metadata.name renders BARE (`drust` / `rustfs`), but every record also
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
    for(i=1;i<=n;i++){ if(L[i]=="  name: rustfs") me=1; if(L[i] ~ /nodeSelector:/) ns=1 }
    if(me&&ns) ok=1
  } END{exit ok?0:1}'; then
  echo "ok: rustfs STS honors scheduling.rustfs"; else echo "FAIL: rustfs nodeSelector not wired"; FAILS=$((FAILS+1)); fi
# The /public Caddy and the rustfs-init hook Job must be placeable too: on tainted or dedicated
# nodes a pod with no toleration stays Pending, and a Pending hook fails every install and
# upgrade at its timeout. The Job follows scheduling.rustfs (nodeSelector + tolerations).
for spec in "Deployment|public-proxy|disktype: edge" "Deployment|public-proxy|value: edge" \
            "Job|rustfs-init|disktype: ssd" "Job|rustfs-init|value: store"; do
  IFS='|' read -r kind name needle <<<"$spec"
  if _rec placement.yaml "$kind" "$name" | grep -qF -- "$needle"; then echo "ok: $kind/$name is placed by its scheduling values ('$needle')"
  else echo "FAIL: $kind/$name lacks '$needle' from its scheduling values"; FAILS=$((FAILS+1)); fi
done
for rn in "Deployment|public-proxy" "Job|rustfs-init"; do
  IFS='|' read -r kind name <<<"$rn"
  if _rec full.yaml "$kind" "$name" | grep -qE '^      (nodeSelector|tolerations|affinity|topologySpreadConstraints):'; then
    echo "FAIL: $kind/$name renders a scheduling field by default"; FAILS=$((FAILS+1)); else echo "ok: $kind/$name has no scheduling field by default"; fi
done
assert_absent minimal.yaml "nodeSelector"               "no nodeSelector by default (empty {} => omitted)"
assert_absent full.yaml    "topologySpreadConstraints"  "no topologySpread by default"

# --- /public through the public-proxy Caddy (templates/public-proxy.yaml) ---
assert_contains full.yaml    "name: public-proxy"                 "public-proxy rendered when storage+publicFiles on"
assert_contains full.yaml    "docker.io/library/caddy:2.11.9@sha256:4e2425f6009577e7c651010f16679c28f7d12df3e7b1914f941a7a3370746b3c" "public-proxy runs Caddy pinned tag+digest"
assert_contains full.yaml    "checksum/caddyfile:"                "a Caddyfile change rolls the proxy"
assert_absent   storage-noPublic.yaml "public-proxy"              "no public-proxy when publicFiles off"
assert_absent   minimal.yaml "public-proxy"                       "no public-proxy when storage off"
# publicFiles on with storage off: no proxy and no /public path (there is no store behind them).
NOSTORE_PUB=$(helm template testrel "$CHART" -f "$FIX/minimal.yaml" --namespace testns --set storage.enabled=false --set publicFiles.enabled=true 2>&1) ||
  { echo "FAIL: storage off + publicFiles on did not render"; FAILS=$((FAILS+1)); }
if printf '%s' "$NOSTORE_PUB" | grep -qE 'public-proxy|path: /public'; then
  echo "FAIL: public-proxy or /public rendered with storage off + publicFiles on"; FAILS=$((FAILS+1))
else echo "ok: no public-proxy and no /public path with storage off + publicFiles on"; fi
# The rollout trigger must follow the file, not merely exist.
if command -v sha256sum >/dev/null; then CADDY_SHA=$(sha256sum "$CHART/files/public-proxy.Caddyfile"); else CADDY_SHA=$(shasum -a 256 "$CHART/files/public-proxy.Caddyfile"); fi
CADDY_SHA=${CADDY_SHA%% *}
if _rec full.yaml Deployment public-proxy | grep -qx "        checksum/caddyfile: $CADDY_SHA"; then
  echo "ok: checksum/caddyfile is the sha256 of files/public-proxy.Caddyfile"; else echo "FAIL: checksum/caddyfile is not the sha256 of files/public-proxy.Caddyfile"; FAILS=$((FAILS+1)); fi
_pp_dep() { _render "$1" | awk 'BEGIN{RS="---\n"} /kind: Deployment\n/ && /\n  name: public-proxy\n/{print}'; }
if _pp_dep full.yaml | grep -q "kind: Deployment"; then
  echo "ok: public-proxy is a Deployment"; else echo "FAIL: no public-proxy Deployment in full.yaml"; FAILS=$((FAILS+1)); fi
if _pp_dep full.yaml | grep -qF 'name: PUBLIC_OBJECTS_UPSTREAM, value: "rustfs:9000" }'; then
  echo "ok: public-proxy upstream is rustfs:9000"; else echo "FAIL: public-proxy upstream is not \"rustfs:9000\""; FAILS=$((FAILS+1)); fi
# The proxy is the anonymous surface: no credential of any kind in its pod.
if _pp_dep full.yaml | grep -q "secretKeyRef"; then
  echo "FAIL: public-proxy Deployment references a Secret"; FAILS=$((FAILS+1)); else echo "ok: public-proxy holds no secretKeyRef"; fi
# Its pod template must not wear rustfs's or drust's selector label (it would join that Service).
if _pp_dep full.yaml | awk '/^  template:$/{t=1;next} t&&/^    spec:$/{exit} t&&/app\.kubernetes\.io\/name: (drust|rustfs)$/{bad=1} END{exit bad?1:0}' &&
   _pp_dep full.yaml | awk '/^  template:$/{t=1;next} t&&/^    spec:$/{exit} t&&/app\.kubernetes\.io\/name: public-proxy$/{ok=1} END{exit ok?0:1}'; then
  echo "ok: public-proxy pod template wears only its own label"; else echo "FAIL: public-proxy pod template labels wrong (rustfs/drust label, or its own missing)"; FAILS=$((FAILS+1)); fi
# The rustfs policy admits the proxy pod on 9000, and its INGRESS keeps no namespaceSelector and no
# ipBlock peer: the controller reaches only the proxy's 8080, never 9000.
for fs in full.yaml:rustfs hostnetwork-ingress.yaml:rustfs; do
  f=${fs%%:*}; st=${fs##*:}
  if ! _np "$f" "$st" | grep -q '^  ingress:'; then
    echo "FAIL: no testrel-$st NetworkPolicy ingress in $f"; FAILS=$((FAILS+1))
  elif _np_ingress "$f" "$st" | grep -qE '^[[:space:]]*-?[[:space:]]*(namespaceSelector|ipBlock):'; then
    echo "FAIL: $st NP ingress admits a namespace or ipBlock peer ($f)"; FAILS=$((FAILS+1)); else echo "ok: $st NP ingress has no namespaceSelector/ipBlock ($f)"; fi
done
if _np_ingress full.yaml rustfs | grep -qE '^[[:space:]]+app\.kubernetes\.io/name: public-proxy$'; then
  echo "ok: rustfs NP admits public-proxy"; else echo "FAIL: rustfs NP does not admit public-proxy"; FAILS=$((FAILS+1)); fi
if _np_ingress storage-noPublic.yaml rustfs | grep -q 'public-proxy'; then
  echo "FAIL: rustfs NP admits public-proxy with publicFiles off"; FAILS=$((FAILS+1)); else echo "ok: rustfs NP has no public-proxy peer with publicFiles off"; fi
if _np_ingress full.yaml public-proxy | grep -q 'kubernetes.io/metadata.name: kube-system' &&
   _np_ingress full.yaml public-proxy | grep -q 'port: 8080' &&
   _np full.yaml public-proxy | awk '/^  egress:/{on=1} on' | grep -qE '^[[:space:]]+app\.kubernetes\.io/name: rustfs$' &&
   _np full.yaml public-proxy | awk '/^  egress:/{on=1} on' | grep -q 'port: 9000'; then
  echo "ok: public-proxy NP: controller namespace on 8080 in, rustfs:9000 out"; else echo "FAIL: public-proxy NP ingress/egress wrong"; FAILS=$((FAILS+1)); fi

# --- lockstep with Compose: rustfs-init runs the Compose files, byte for byte ---
for f in init.sh public-read.json drust-objects.json; do
  if cmp -s "$CHART/files/rustfs-init/$f" "$REPO_ROOT/deploy/compose-rustfs/$f"; then
    echo "ok: files/rustfs-init/$f is byte-identical to deploy/compose-rustfs/$f"
  else echo "FAIL: files/rustfs-init/$f differs from deploy/compose-rustfs/$f — edit both"; FAILS=$((FAILS+1)); fi
done
# --- lockstep with Compose: the chart's /public block is a byte copy of deploy/compose.Caddyfile's ---
# (compose_public_route_test.sh pins the Compose block to files.rs, so this pins the chart copy too.)
pub_block() { awk '!on && /^\thandle_path \/public\/\* \{/ {on=1}
  on {print; n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); d+=n-m; if(d==0) exit}' "$1"; }
if [ -n "$(pub_block "$REPO_ROOT/deploy/compose.Caddyfile")" ] &&
   [ "$(pub_block "$REPO_ROOT/deploy/compose.Caddyfile")" = "$(pub_block "$CHART/files/public-proxy.Caddyfile")" ]; then
  echo "ok: chart /public block is byte-identical to deploy/compose.Caddyfile's"
else echo "FAIL: files/public-proxy.Caddyfile /public block differs from deploy/compose.Caddyfile"; FAILS=$((FAILS+1)); fi

# --- Issue #8: hostNetwork ingress controller needs an ipBlock peer ---
# A hostNetwork controller carries no pod IP, so `namespaceSelector` can never
# resolve it and every request is REJECTed — 502 that reads like the app is down.
# Two independent paths break: the admin plane (drust:47826) and /public/*
# (public-proxy:8080). Assert BOTH policies carry the CIDRs, because fixing only the
# one you happened to test leaves the other silently black-holed.
assert_absent   minimal.yaml            "ipBlock: { cidr:" "no hostNetwork ipBlock by default (empty list => omitted)"
if _render hostnetwork-ingress.yaml | awk 'BEGIN{RS="---\n"} /kind: NetworkPolicy/ && /name: testrel-drust/{
    if ($0 ~ /10\.42\.0\.0\/32/ && $0 ~ /10\.0\.2\.218\/32/ && $0 ~ /port: 47826/) ok=1
  } END{exit ok?0:1}'; then
  echo "ok: drust NetworkPolicy admits hostNetworkIngressCIDRs on 47826"
else echo "FAIL: drust NetworkPolicy missing hostNetwork ipBlock peers"; FAILS=$((FAILS+1)); fi
if _np_ingress hostnetwork-ingress.yaml public-proxy | awk '/10\.42\.0\.0\/32/{a=1} /10\.0\.2\.218\/32/{b=1} /port: 8080/{p=1} END{exit (a&&b&&p)?0:1}'; then
  echo "ok: public-proxy NetworkPolicy admits hostNetworkIngressCIDRs on 8080 (/public path)"
else echo "FAIL: public-proxy NetworkPolicy missing hostNetwork ipBlock peers"; FAILS=$((FAILS+1)); fi
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

# --- the bundled RustFS ---
RUSTFS_PIN="docker.io/rustfs/rustfs:1.0.5@sha256:b81d16a90ee25bd9511280127ca1471788c6e874cf0f0da759645f46b2dc1d74"
assert_contains full.yaml "$RUSTFS_PIN" "RustFS image pinned tag+digest"
_rustfs_sts() { _rec "$1" StatefulSet rustfs; }
for needle in "runAsUser: 10001" "fsGroup: 10001" "fsGroupChangePolicy: OnRootMismatch" "readOnlyRootFilesystem: true" \
              'name: RUSTFS_CONSOLE_ENABLE, value: "false" }' 'name: RUSTFS_OBS_LOG_DIRECTORY, value: "" }' \
              "path: /health/ready" "path: /health/live" "name: rustfs-data" "replicas: 1" "automountServiceAccountToken: false" \
              "runAsNonRoot: true" "allowPrivilegeEscalation: false" 'capabilities: { drop: ["ALL"] }' "enableServiceLinks: false"; do
  if _rustfs_sts full.yaml | grep -qF -- "$needle"; then echo "ok: rustfs STS has '$needle'"; else echo "FAIL: rustfs STS lacks '$needle'"; FAILS=$((FAILS+1)); fi
done
# rustfs-init holds the root key: the same hardening, asserted on its own record.
for needle in "runAsNonRoot: true" "runAsUser: 10001" "readOnlyRootFilesystem: true" "allowPrivilegeEscalation: false" \
              'capabilities: { drop: ["ALL"] }' "automountServiceAccountToken: false" "enableServiceLinks: false"; do
  if _rec full.yaml Job rustfs-init | grep -qF -- "$needle"; then echo "ok: rustfs-init Job has '$needle'"; else echo "FAIL: rustfs-init Job lacks '$needle'"; FAILS=$((FAILS+1)); fi
done
# Each credential env var reads the right Secret key (a swapped pair renders fine and 403s live).
_envkey() { awk -v n="name: $1" 'index($0, n) && $0 ~ (n "$") {getline; sub(/.*key: /,""); sub(/ }.*/,""); print; exit}'; }
for spec in "StatefulSet drust GARAGE_S3_ACCESS_KEY s3-access-key" "StatefulSet drust GARAGE_S3_SECRET_KEY s3-secret-key" \
            "StatefulSet rustfs RUSTFS_ACCESS_KEY rustfs-root-access-key" "StatefulSet rustfs RUSTFS_SECRET_KEY rustfs-root-secret-key" \
            "Job rustfs-init RUSTFS_ACCESS_KEY rustfs-root-access-key" "Job rustfs-init RUSTFS_SECRET_KEY rustfs-root-secret-key" \
            "Job rustfs-init GARAGE_S3_ACCESS_KEY s3-access-key" "Job rustfs-init GARAGE_S3_SECRET_KEY s3-secret-key"; do
  read -r kind name var want <<<"$spec"
  got=$(_rec full.yaml "$kind" "$name" | _envkey "$var")
  if [ "$got" = "$want" ]; then echo "ok: $kind/$name $var reads $want"; else echo "FAIL: $kind/$name $var reads '$got', not $want"; FAILS=$((FAILS+1)); fi
done
# The rustfs NetworkPolicy admits exactly these pods, on 9000 only.
_np_peers() { _np_ingress "$1" rustfs | grep -oE 'app\.kubernetes\.io/name: [a-z-]+$' | sed 's/.*: //' | sort | tr '\n' ' '; }
for fe in "full.yaml:drust public-proxy rustfs-init " "backup-mirror.yaml:backup-mirror drust rustfs-init " "storage-noPublic.yaml:drust rustfs-init "; do
  f=${fe%%:*}; want=${fe#*:}; got=$(_np_peers "$f")
  if [ "$got" = "$want" ]; then echo "ok: rustfs NP ingress peers are exactly '$want' ($f)"; else echo "FAIL: rustfs NP ingress peers '$got', want '$want' ($f)"; FAILS=$((FAILS+1)); fi
  ports=$(_np_ingress "$f" rustfs | grep -oE 'port: [0-9]+' | sort -u | tr '\n' ' ')
  if [ "$ports" = "port: 9000 " ]; then echo "ok: rustfs NP ingress opens 9000 only ($f)"; else echo "FAIL: rustfs NP ingress ports '$ports', want 9000 only ($f)"; FAILS=$((FAILS+1)); fi
done
assert_absent full.yaml "RUSTFS_SERVER_DOMAINS" "path-style only: RUSTFS_SERVER_DOMAINS unset"
assert_absent full.yaml "9001"                  "no RustFS console port anywhere"
# drust talks to the bundled RustFS
if _render full.yaml | grep -qF 'name: GARAGE_S3_ENDPOINT, value: "http://rustfs.testns.svc:9000" }'; then
  echo "ok: GARAGE_S3_ENDPOINT is http://rustfs.testns.svc:9000"; else echo "FAIL: GARAGE_S3_ENDPOINT is not http://rustfs.testns.svc:9000"; FAILS=$((FAILS+1)); fi
# Root-key reach (D3): the RustFS root key is read only by the rustfs StatefulSet, the rustfs-init
# Job and the Secret that holds it — never by the drust pod, the proxy or the mirror.
_rootkey_reach_ok() { _render "$1" | awk 'BEGIN{RS="---\n"} /rustfs-root-/{
    n=split($0,L,"\n"); kind=""; name="";
    for(i=1;i<=n;i++){ if(L[i] ~ /^kind: /) kind=substr(L[i],7); if(L[i] ~ /^  name: /) name=substr(L[i],9) }
    if(!((kind=="StatefulSet" && name=="rustfs") || (kind=="Job" && name=="rustfs-init") || kind=="Secret")){bad=1; print "  " kind "/" name}
  } END{exit bad?1:0}'; }
for f in full.yaml existing-secret.yaml backup-mirror.yaml; do
  if out=$(_rootkey_reach_ok "$f"); then echo "ok: rustfs-root-* only in the rustfs STS, rustfs-init and the Secret ($f)"
  else echo "FAIL: rustfs-root-* reaches another workload ($f):"; echo "$out"; FAILS=$((FAILS+1)); fi
done
if _rustfs_sts full.yaml | grep -q 'key: rustfs-root-access-key' && _rec full.yaml Job rustfs-init | grep -q 'key: rustfs-root-access-key'; then
  echo "ok: rustfs STS and rustfs-init read the root key"; else echo "FAIL: rustfs STS / rustfs-init do not read rustfs-root-access-key"; FAILS=$((FAILS+1)); fi
# The Secret is rendered as data: (base64), never stringData: — see the comment in secret.yaml.
_b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
if _rec full.yaml Secret testrel-secret | grep -q '^stringData:'; then
  echo "FAIL: the chart Secret uses stringData (a key dropped later would never leave the live Secret)"; FAILS=$((FAILS+1))
else echo "ok: the chart Secret uses data:, not stringData:"; fi
if _rec full.yaml Secret testrel-secret | grep -qx "  s3-access-key: \"$(_b64 fullak)\"" && _rec full.yaml Secret testrel-secret | grep -qx "  rustfs-root-access-key: \"$(_b64 fullrootak)\""; then
  echo "ok: Secret s3-access-key is drust's key, rustfs-root-access-key the root key"; else echo "FAIL: Secret key layout wrong"; FAILS=$((FAILS+1)); fi
# Checksums (M2): a key change through Helm restarts the pod that holds the key.
_ck() { awk -v k="$1" 'index($0, k){sub(/.*: /,""); print; exit}'; }
S3K=$(_rec full.yaml StatefulSet drust | _ck "checksum/s3-key:")
ROOTK=$(_rustfs_sts full.yaml | _ck "checksum/root-key:")
S3K2=$(helm template testrel "$CHART" -f "$FIX/full.yaml" --namespace testns --set storage.secretKey=other 2>/dev/null | _ck "checksum/s3-key:")
ROOTK2=$(helm template testrel "$CHART" -f "$FIX/full.yaml" --namespace testns --set storage.rustfs.rootSecretKey=other 2>/dev/null | _ck "checksum/root-key:")
if [ -n "$S3K" ] && [ -n "$S3K2" ] && [ "$S3K" != "$S3K2" ]; then
  echo "ok: drust pod checksum/s3-key changes with storage.secretKey"; else echo "FAIL: checksum/s3-key missing or unchanged by storage.secretKey"; FAILS=$((FAILS+1)); fi
if [ -n "$ROOTK" ] && [ -n "$ROOTK2" ] && [ "$ROOTK" != "$ROOTK2" ]; then
  echo "ok: rustfs pod checksum/root-key changes with storage.rustfs.rootSecretKey"; else echo "FAIL: checksum/root-key missing or unchanged by rootSecretKey"; FAILS=$((FAILS+1)); fi
# ... and with the access-key half, so a hash over the secret alone fails.
S3K3=$(helm template testrel "$CHART" -f "$FIX/full.yaml" --namespace testns --set storage.accessKey=other 2>/dev/null | _ck "checksum/s3-key:")
ROOTK3=$(helm template testrel "$CHART" -f "$FIX/full.yaml" --namespace testns --set storage.rustfs.rootAccessKey=other 2>/dev/null | _ck "checksum/root-key:")
if [ -n "$S3K3" ] && [ "$S3K3" != "$S3K" ] && [ -n "$ROOTK3" ] && [ "$ROOTK3" != "$ROOTK" ]; then
  echo "ok: checksums change with storage.accessKey / storage.rustfs.rootAccessKey too"; else echo "FAIL: a checksum does not cover the access key"; FAILS=$((FAILS+1)); fi
# Key files from the documented recipe (`openssl rand -hex 20 > f`) end in a newline, which
# --set-file keeps. The Secret and both checksums must come out exactly as without it.
NL_DIR="$RENDER_DIR/nl"; mkdir -p "$NL_DIR"
for kv in accessKey:fullak secretKey:fullsk rootAccessKey:fullrootak rootSecretKey:fullrootsk; do printf '%s\n' "${kv#*:}" > "$NL_DIR/${kv%%:*}"; done
NL_OUT=$(helm template testrel "$CHART" -f "$FIX/full.yaml" --namespace testns \
  --set-file storage.accessKey="$NL_DIR/accessKey" --set-file storage.secretKey="$NL_DIR/secretKey" \
  --set-file storage.rustfs.rootAccessKey="$NL_DIR/rootAccessKey" --set-file storage.rustfs.rootSecretKey="$NL_DIR/rootSecretKey" 2>&1)
_keylines() { grep -E '^  (s3-access-key|s3-secret-key|rustfs-root-access-key|rustfs-root-secret-key): |checksum/(s3|root)-key:'; }
if [ -n "$(_render full.yaml | _keylines)" ] && [ "$(printf '%s\n' "$NL_OUT" | _keylines)" = "$(_render full.yaml | _keylines)" ]; then
  echo "ok: --set-file keys with a trailing newline render the same Secret values and checksums"
else echo "FAIL: a trailing newline in a --set-file key reaches the Secret or a checksum"; FAILS=$((FAILS+1)); fi
assert_absent existing-secret.yaml "checksum/s3-key"  "no checksum/s3-key with existingSecret (Helm cannot see the values)"
assert_absent existing-secret.yaml "checksum/root-key" "no checksum/root-key with existingSecret (Helm cannot see the values)"
# existingSecret: no Secret rendered, every secretKeyRef names the operator's Secret.
if _rec existing-secret.yaml StatefulSet rustfs | grep -q 'key: rustfs-root-access-key'; then
  echo "ok: rustfs reads its root key from the existingSecret"; else echo "FAIL: rustfs does not read rustfs-root-access-key with existingSecret"; FAILS=$((FAILS+1)); fi
assert_absent existing-secret.yaml "kind: Secret" "no Secret rendered with secrets.create=false"
if _render existing-secret.yaml | grep 'secretKeyRef' | grep -v 'name: s,' | grep -q .; then
  echo "FAIL: a secretKeyRef in existing-secret.yaml does not name Secret s"; FAILS=$((FAILS+1))
elif _render existing-secret.yaml | grep -q 'secretKeyRef'; then echo "ok: every secretKeyRef names the existingSecret"
else echo "FAIL: no secretKeyRef at all in existing-secret.yaml"; FAILS=$((FAILS+1)); fi
# No mc anywhere: the mc client images can no longer be pulled.
for f in $ALL_FIXTURES; do
  bad=""
  for needle in "MC_HOST" "mc alias" "mc ls" "mc mirror"; do
    _render "$f.yaml" | grep -qF -- "$needle" && bad="$bad '$needle'"
  done
  if [ -z "$bad" ]; then echo "ok: no mc in $f.yaml"; else echo "FAIL: mc left in $f.yaml:$bad"; FAILS=$((FAILS+1)); fi
done
# Render must FAIL for these (helm template exit != 0).
_must_fail() { # <label> <expect-substring or ""> <helm args...>
  local label="$1" want="$2"; shift 2; local out
  if out=$(helm template testrel "$CHART" --namespace testns "$@" 2>&1); then
    echo "FAIL: render accepted: $label"; FAILS=$((FAILS+1))
  elif [ -n "$want" ] && ! printf '%s' "$out" | grep -qF -- "$want"; then
    echo "FAIL: render refused but without '$want': $label"; FAILS=$((FAILS+1))
  else echo "ok: render refused: $label"; fi; }
# The root key is never drust's key: rustfs-init would hand drust a key that can create buckets
# and change who may read "public". Checked in secret.yaml, the only place both values are known.
_must_fail "storage.accessKey equal to the root access key" "must be drust's own key" -f "$FIX/full.yaml" --set storage.accessKey=fullrootak
# What init.sh refuses at hook time is refused at render (create mode).
_must_fail "a root secret key with a URL character" "letters and digits only" -f "$FIX/full.yaml" --set storage.rustfs.rootSecretKey=a/b
_must_fail "a root access key with a URL character" "letters and digits only" -f "$FIX/full.yaml" --set storage.rustfs.rootAccessKey=a:b
_must_fail "root access key rustfsadmin" "published default rustfsadmin" -f "$FIX/full.yaml" --set storage.rustfs.rootAccessKey=rustfsadmin
_must_fail "root secret key rustfsadmin" "published default rustfsadmin" -f "$FIX/full.yaml" --set storage.rustfs.rootSecretKey=rustfsadmin
# Each of the four storage keys is required while storage is on, with no default. An upgrade from
# 0.1.x with its old values file stops here with secrets.create (an existingSecret is not checked).
for k in storage.accessKey storage.secretKey storage.rustfs.rootAccessKey storage.rustfs.rootSecretKey; do
  _must_fail "empty $k" "$k required when storage.enabled=true" -f "$FIX/full.yaml" --set "$k="
done
# No lookup anywhere: what renders depends on values only, never on what the cluster holds.
if grep -rnE '\blookup\b' "$CHART/templates" >/dev/null; then
  echo "FAIL: a template calls lookup:"; grep -rnE '\blookup\b' "$CHART/templates"; FAILS=$((FAILS+1))
else echo "ok: no template calls lookup"; fi
# RustFS is the only bundled store: nothing of MinIO renders, in any fixture, in any letter case.
for f in $ALL_FIXTURES; do
  if _render "$f.yaml" | grep -qi 'minio'; then
    echo "FAIL: minio rendered in $f.yaml:"; _render "$f.yaml" | grep -ni 'minio' | head -5; FAILS=$((FAILS+1))
  else echo "ok: no minio in $f.yaml"; fi
done

# --- Task 10: full-matrix kubeconform ---
for f in $ALL_FIXTURES; do assert_kubeconform "$f.yaml"; done
# README exists
[ -f "$CHART/README.md" ] && echo "ok: README present" || { echo "FAIL: README missing"; FAILS=$((FAILS+1)); }

echo "== $FAILS failure(s) =="
exit $((FAILS>0))
