# drust Helm chart — changelog

## [0.2.0] — unreleased

### Security
- **`/public` served stored markup with no sandbox.** The Ingress sent `/public/*`
  straight to MinIO's port 9000: a `text/html` (or any `*+xml`) object came back with no
  CSP, and `?response-content-type=text/html` on an anonymous GET turned any public
  object into HTML — script running on the admin UI's origin. `/public/*` now goes to a
  new `public-proxy` Caddy Deployment (`publicProxy.image`, `resources.publicProxy`)
  whose `/public` block is a byte copy of the Compose one (`files/public-proxy.Caddyfile`,
  pinned by `render_test.sh`): GET/HEAD only, query string dropped, `Authorization` /
  `Cookie` stripped, `Set-Cookie` dropped, `nosniff` everywhere and the sandbox CSP on
  markup. The ingress controller is now admitted to the proxy's 8080 only; MinIO's
  NetworkPolicy no longer admits the controller namespace or `hostNetworkIngressCIDRs`
  on 9000 (those CIDRs moved to the proxy's policy). Upper-case markup types stored
  before drust v1.56.3 still get no CSP (case-sensitive matcher); set such a file
  private and public again.

### Changed
- **`DRUST_TRUSTED_PROXIES` is set, from `ingress.trustedProxies` (default `1`).** Before,
  the chart did not set it and drust pods inherited the image's `0`: every request was
  keyed on the ingress controller pod's address, so all clients of a group shared one
  rate-limit bucket. `1` counts the controller, the one proxy that appends to
  `X-Forwarded-For`. If you set `DRUST_TRUSTED_PROXIES` in `extraEnv`, move it to
  `ingress.trustedProxies`. The README's known caveats cover the k3s ServiceLB SNAT, the
  controller's forwarded-header settings and the NetworkPolicy.
- **The `GARAGE_ADMIN_*` placeholders are gone.** They existed because drust required
  both variables whenever `GARAGE_S3_ENDPOINT` was set; since v1.67.0 it boots on the S3
  settings alone, and it read the two never-dialed values as "Garage admin API
  configured". Removed: the `GARAGE_ADMIN_ENDPOINT` / `GARAGE_ADMIN_TOKEN` env entries, the
  `admin-endpoint` / `admin-token` Secret keys, and the values
  `storage.adminEndpointPlaceholder` / `storage.adminTokenPlaceholder`. An
  `existingSecret` that still carries the two keys keeps working (nothing reads them).
- **Pullable backup tooling.** The `minio/mc` and `bitnami/kubectl` images can no longer
  be pulled, so the Litestream restore (`litestream-enumerate`), the object mirror and the
  VolumeSnapshot CronJob could not start on a node that did not already hold them.
  - The enumerate init container and the `backup-mirror` CronJob run rclone, from the new
    `s3ClientImage` (`rclone/rclone:1.75.2`, pinned tag+digest: it holds the backup-S3
    key and drust's key). Remotes come only from env; keys arrive by `secretKeyRef`. The
    mirror copies with `-M` (without it `Content-Disposition`, `Cache-Control` and
    `x-amz-meta-*` were dropped) and `RCLONE_S3_NO_CHECK_BUCKET=true` (without it a
    bucket-scoped key fails every upload with 403), and now probes its backup prefix
    instead of the bucket list, which a prefix-scoped key cannot list. Still a copy,
    never a sync.
  - `backup.kubectlImage` defaults to `alpine/kubectl:1.36.4`, pinned tag+digest (its
    pod holds a token that may delete VolumeSnapshots). The CronJob itself is unchanged.
  - Removed values: `backup.litestream.mcImage`, `backup.objectMirror.image` (both now
    `s3ClientImage`).

## [0.1.4] — 2026-08-04

### Fixed
- **A `hostNetwork` ingress controller was black-holed, 502 on every request**
  (issue #8). The ingress rules gated solely on `namespaceSelector`, and a
  hostNetwork pod has no CNI pod IP — so there is no pod → namespace mapping to
  resolve and the selector can never match, however
  `ingressControllerNamespace` is set. That is the normal shape on bare metal,
  where there is no LoadBalancer to hand out an external IP.
  `networkPolicy.hostNetworkIngressCIDRs` (default `[]`, so no rendered output
  changes) adds `ipBlock` peers to **both** affected rules: the admin plane on
  `drust:47826` and, when `publicFiles.enabled`, `/public/*` on `minio:9000`.
  They fail independently — `/login` can be green while every public file 502s
  — so the render tests assert both.

  Two traps worth stating, both reported from the field:
  the source is **not** the node IP for a cross-node connection (the packet
  carries the ingress node's flannel address; find it with `ip route get <drust
  pod IP>` **on the ingress node**), and the symptom is `Connection refused`
  rather than a timeout, because kube-router REJECTs — so it reads like the app
  is down, not like a firewall. It also stays invisible on distributions that
  ship `disable-network-policy: true`: the policies render and enforce nothing.

  `0.0.0.0/0` is rejected at template time. This rule fronts the admin plane,
  and a catch-all there admits every pod in the cluster including other groups'
  — same fail-closed discipline as `backup.external.destinationCIDRs`.

### Changed
- **`scheduling.drust.tolerations` documented as a recovery-time control**, not
  a placement passthrough. Kubernetes injects `node.kubernetes.io/not-ready`
  and `.../unreachable` at `tolerationSeconds: 300`; drust is `replicas: 1`
  (SQLite, single writer), so nothing serves during those 300 seconds. Measured
  on a real node failure with Longhorn RWO volumes: **~396s total RTO on the
  default vs ~193s at 60s**, i.e. the default was about three-quarters of the
  outage. `values.yaml` now carries the rationale and a ready-to-paste block.
- **README** gained the hostNetwork prerequisite above, and a CAUTION that
  Longhorn's `node-down-pod-deletion-policy` defaults to `do-nothing` — with
  which the old pod stays `Terminating`, the RWO volume reports `Multi-Attach
  error`, and the replacement pod never starts, so failover hangs rather than
  merely being slow.

## [0.1.3] — 2026-08-04

### Fixed
- **`helm install` deployed a nine-release-old binary.** `image.tag` was a second
  hardcoded version, independent of `appVersion`, and it read `1.49.4` while 1.58.1
  was current — so a default install shipped without the v1.56.2/v1.56.3 stored-XSS
  CSP sandbox, both v1.58.0 intra-tenant fixes, and the v1.58.1 wasmtime advisory
  bump. `image.tag` now defaults to `""`, and both drust containers (main +
  `maintenance` sidecar) fall back to `.Chart.AppVersion`. Set `image.tag`
  explicitly only to pin a rollback or a canary.

### Added
- **`render_test.sh` asserts `Chart.yaml` appVersion == `Cargo.toml` version**, plus
  that the rendered image actually follows appVersion when `image.tag` is empty.
  With the fallback above, appVersion stops being decorative — it is the tag
  `helm install` pulls — so a drift is now a red test rather than a silent
  nine-release gap. Verified to fail: reverting appVersion to 1.49.4 reproduces
  `FAIL: … helm install would deploy the wrong binary`.
- **CI runs the chart tests** (`helm-chart` job: `helm template` + `kubeconform`,
  offline, no cluster). The chart previously had zero CI coverage — the whole
  harness only ran when someone remembered to, which is precisely how the stale
  tag survived nine releases.

### Note
- The next drust release sweeps expired sessions in-process, so the `maintenance`
  sidecar's `drust_session_janitor` call — like its `_trash` sweep since 1.58.0 —
  becomes redundant belt-and-braces rather than the mechanism. Both stay
  idempotent (a re-DELETE affects 0 rows), so the sidecar default is unchanged
  and older images keep working against this chart.

## [0.1.2] — 2026-07-22
Additive; all opt-in / default-off. Existing installs render byte-identically.

### Added
- **B1 Litestream continuous DB replication** (`backup.litestream.*`): sidecar streams
  meta.sqlite, meta_logs.sqlite, and every tenants/*/data.sqlite to an external S3 via
  native directory-mode replication with a live watcher (`watch: true`) — post-boot
  tenants are picked up without a restart. Two restore initContainers rebuild an empty
  /data from S3 on a fresh PVC (enumerate via mc, restore via litestream; atomic
  temp+rename, never --force). Independent opt-in from the CSI VolumeSnapshot backup.
- **B2 object backup** (`backup.objectMirror.*`): hourly CronJob mc-mirrors this group's
  MinIO public/private buckets to the same external S3 (objects only). Dedicated-label
  pod + scoped NetworkPolicy; automountServiceAccountToken:false.
- **B3 scheduling passthrough** (`scheduling.drust.*`, `scheduling.minio.*`):
  nodeSelector / tolerations / affinity / topologySpreadConstraints on both StatefulSets.
- Shared external-backup Secret `<release>-backup-secret` (or `backup.external.existingSecret`);
  NetworkPolicy egress for both backup sinks on the backup port, decoupled from
  allowInternetEgress. When general egress is OFF, `backup.external.destinationCIDRs` is
  REQUIRED (template fails closed) so the drust pod never gains a cluster-wide egress hole.

### Fixed (pre-release adversarial review + live-binary verification)
- **CRITICAL** — the tenant glob was `*/data.sqlite`, which enrolls ZERO databases in Litestream
  (verified against the real litestream 0.5.15 binary): every tenant's data.sqlite would be
  silently unbacked while meta.sqlite still shipped — a maximally misleading disaster recovery.
  Corrected to the basename form `*.sqlite` (recursive scan walks the per-tenant subdirs); a
  render-test guard now pins it.
- Restore enumerate retries the tenant listing and FAILS LOUD on persistent error (was a single
  swallowed `mc ls` → silent half-restore of meta only); tenant ids are validated uuid-v4 before
  use in the restore path (closes a `../` traversal from a poisoned backup prefix).
- Backup egress no longer silently punches 0.0.0.0/0 on the drust pod when general egress is off —
  `destinationCIDRs` is required (fail-closed), keeping the SSRF surface closed on the pod that
  also runs untrusted edge-function WASM and outbound webhooks.
- Removed the dead top-level `monitor-interval` knob (Litestream ignores it there; `watch: true`
  is the actual post-boot tenant-discovery mechanism).
- Three render-test guards that passed WITHOUT verifying anything (RO-root whole-file grep,
  `RS="---"` end-anchor bug, drust-label cross-match on the minio StatefulSet) rewritten to real,
  record-scoped checks — each confirmed to fail when its defect is injected.

### Notes
- Litestream retention default 720h (30d) deliberately exceeds the audit DB monthly VACUUM.
- appVersion unchanged (1.49.4).
