# drust Helm chart — changelog

## [Unreleased] — Deploy

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
