# drust — k3s multi-instance Helm chart

## What this is

This chart deploys **one drust instance per group**, with hard isolation between
groups. Each Helm release lives in its own namespace and stands up a complete,
self-contained drust stack: a single-writer drust StatefulSet, its own dedicated
MinIO object store, a bucket-init hook Job, Services, an Ingress with the
mandatory rmcp Host rewrite, a bootstrap Secret, a default-deny NetworkPolicy,
an optional maintenance sidecar, and an optional CSI-snapshot backup CronJob.

The topology is deliberately "one group = one namespace = one release = one
drust + one MinIO". Nothing is shared across groups — not the database, not the
object store, not the network path. To add a group you install the chart again
into a new namespace with a new values file. drust's own program code is never
modified; a single GHCR image (`ghcr.io/kaellim/drust`) is parameterised purely
through Helm values.

> The single-writer invariant is load-bearing: both the drust and MinIO
> StatefulSets are pinned to `replicas: 1` on ReadWriteOnce volumes. **Never**
> scale either above 1 against the same volume — SQLite and single-node MinIO
> are single-writer stores and concurrent writers corrupt them.

## Prerequisites

- A **k3s / Sealos** (or any conformant Kubernetes) cluster where you have
  **cluster-admin** (the chart creates NetworkPolicies, and — when backup is
  enabled — a Role/RoleBinding). You create the namespace yourself with
  `helm install --create-namespace`; `createNamespace` defaults to false.
- An **ingress controller**: **Traefik** (the k3s default, and this chart's
  default) or **nginx-ingress**. Select with `ingress.controller`.
  > [!CAUTION]
  > **If the controller runs `hostNetwork: true` — the norm on bare metal, where
  > there is no LoadBalancer — you must set `networkPolicy.hostNetworkIngressCIDRs`
  > or every request 502s.** A hostNetwork pod has no CNI pod IP, so
  > `networkPolicy.ingressControllerNamespace` can never match it and the traffic is
  > refused. The source is *not* simply the node IP: cross-node, the packet carries
  > the ingress node's flannel address. Run `ip route get <drust pod IP>` **on the
  > ingress node** and use the `src` it reports, plus the node IP for the same-node
  > case. Both the admin plane and `/public/*` are affected, and they fail
  > independently. Symptom is `Connection refused` (kube-router REJECTs rather than
  > DROPs), so it reads like the app is down rather than like a firewall.
  > Note this stays invisible on clusters that ship `disable-network-policy: true`
  > (several k3s distributions do): the policies render and enforce nothing.
- **cert-manager** with a `ClusterIssuer`, only if you enable TLS
  (`ingress.tls.enabled=true`). The issuer name goes in `ingress.tls.issuer`.
- A **CSI `VolumeSnapshotClass`**, only if you enable backups
  (`backup.volumeSnapshotClassName`). Leave it empty and no backup objects
  render.
- A **CSI storage class that supports `ReadWriteOnce`** for the drust `/data`
  and `/logs` PVCs and the MinIO data PVC. Set `persistence.storageClassName`
  (and `storage.minio.pvcSize`) or leave `storageClassName` empty to use the
  cluster default.

## Install a group

```bash
helm install group-a deploy/helm/drust \
  --namespace group-a --create-namespace \
  -f groups/group-a.yaml
```

Each group gets its own release name, its own namespace, and its own values
file. The `groups/*.yaml` per-group values files are **not** part of this repo —
you maintain them yourself, one per group.

## Per-group values example

Copy the shape of `tests/fixtures/full.yaml` and substitute real hostnames and
credentials:

```yaml
createNamespace: false            # already created by `helm install --create-namespace`
ingress:
  host: group-a.example.tw        # this group's public hostname
  controller: traefik             # traefik | nginx
  tls:
    enabled: true
    issuer: letsencrypt           # cert-manager ClusterIssuer name
publicUrl: https://group-a.example.tw   # required for OAuth redirect round-trips
publicFiles:
  enabled: false                  # true => /public/* anon-read path to the MinIO public bucket
storage:
  enabled: true
  minio:
    rootUser: group-a-key
    rootPassword: "CHANGE-ME"     # required when storage.enabled
    pvcSize: 20Gi                 # bucket names are fixed ("public"/"private"), not configurable
maintenance:
  sidecar:
    enabled: true                 # daily drust_session_janitor
backup:
  volumeSnapshotClassName: csi-hostpath-snapclass   # empty => no backup CronJob
  schedule: "0 3 * * *"
  retain: 7
secrets:
  create: true
  adminUser: admin
  adminPassword: "CHANGE-ME"      # DRUST_INIT_ADMIN_PASSWORD, first boot only
```

You **must** provide `secrets.adminPassword`, and (when `storage.enabled`)
`storage.minio.rootPassword` — the chart's `required` guards fail the render
otherwise. If you manage credentials outside Helm, set `secrets.create=false`
and point `secrets.existingSecret` at a pre-created Secret carrying the same
keys (`admin-username`, `admin-password`, and when storage is on `s3-access-key`,
`s3-secret-key`, `admin-endpoint`, `admin-token`). When a backup feature (B1/B2) is
enabled with `backup.external.create=false`, also pre-create the backup Secret named by
`backup.external.existingSecret` with keys `backup-s3-access-key` / `backup-s3-secret-key`.

## CRITICAL — MCP Host rewrite live-verify

The single failure mode a render test cannot catch is the rmcp DNS-rebinding
guard. drust's MCP endpoint rejects any upstream `Host` header that is not the
loopback form `127.0.0.1:47826` with a **403/421** that looks like a WAF block.
This chart's Ingress rewrites the upstream Host for you — Traefik via a
`Middleware` with `customRequestHeaders.Host`, nginx via the
`nginx.ingress.kubernetes.io/upstream-vhost` annotation — but the rewrite MUST
be confirmed against a live request after install:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Host: group-a.example.tw" \
  https://group-a.example.tw/t/<tenant>/mcp
```

A `200`/`400`/`401` is fine; a **`403` or `421` means the Host rewrite did not
take effect**. Traefik's `customRequestHeaders.Host` behaviour is version
sensitive (see Known caveats): if it does not apply on your Traefik build, fall
back to nginx-ingress (`ingress.controller: nginx`), or use a Traefik
`IngressRoute` with `passHostHeader` set to the loopback form.

## Upgrade

> **Upgrading from chart 0.1.0? READ THIS FIRST — it prevents data loss.** Chart
> 0.1.0 defaulted `createNamespace: true`, making the namespace **release-owned**.
> Chart 0.1.1 defaults it **false**, so on the first `helm upgrade` Helm sees the
> Namespace drop out of the rendered manifest and **prunes it — reaping every PVC
> (all tenant SQLite databases + MinIO objects), irreversibly on a `reclaimPolicy:
> Delete` StorageClass.** If your 0.1.0 install used `createNamespace: true` (or
> relied on that old default), annotate the live namespace **before** upgrading so
> Helm's prune skips it:
>
> ```bash
> kubectl annotate namespace group-a helm.sh/resource-policy=keep --overwrite
> ```
>
> Installs that already set `createNamespace: false` (the README example always
> did) own no namespace and are unaffected.

Upgrade a group in place:

```bash
helm upgrade group-a deploy/helm/drust \
  --namespace group-a \
  -f groups/group-a.yaml
```

Because the drust StatefulSet is a single writer on a RWO volume, a rolling
upgrade terminates the old pod before the new one binds the volume — expect a
**brief downtime window** per group during the pod swap. Upgrades are per group
and independent; upgrading one group never touches another.

## Uninstall

```bash
helm uninstall group-a --namespace group-a
```

**PVCs are intentionally retained.** `helm uninstall` removes the release's
workloads but **not** the StatefulSet/MinIO PVCs — reinstalling the same release
re-binds the existing `data-drust-0` / `logs-drust-0` / `minio-data-minio-0`
volumes, so tenant data survives. This is deliberate: the PVC *is* the database.
Because `createNamespace` defaults to **false**, the namespace you created with
`--create-namespace` also survives. To reclaim everything for a group:

```bash
kubectl delete namespace group-a   # deletes the PVCs (and their backing data) too
```

> **Never** rely on `createNamespace: true` to "clean up on uninstall". A
> release-owned Namespace would let `helm uninstall` reap every PVC in it —
> silent, irreversible data loss on a `reclaimPolicy: Delete` StorageClass. If
> you set it true anyway, the chart annotates the Namespace
> `helm.sh/resource-policy: keep` so uninstall cannot delete it; reclaim
> deliberately with `kubectl delete namespace` when you actually mean to.

## Backup

Backups are opt-in CSI `VolumeSnapshot`s of the drust `/data` PVC
(`data-drust-0`). Set `backup.volumeSnapshotClassName` to your cluster's
`VolumeSnapshotClass` to render a ServiceAccount + Role/RoleBinding + a CronJob
that snapshots on `backup.schedule` (UTC) and prunes to the newest
`backup.retain` snapshots. Leave the class empty and no backup objects render at
all.

To **restore**: create a new PVC from the chosen snapshot
(`spec.dataSource` → the `VolumeSnapshot`), then point a fresh release's
`persistence` at that PVC and install into a review namespace. Inspect before
promoting.

> **Treat snapshots as secrets.** A drust `/data` snapshot contains live
> plaintext credentials at rest (per-tenant anon/service tokens and admin PATs
> are stored alongside their hashes so the admin UI can echo them). Apply the
> same filesystem/RBAC controls you would to the bootstrap Secret; never copy a
> snapshot off-cluster unencrypted; reroll tokens after any suspected leak.

## Continuous DB backup (Litestream, B1)

The CSI-snapshot backup above needs a cluster `VolumeSnapshotClass`. **k3s's default
`local-path` provisioner ships none**, so on a stock k3s cluster the snapshot CronJob
cannot render — that leaves the SQLite databases with **zero automated protection**.
`backup.litestream.*` fills that gap: a Litestream sidecar in the drust pod continuously
streams every database to an external S3 bucket.

It covers all three DB classes — `meta.sqlite`, `meta_logs.sqlite`, and **every**
`tenants/<id>/data.sqlite`. The tenant coverage is dynamic: the sidecar config uses
Litestream's native directory mode with `watch: true`, so a tenant DB created **after
boot** is enrolled within seconds without restarting the sidecar. **Do not set
`backup.litestream.watch: false`** — that is a correctness switch, not a tuning knob; with
it off a new tenant is unprotected until the next sidecar restart.

RPO is three-part and honest:
1. Existing tenant DBs + meta + meta_logs: RPO ≈ `syncInterval` (1s) + flush ≈ **1–2s**.
2. New-tenant enrollment window: from `data.sqlite` landing to its first frame reaching S3
   (watcher discovery "seconds" + first sync) that tenant's writes are not yet protected.
   Its `meta.sqlite.tenants` row survives via the continuous meta replication. This is the
   one structural RPO gap — narrowable, not zero.
3. Restore rebuilds an empty `/data` from S3; a tenant created inside window 2 whose
   `data.sqlite` never uploaded is restored as an empty DB (schema self-heals on first
   access; only that window's data is lost).

Restore is automatic and runs **only when `/data` is empty** (fresh PVC / new node). Two
initContainers run before drust starts: `litestream-enumerate` (lists tenant prefixes in
the backup bucket via `mc`), then `litestream-restore` (restores each DB via `litestream
restore`, atomic `.tmp`→`mv`, `-if-replica-exists`, never `-force`). A populated `/data`
hits two independent skip gates plus a per-file existence check — live data is never
overwritten. After restore, drust sees an existing `meta.sqlite`, so first-boot bootstrap
is a no-op: **tokens survive verbatim, the admin is not re-seeded.**

- Independent of `backup.volumeSnapshotClassName` — enable either, both, or neither.
- The audit DB's monthly full VACUUM rolls the Litestream generation; the 720h (30d)
  retention default is comfortably wider than that cycle, so a restorable snapshot always
  exists across a VACUUM. Keep `retention` above one month.
- Credentials live in `<release>-backup-secret` (or set `backup.external.existingSecret`).
- **Backup egress is fail-closed when general egress is off.** With
  `networkPolicy.allowInternetEgress: false` you MUST set `backup.external.destinationCIDRs`
  (+ `backup.external.port`) to scope the NetworkPolicy egress to your S3 provider's ranges —
  otherwise the template REFUSES to render, rather than silently punching a `0.0.0.0/0` hole on
  the pod that also runs untrusted edge-function WASM and outbound webhooks. With general egress
  already on, CIDRs are optional (the pod already has broad egress by your choice).
- The sidecar/init run under `readOnlyRootFilesystem: true` at uid 10001 (must match drust
  so it can read the DBs it wrote). `mc` and `litestream` both run fine on a read-only root
  — confirm with one live restore drill.

> [!CAUTION]
> **Cross-group backup isolation is the operator's job.** The replicated `meta.sqlite` carries
> PLAINTEXT tokens (`tokens.plaintext` / `_admin_tokens.plaintext`). `pathPrefix` (default = the
> group's namespace) is only a SOFT boundary — if two groups target the SAME bucket with
> bucket-wide credentials, group A can list/read group B's prefix = full data-plane + admin-PAT
> compromise of the other group. Give each group EITHER a distinct bucket OR credentials whose
> IAM policy is scoped to that group's `<prefix>/` only.

## Object-file backup (B2)

`backup.objectMirror.*` adds an hourly CronJob that `mc mirror`s this group's MinIO
`public` + `private` buckets to the same external S3 under `<prefix>/objects/`. Litestream
handles the databases; this handles only the object files. It uses `--overwrite` but **not
`--remove`**: an accidental source delete does not propagate into the backup, so a deleted
object stays recoverable — the trade-off is the backup only grows, so prune it with a
bucket lifecycle policy on the S3 side. The Job retries its first connection (a new Job pod
IP takes seconds to enter the CNI NetworkPolicy allow-set, same cause as `minio-init`),
wears a dedicated label with its own scoped NetworkPolicy, and drops its ServiceAccount
token. Needs `storage.enabled`.

## Scheduling / placement (B3)

`scheduling.drust.*` and `scheduling.minio.*` pass `nodeSelector` / `tolerations` /
`affinity` / `topologySpreadConstraints` straight through to the respective StatefulSet pod
spec. All default empty, so leaving them unset is zero behavior change.

> [!IMPORTANT]
> **`tolerations` is a recovery-time control, not just placement.** Kubernetes injects
> `node.kubernetes.io/not-ready` and `.../unreachable` at `tolerationSeconds: 300`. drust
> runs `replicas: 1` — SQLite, single writer — so nothing serves during those 300 seconds.
> Measured on a real node failure with Longhorn RWO volumes: **~396s total RTO on the
> default, ~193s at `tolerationSeconds: 60`**, i.e. the default accounted for about
> three-quarters of the outage. `values.yaml` carries a ready-to-paste block. This only
> helps where the pod has somewhere to fail over to — see the node-binding note below.

> [!CAUTION]
> **StatefulSet on replicated storage: Longhorn's `node-down-pod-deletion-policy` defaults
> to `do-nothing`.** With that default the old pod stays `Terminating` on the dead node, the
> RWO volume reports `Multi-Attach error`, and the replacement pod never starts — the
> failover hangs indefinitely rather than being slow. Set it to
> `delete-both-statefulset-and-deployment-pod` for the drift to complete. This is a Longhorn
> setting, not a chart value.

## Cross-group backup isolation

The external backup destination is shared-by-prefix: each group replicates under
`backup.external.pathPrefix` (default `.Release.Namespace`). **Two groups must never share a
prefix** — a shared prefix is cross-group shared-fate. Prefer a **per-group bucket** or
IAM-scoped credentials pinned to the prefix. **Never** reuse `s3-access-key` /
`s3-secret-key` (this group's MinIO root) as the backup credentials — the backup S3 is a
different trust domain; use `backup.external.accessKey`/`secretKey`. In-cluster shared
backup MinIO across groups is a deliberate non-goal (it would require a namespaceSelector
egress to another group); use a dedicated backup namespace or an off-cluster S3.

> **`storage.enabled` and node binding.** On k3s `local-path`, a PV is pinned to its node
> (nodeAffinity), so a pod cannot fail over to another node. True pod mobility needs a
> networked RWO CSI (Longhorn / Ceph), at the cost of SQLite fsync traversing the network.
> B1 Litestream is the recommended recovery path on `local-path`: after deleting the pod +
> PVC, a fresh volume is rebuilt from S3 (RTO in the tens of seconds).

## Trash cleanup

drust soft-deletes tenants into `/data/_trash/<dir>`. The maintenance sidecar's
daily loop runs the session janitor (`drust_session_janitor`) **and** attempts a
trash sweep (`find /data/_trash -mtime +7 -exec rm -rf`). The sweep is
**non-fatal**: the slim runtime image is not guaranteed to ship `find`, so if
`find` is missing the sidecar logs `trash sweep skipped` and keeps running the
janitor. If your image lacks `find`, reclaim trash manually:

```bash
kubectl -n group-a exec sts/drust -c drust -- sh -c 'rm -rf /data/_trash/<dir>'
```

or schedule your own busybox CronJob mounting the same PVC (`find /data/_trash -mtime +7 -delete`).

## Known caveats

- **Traefik `customRequestHeaders.Host` is version sensitive.** Some Traefik
  builds do not apply the Host rewrite via the Middleware header. Always run the
  MCP Host live-verify above; the fallback is nginx-ingress or a Traefik
  `IngressRoute` + `passHostHeader`.
- **`networkPolicy.clusterCIDRs` must match your cluster's real pod/service
  CIDRs.** The defaults (`10.42.0.0/16` / `10.43.0.0/16`) are the k3s defaults;
  if your cluster differs, the internet-egress `except` block will either leak
  cross-group reachability or over-block. Confirm your CNI's CIDRs. The
  destination group's ingress policy is the fail-closed backstop — but only if
  **every** group deploys with `networkPolicy.enabled`.
- **nginx-ingress needs `networkPolicy.ingressControllerNamespace`.** It defaults
  to `kube-system` (correct for k3s Traefik); nginx-ingress usually runs in
  `ingress-nginx`. If it is wrong, the NetworkPolicy black-holes the controller's
  traffic to drust (and to MinIO when `publicFiles.enabled`). `networkPolicy.dnsNamespace`
  likewise assumes cluster DNS runs in `kube-system`.
- **MinIO runs with `readOnlyRootFilesystem: true`.** MinIO persists under `/data`
  and uses `HOME=/tmp` (emptyDir), so a read-only root is expected to work — but
  confirm MinIO reaches `/minio/health/ready` on your image tag after first
  install; if it crash-loops on a read-only root, that is the place to look.
- **`GARAGE_ADMIN_ENDPOINT` / `GARAGE_ADMIN_TOKEN` are unused placeholders.**
  drust's config requires them to be present whenever `GARAGE_S3_ENDPOINT` is
  set, but MinIO has no Garage admin API and they are never dialed. The chart
  injects harmless placeholder values so boot does not fail.
- **`ingress.tls.enabled: false` is evaluation-only.** Over plain HTTP the chart
  sets `DRUST_DEV_NO_SECURE_COOKIES=1`, so the admin session cookie ships without
  the `Secure` flag — otherwise user agents drop it (RFC 6265bis) and admin login
  silently never sticks (the POST 303s but every `/admin` request bounces back to
  `/login`). This weakens session security; use it only for local evaluation. The
  client-facing file-URL host, `DRUST_PUBLIC_BASE_URL`, is derived automatically
  from `ingress.host` + the TLS toggle (you do **not** set it in values) instead of
  `localhost:8793`. Note **public**-visibility file URLs (`/public/<id>/<key>`) are
  only actually served when `publicFiles.enabled=true` — that flag is what routes
  `/public` to MinIO; private and pre-signed URLs are served through drust regardless.

## Test the chart

The offline render-test harness needs `helm` + `kubeconform` on `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
bash tests/render_test.sh
```

It runs `helm lint`, renders every fixture with `helm template`, asserts the
invariants (single writer, hardened securityContext, mandatory env, Host
rewrite, storage/ingress gating, NetworkPolicy, backup), and validates each
rendered manifest set with `kubeconform -ignore-missing-schemas` (CRDs such as
Traefik `Middleware` and `VolumeSnapshot` are skipped). A clean run prints
`0 failure(s)` and `0 chart(s) failed`.

The fixture matrix includes `litestream.yaml` (B1 sidecar + restore init, storage off to
prove independence, `allowInternetEgress:false` to prove egress decoupling),
`backup-mirror.yaml` (B2 hourly object mirror), and `placement.yaml` (B3 scheduling
passthrough on both StatefulSets), alongside the base fixtures.
