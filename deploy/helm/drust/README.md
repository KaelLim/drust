# drust — k3s multi-instance Helm chart

> [!IMPORTANT]
> **This chart is on hold.** It is frozen at chart 0.2.0 for drust 1.67.0, which is what a
> default install pulls, and it is not updated for later drust releases. Docker (the image
> and Docker Compose) and bare-metal systemd are the maintained deployment targets.
> Pointing it at a later drust image through `image.tag` is untested: its `/public` proxy
> rules, env and volumes match 1.67.0 only.

## What this is

This chart deploys **one drust instance per group**, with hard isolation between
groups. Each Helm release lives in its own namespace and stands up a complete,
self-contained drust stack: a single-writer drust StatefulSet, its own dedicated
RustFS object store, a bucket-and-key init hook Job, Services, an Ingress with the
mandatory rmcp Host rewrite, a bootstrap Secret, a default-deny NetworkPolicy,
an optional `public-proxy` Caddy that serves `/public/*` (`publicFiles.enabled`),
an optional maintenance sidecar, and an optional CSI-snapshot backup CronJob.

The topology is deliberately "one group = one namespace = one release = one
drust + one object store". Nothing is shared across groups — not the database, not the
object store, not the network path. To add a group you install the chart again
into a new namespace with a new values file. drust's own program code is never
modified; a single GHCR image (`ghcr.io/kaellim/drust`) is parameterised purely
through Helm values.

> The single-writer invariant is load-bearing: the drust and RustFS StatefulSets are
> pinned to `replicas: 1` on ReadWriteOnce
> volumes. **Never** scale any of them above 1 against the same volume — SQLite and a
> single-node object store are single-writer stores and concurrent writers corrupt them.

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
  and `/logs` PVCs and the object store's PVC (`rustfs-data-rustfs-0`). Set
  `persistence.storageClassName` (and `storage.rustfs.pvcSize`) or leave
  `storageClassName` empty to use the cluster default.

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
  enabled: false                  # true => /public/* anon-read of the public bucket, via public-proxy
storage:
  enabled: true                   # the bundled RustFS
  accessKey: "CHANGEME"           # drust's own key:      openssl rand -hex 10
  secretKey: "CHANGEME"           #                       openssl rand -hex 20
  rustfs:
    rootAccessKey: "CHANGEME"     # RustFS root, not drust's: openssl rand -hex 10
    rootSecretKey: "CHANGEME"     #                           openssl rand -hex 20
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

You **must** provide `secrets.adminPassword`, and when `storage.enabled` the four
storage keys (next section) — the chart's `required` guards fail
the render otherwise. If you manage credentials outside Helm, set
`secrets.create=false` and point `secrets.existingSecret` at a pre-created Secret
carrying the same keys (`admin-username`, `admin-password`, and the storage keys in
the table below). An existing Secret that still carries the old `admin-endpoint` /
`admin-token` keys keeps working: nothing reads them any more. When a backup feature (B1/B2) is
enabled with `backup.external.create=false`, also pre-create the backup Secret named by
`backup.external.existingSecret` with keys `backup-s3-access-key` / `backup-s3-secret-key`.

## Object store and its keys

The bundled object store is RustFS: a StatefulSet `rustfs`, Service `rustfs:9000`, PVC
`rustfs-data-rustfs-0`, and a `rustfs-init` post-install/post-upgrade/post-rollback hook
Job. The Secret holds two key pairs for it:

| Secret key | Values | Read by |
|---|---|---|
| `s3-access-key` / `s3-secret-key` | `storage.accessKey` / `storage.secretKey` (drust's own key) | drust, `rustfs-init`, `backup-mirror` |
| `rustfs-root-access-key` / `rustfs-root-secret-key` | `storage.rustfs.rootAccessKey` / `storage.rustfs.rootSecretKey` | the `rustfs` StatefulSet and `rustfs-init` only |

The root key never reaches the drust pod. `rustfs-init` runs the same
`init.sh`, `public-read.json` and `drust-objects.json` as Docker Compose
(`deploy/compose-rustfs/`; the chart's copies in `files/rustfs-init/` are byte-checked by
`render_test.sh`): it creates the `public` and `private` buckets, gives `public` an
anonymous GetObject-only policy when `publicFiles.enabled` (and removes it when not), and
creates drust's user limited to those two buckets — it cannot create buckets or change
who may read `public`. With `secrets.create` the render fails when `storage.accessKey`
equals `storage.rustfs.rootAccessKey`, or when a root key is RustFS's published default
`rustfsadmin` or holds anything but letters and digits; `init.sh` refuses the first two in
every case, at hook time.

- **Generate and pass keys from files**: `openssl rand -hex 10 > ak` for an access key,
  `openssl rand -hex 20 > sk` for a secret, then `-f values.yaml` or `--set-file
  storage.secretKey=sk` — not `--set`, which lands in shell history. The chart trims the
  trailing newline such a file ends with (`--set-file` keeps it).
- **Random keys only.** The `checksum/s3-key` and `checksum/root-key` pod annotations are an
  unsalted SHA-256 of each key pair, readable by anyone who may read pods; for a 160-bit
  random key that reveals nothing, for a chosen password it is a guessing oracle.
- **Letters and digits only** for the RustFS root key: `init.sh` puts it in an
  `http://key:secret@host` URL, so `/`, `@` or `:` breaks it. `openssl rand -hex` output is safe.
- **First install**: drust usually starts before the init Job has created its buckets and
  key, so two `object store bucket check failed` warnings in its boot log are expected;
  files work as soon as the Job is done (`NOTES` says the same).
- **Rotating drust's key**: change `storage.secretKey`. The drust pod
  restarts by itself (a `checksum/s3-key` annotation) and the hook sets the new secret on
  the existing RustFS user; for a few seconds in between, file calls may get 403. Changing
  `storage.accessKey` instead creates a **second** RustFS user and leaves the old one
  working on both buckets (users live on the PVC). Remove it with the root key, which the
  `rustfs-0` container already holds (the single quotes keep it out of your terminal; the
  pod has no writable alias file, so the alias comes from the environment):

  ```bash
  kubectl -n <ns> exec rustfs-0 -- sh -c \
    'RC_HOST_s3="http://$RUSTFS_ACCESS_KEY:$RUSTFS_SECRET_KEY@127.0.0.1:9000" rc admin user rm s3 <old access key>'
  ```

  The same prefix with `rc admin user ls s3` lists what is left.
- **Rotating the root key**: change `storage.rustfs.rootSecretKey` (or both). `rustfs-0`
  restarts (`checksum/root-key`), takes the new key from env and keeps its users and
  buckets; the hook then logs in with it.
- **`helm rollback`** runs `rustfs-init` too (`post-rollback`): RustFS holds drust's secret
  as the hook last set it, so a rollback to an older `storage.secretKey` or `publicFiles`
  needs that run to match the restored Secret again.
- **With `secrets.existingSecret`** Helm cannot see the values, so nothing restarts by
  itself. After changing drust's key in that Secret: `helm upgrade` (the hook applies it),
  then `kubectl rollout restart sts/drust`. After changing the root key: `kubectl rollout
  restart sts/rustfs` first, then `helm upgrade`. A missing key shows as
  `CreateContainerConfigError` on the pod that needs it.

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
> (all tenant SQLite databases + stored objects), irreversibly on a `reclaimPolicy:
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

## Upgrading from 0.1.x

Chart 0.2.0 replaces the bundled MinIO with RustFS. It neither looks for MinIO nor moves
files:

- `storage.accessKey`, `storage.secretKey`, `storage.rustfs.rootAccessKey` and
  `storage.rustfs.rootSecretKey` are required, so with `secrets.create` an upgrade with an
  old values file stops at render with a `required` message. Upgrade with `-f` your values
  file, never `--reuse-values` (it does not read this chart's new defaults).
- With `secrets.existingSecret` nothing is checked at render: the upgrade goes through and
  `rustfs-0` and the hook sit in `CreateContainerConfigError` until the hook times out. Add
  `rustfs-root-access-key` and `rustfs-root-secret-key` to that Secret before upgrading, and
  keep `s3-access-key` different from the root access key (`init.sh` refuses it).
- Helm removes the MinIO StatefulSet, Service and NetworkPolicies. The `minio-init` hook
  Job was deleted when it succeeded; a failed one stays until you delete it. The PVC
  `minio-data-minio-0` is left in place, and nothing reads it.
- Files uploaded before the upgrade are not in RustFS, and the chart does not copy them: their
  `/public` URL answers 404, while drust still lists them and their download answers 502.
  If you need them, copy them with an S3 client that keeps object metadata (Content-Type,
  Content-Disposition, Cache-Control) before you delete that PVC.

## Uninstall

```bash
helm uninstall group-a --namespace group-a
```

**PVCs are intentionally retained.** `helm uninstall` removes the release's
workloads but **not** the StatefulSet PVCs — reinstalling the same release
re-binds the existing `data-drust-0` / `logs-drust-0` / `rustfs-data-rustfs-0`
volumes, so tenant data survives. This is deliberate: the PVC *is* the database.
A `rustfs-init` hook Job that failed also stays, with the pods of its failed attempts (Helm
does not delete hook resources on uninstall); `kubectl delete job rustfs-init` removes both.
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
the backup bucket with `rclone`, image `s3ClientImage`), then `litestream-restore` (restores each DB via `litestream
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
  so it can read the DBs it wrote). `rclone` was seen running there (uid 10001, read-only
  root, `HOME=/tmp`); confirm `litestream` with one live restore drill.
- The enumerate step probes **this group's own prefix**, never the bucket list, so a key
  whose policy is scoped to `<prefix>/` (as recommended below) works: such a key cannot
  list buckets. Its remote is configured from env only (`RCLONE_CONFIG_BK_*`, keys by
  `secretKeyRef`), never from a URL or a config file.

> [!CAUTION]
> **Cross-group backup isolation is the operator's job.** The replicated `meta.sqlite` carries
> PLAINTEXT tokens (`tokens.plaintext` / `_admin_tokens.plaintext`). `pathPrefix` (default = the
> group's namespace) is only a SOFT boundary — if two groups target the SAME bucket with
> bucket-wide credentials, group A can list/read group B's prefix = full data-plane + admin-PAT
> compromise of the other group. Give each group EITHER a distinct bucket OR credentials whose
> IAM policy is scoped to that group's `<prefix>/` only.

## Object-file backup (B2)

`backup.objectMirror.*` adds an hourly CronJob that copies this group's object-store
`public` + `private` buckets (from RustFS, with drust's key) to the same external S3 under `<prefix>/objects/`, with `rclone copy -M`
(image `s3ClientImage`). Litestream handles the databases; this handles only the object
files. A changed object is replaced, but it is a **copy, never a sync**: an accidental
source delete does not propagate into the backup, so a deleted object stays recoverable —
the trade-off is the backup only grows, so prune it with a bucket lifecycle policy on the
S3 side. Two settings are load-bearing (each was seen to fail without it):

- `-M` keeps `Content-Type`, `Content-Disposition`, `Cache-Control` and `x-amz-meta-*`.
  Without it only `Content-Type` survives, and `/public` serves the other two straight
  from the store, so a restore would change what anonymous clients get.
- `RCLONE_S3_NO_CHECK_BUCKET=true`: otherwise rclone tries `CreateBucket` before every
  upload, and a bucket-scoped backup key fails it with 403.

The Job retries its first connection (a new Job pod IP takes seconds to enter the CNI
NetworkPolicy allow-set, same cause as the init Jobs), probes this group's backup prefix
rather than the bucket list (a prefix-scoped key cannot list buckets), wears a dedicated
label with its own scoped NetworkPolicy, and drops its ServiceAccount token. Needs
`storage.enabled`.

## /public

With `publicFiles.enabled: true` (and `storage.enabled`), the Ingress sends `/public/*`
to `public-proxy`, a one-replica Caddy Deployment, which serves it straight from the
store's `public` bucket. drust never sees these requests. The proxy's `/public/*` block,
`files/public-proxy.Caddyfile`, is a byte-for-byte copy of the Compose one in
`deploy/compose.Caddyfile` (`render_test.sh` fails when they differ), so every rule is
explained once, there. In short:

- **GET and HEAD only**; any other method answers 405.
- The bucket comes from configuration, never from the request path, and the **query
  string is dropped**: the store's S3 API honours `?response-content-type=` on
  anonymous GETs, which would re-serve any public object as HTML.
- `Authorization` and `Cookie` never reach the store, and the store's `Set-Cookie`
  never reaches the browser (this is the admin UI's origin).
- Every response carries `X-Content-Type-Options: nosniff`, and markup
  (`text/html`, `text/xml`, `application/xml`, `text/xsl`, `*+xml`, with or without
  parameters) gets `Content-Security-Policy: sandbox allow-top-navigation-by-user-activation`.
- **No listing**: anonymous access to `public` is GetObject on single objects only
  (`rustfs-init` applies `public-read.json`), so `GET /public/` answers 403.

Before this proxy, `/public` went from the Ingress straight to the store's port 9000:
markup was served with no CSP and `?response-content-type=` was honoured, a stored XSS
on the admin origin. The ingress controller now reaches only the proxy's port 8080;
the `rustfs` NetworkPolicy admits drust, `rustfs-init`, the backup mirror and the proxy,
and no namespace or address range.

Caveats:

- **Upper-case markup types get no CSP.** The proxy's matcher is case-sensitive, so a
  file stored with a type like `TEXT/HTML; charset=UTF-8` (possible for files uploaded
  before drust v1.56.3) is served without the sandbox. Remedy: set such a file private
  and then public again; the move lowercases its type.
- **A comma-joined declared type** (`<safe>/<x>,text/html`) is neither treated as
  markup by drust nor matched by the proxy. This is inherited from the Compose block
  (the byte copy keeps them identical) and is out of scope there too.
- **`publicProxy.image` must be bumped routinely.** This Caddy is the anonymous,
  internet-facing surface; it is pinned by tag and digest (Compose floats `caddy:2`
  instead), so moving the pin to the current Caddy 2.x release is part of routine chart
  maintenance, not optional.

## Scheduling / placement (B3)

`scheduling.drust.*`, `scheduling.rustfs.*` and `scheduling.publicProxy.*` pass
`nodeSelector` / `tolerations` / `affinity` / `topologySpreadConstraints` straight through to
the pod spec of the drust StatefulSet, the rustfs StatefulSet and the `public-proxy`
Deployment. The `rustfs-init` hook Job takes `scheduling.rustfs.nodeSelector` and
`.tolerations` (nothing else): on tainted nodes a hook pod with no toleration stays Pending
and every install and upgrade fails at the hook timeout. All default empty, so leaving them
unset is zero behavior change. The snapshot and backup-mirror CronJobs have no scheduling
values.

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
`s3-secret-key` (drust's key on this group's RustFS) as the backup credentials — the backup
S3 is a different trust domain; use `backup.external.accessKey`/`secretKey`. An in-cluster
backup store shared across groups is a deliberate non-goal (it would require a namespaceSelector
egress to another group); use a dedicated backup namespace or an off-cluster S3.

> **`storage.enabled` and node binding.** On k3s `local-path`, a PV is pinned to its node
> (nodeAffinity), so a pod cannot fail over to another node. True pod mobility needs a
> networked RWO CSI (Longhorn / Ceph), at the cost of SQLite fsync traversing the network.
> B1 Litestream is the recommended recovery path on `local-path`: after deleting the pod +
> PVC, a fresh volume is rebuilt from S3 (RTO in the tens of seconds).

## Trash cleanup

drust soft-deletes tenants into `/data/_trash/<dir>` and expires them **in-process**:
`DRUST_TRASH_RETENTION_DAYS` (default 7, `0` = keep forever; set it through `extraEnv`).
The maintenance sidecar's daily loop runs only the session janitor
(`drust_session_janitor`); it deliberately does no time-based trash sweep, which would cap
a longer retention and defeat `0`.

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
  traffic to drust (and to the `public-proxy` when `publicFiles.enabled`). `networkPolicy.dnsNamespace`
  likewise assumes cluster DNS runs in `kube-system`.
- **`ingress.tls.enabled: false` is evaluation-only.** Over plain HTTP the chart
  sets `DRUST_DEV_NO_SECURE_COOKIES=1`, so the admin session cookie ships without
  the `Secure` flag — otherwise user agents drop it (RFC 6265bis) and admin login
  silently never sticks (the POST 303s but every `/admin` request bounces back to
  `/login`). This weakens session security; use it only for local evaluation. The
  client-facing file-URL host, `DRUST_PUBLIC_BASE_URL`, is derived automatically
  from `ingress.host` + the TLS toggle (you do **not** set it in values) instead of
  `localhost:8793`. Note **public**-visibility file URLs (`/public/<id>/<key>`) are
  only actually served when `publicFiles.enabled=true` — that flag is what routes
  `/public` to the `public-proxy` (see "/public" above); private and pre-signed URLs are
  served through drust regardless.
- **Client addresses and `ingress.trustedProxies` (`DRUST_TRUSTED_PROXIES`, default
  `1`).** drust keys its per-IP rate limits (logins, register, OAuth callbacks, the CLI
  device flow, anonymous file upload/delete and function invoke) on the
  `X-Forwarded-For` entry that many positions from the right. `1` counts the ingress
  controller, which appends exactly one entry; add one per proxy in front of it that the
  controller is configured to trust (a cloud LB, a CDN). drust refuses to boot on a value
  outside `0..8`, so a typo shows as a crash-looping pod. Three things decide whether the
  key is really the client:
  1. **k3s ServiceLB SNAT.** With the default k3s ServiceLB (`svclb`) and
     `externalTrafficPolicy: Cluster` on the controller's Service, client traffic is
     SNATed to a node address before the controller sees it, so every client collapses
     onto that address (on a single-node k3s with Traefik every request arrived as
     `10.42.0.1`). That is fail-closed (one shared bucket), not a bypass. The fix is
     cluster-level: `externalTrafficPolicy: Local` on the controller's Service, or a
     source-preserving load balancer.
  2. **Controller forwarded-header settings.** ingress-nginx with
     `use-forwarded-headers: true` but without `compute-full-forwarded-for: true`
     forwards the client-supplied `X-Forwarded-For` verbatim, and so does Traefik with
     `forwardedHeaders.insecure=true`: the key is then whatever the client wrote, for any
     value of `trustedProxies`. Keep the controller's defaults, or set both nginx options
     with `proxy-real-ip-cidr` restricted to your load balancer.
  3. **NetworkPolicy.** With `networkPolicy.enabled: false`, or a
     `hostNetworkIngressCIDRs` that admits every hostNetwork process on the nodes rather
     than only the controller, a caller can reach drust's ClusterIP directly and pick its
     own bucket by sending a one-entry header. Keep the policy on and the CIDR list
     narrow.

  If you set `DRUST_TRUSTED_PROXIES` in `extraEnv` before, **move it to
  `ingress.trustedProxies`** when you upgrade: the render refuses `extraEnv` naming it,
  because the chart sets it now and a duplicate env name fails a server-side apply.

## Test the chart

The offline render-test harness needs `helm` + `kubeconform` on `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
bash tests/render_test.sh
```

It runs `helm lint`, renders every fixture with `helm template`, asserts the
invariants (single writer, hardened securityContext, mandatory env, Host
rewrite, storage/ingress gating, NetworkPolicy, backup), and validates each
rendered manifest set with `kubeconform -strict -ignore-missing-schemas` (CRDs such as
Traefik `Middleware` and `VolumeSnapshot` are skipped). A clean run prints
`0 failure(s)` and `0 chart(s) failed`.

The fixture matrix includes `litestream.yaml` (B1 sidecar + restore init, storage off to
prove independence, `allowInternetEgress:false` to prove egress decoupling),
`backup-mirror.yaml` (B2 hourly object mirror), `placement.yaml` (B3 scheduling
passthrough on both StatefulSets) and `existing-secret.yaml` (`secrets.create: false`),
alongside the base fixtures. Every fixture is also checked to render nothing named MinIO.

It also reads files outside the chart: `deploy/compose.Caddyfile`, whose `/public/*`
block `files/public-proxy.Caddyfile` must copy byte for byte, and
`deploy/compose-rustfs/{init.sh,public-read.json,drust-objects.json}`, which
`files/rustfs-init/` must equal byte for byte. Run it from a full checkout.
