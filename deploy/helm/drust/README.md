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
  **cluster-admin** (the chart creates a Namespace, NetworkPolicies, and — when
  backup is enabled — a Role/RoleBinding).
- An **ingress controller**: **Traefik** (the k3s default, and this chart's
  default) or **nginx-ingress**. Select with `ingress.controller`.
- **cert-manager** with a `ClusterIssuer`, only if you enable TLS
  (`ingress.tls.enabled=true`). The issuer name goes in `ingress.tls.issuer`.
- A **CSI `VolumeSnapshotClass`**, only if you enable backups
  (`backup.volumeSnapshotClassName`). Leave it empty and no backup objects
  render.
- A **CSI storage class that supports `ReadWriteOnce`** for the drust `/data`
  and `/logs` PVCs and the MinIO data PVC. Set `persistence.storageClassName`
  (and `storage.minio.pvcSize`) or leave `storageClassName` empty to use the
  cluster default.

> [!CAUTION]
> Leave `createNamespace: false` (the default) and create namespaces with
> `helm install --create-namespace`. Setting `createNamespace: true` makes the
> release OWN the Namespace object, so `helm uninstall` deletes the namespace —
> which reaps **all three PVCs** (every tenant's SQLite database, the logs, and
> the MinIO objects; permanent on a `reclaimPolicy: Delete` StorageClass). With
> the default, uninstall leaves the PVCs `Bound` and a reinstall re-binds them.

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
`s3-secret-key`, `admin-endpoint`, `admin-token`).

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
