#!/bin/sh
# One-shot, idempotent RustFS setup for drust (docker-compose.storage.yml). Runs in
# the rustfs/rustfs image, whose bundled `rc` is the only client that can manage
# RustFS users and policies. Prints no secret.
set -eu
die() { echo "rustfs-init: $*" >&2; exit 1; }
for v in RUSTFS_ACCESS_KEY RUSTFS_SECRET_KEY GARAGE_S3_ACCESS_KEY GARAGE_S3_SECRET_KEY; do
  eval "val=\${$v:-}"
  [ -n "$val" ] || die "$v is empty (run deploy/compose-storage-env.sh)"
done
[ "$RUSTFS_ACCESS_KEY" != rustfsadmin ] && [ "$RUSTFS_SECRET_KEY" != rustfsadmin ] \
  || die "refusing RustFS's published default credentials (run deploy/compose-storage-env.sh)"
[ "$GARAGE_S3_ACCESS_KEY" != "$RUSTFS_ACCESS_KEY" ] \
  || die "GARAGE_S3_ACCESS_KEY must be drust's own key, not the RustFS root key"

# The JSON files sit next to this script (Compose and the k3s chart both mount /init).
here="$(cd "$(dirname "$0")" && pwd)"
export RC_CONFIG_DIR=/tmp/rc
export RC_HOST_s3="http://${RUSTFS_ACCESS_KEY}:${RUSTFS_SECRET_KEY}@rustfs:9000"
# Fixed names: drust's write path hardcodes them (storage::files::bucket_for).
rc bucket create s3/public  --ignore-existing >/dev/null
rc bucket create s3/private --ignore-existing >/dev/null
# Anonymous GetObject on "public" ONLY. Never `rc bucket anonymous set download`:
# that also grants s3:ListBucket, so anyone could list every tenant's public keys.
# "private" gets no policy at all. Without public-read.json next to this script (the
# k3s chart leaves it out when publicFiles.enabled is false) "public" gets no policy
# either, and one set earlier is removed.
if [ -f "$here/public-read.json" ]; then
  rc bucket anonymous set-json "$here/public-read.json" s3/public >/dev/null
  public="anonymous GetObject on public"
else
  rc bucket anonymous set private s3/public >/dev/null
  public="no anonymous access"
fi
rc admin policy create s3 drust-objects "$here/drust-objects.json" >/dev/null
# Always (re)set drust's user from .env. On an existing user `rc admin user add`
# replaces the secret, so an edited GARAGE_S3_SECRET_KEY takes effect here instead
# of leaving drust on a key RustFS no longer accepts.
rc admin user add s3 "$GARAGE_S3_ACCESS_KEY" "$GARAGE_S3_SECRET_KEY" >/dev/null
rc admin policy attach s3 drust-objects --user "$GARAGE_S3_ACCESS_KEY" >/dev/null
echo "rustfs-init done: buckets public+private, $public, drust key scoped to both"
