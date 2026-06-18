//! Filesystem statistics helper used by upload handlers to enforce the
//! low-disk guard (`DRUST_DISK_MIN_FREE_PCT`). Wraps POSIX `statvfs`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Process-wide root whose filesystem the upload guards + admin disk panel
/// report on. Set once at startup from `Config.data_dir` so the check follows
/// the deployment — host `/var/lib/drust`, Docker `/data` — instead of a
/// hardcoded path that only existed on the original co-located-Garage host
/// (`/var/lib/garage`, absent inside the container → "?" panel + skipped
/// guards). `statvfs` reports the filesystem *containing* this path, so the
/// numbers track wherever the service actually writes its data.
static DISK_CHECK_ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Install the disk-check root. First call wins (`OnceLock::set`), matching the
/// single startup call in `main`; later calls are no-ops.
pub fn init_disk_check_root(root: PathBuf) {
    let _ = DISK_CHECK_ROOT.set(root);
}

/// The path whose filesystem `statvfs` reports on. Falls back to the historical
/// `/var/lib/garage` when `init_disk_check_root` was never called (e.g. unit
/// tests that don't boot the full server) — preserving pre-fix behavior there.
pub fn disk_check_root() -> &'static Path {
    DISK_CHECK_ROOT
        .get()
        .map(PathBuf::as_path)
        .unwrap_or_else(|| Path::new("/var/lib/garage"))
}

#[derive(Debug, Clone, Copy)]
pub struct DiskStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub used_bytes: u64,
    pub free_pct: f64,
}

pub fn disk_stats(path: &Path) -> anyhow::Result<DiskStats> {
    let stat = nix::sys::statvfs::statvfs(path)
        .map_err(|e| anyhow::anyhow!("statvfs({:?}): {e}", path))?;

    let block = stat.fragment_size() as u64;
    let total = (stat.blocks() as u64).saturating_mul(block);
    // Truly free blocks (includes the slice ext4 reserves for root).
    let free_total = (stat.blocks_free() as u64).saturating_mul(block);
    // Free blocks available to non-root callers — what `df` reports as
    // "Avail" and what the upload guard cares about (drust runs unprivileged).
    let free_available = (stat.blocks_available() as u64).saturating_mul(block);
    // `df`-style used: total minus all free blocks. Counting the reserved
    // slice as used would overstate consumption by ~5% (≈9 GB on a 180 GB
    // filesystem) and not match what an operator sees in the shell.
    let used = total.saturating_sub(free_total);

    let free_pct = if total == 0 {
        0.0
    } else {
        (free_available as f64 / total as f64) * 100.0
    };

    Ok(DiskStats {
        total_bytes: total,
        free_bytes: free_available,
        used_bytes: used,
        free_pct,
    })
}
