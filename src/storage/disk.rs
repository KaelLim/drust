//! Filesystem statistics helper used by upload handlers to enforce the
//! low-disk guard (`DRUST_DISK_MIN_FREE_PCT`). Wraps POSIX `statvfs`.

use std::path::Path;

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
    let free = (stat.blocks_available() as u64).saturating_mul(block);
    let used = total.saturating_sub(free);

    let free_pct = if total == 0 {
        0.0
    } else {
        (free as f64 / total as f64) * 100.0
    };

    Ok(DiskStats {
        total_bytes: total,
        free_bytes: free,
        used_bytes: used,
        free_pct,
    })
}
