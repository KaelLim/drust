//! Small formatting helpers shared across the admin UI.
//!
//! Lives here because it's only used by `mgmt::*` view-models (tenants list,
//! backups list, files page). Binary-unit conversion: 1 KB = 1024 B.

/// Format a byte count as `"NNN B"` / `"N.N KB"` / `"N.N MB"` / `"N.NN GB"`.
pub fn humanize_bytes(n: u64) -> String {
    const K: u64 = 1024;
    let nf = n as f64;
    if n < K {
        format!("{n} B")
    } else if n < K * K {
        format!("{:.1} KB", nf / K as f64)
    } else if n < K * K * K {
        format!("{:.1} MB", nf / (K * K) as f64)
    } else {
        format!("{:.2} GB", nf / (K * K * K) as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanize_bytes_unit_boundaries() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1023), "1023 B");
        assert_eq!(humanize_bytes(1024), "1.0 KB");
        assert_eq!(humanize_bytes(1536), "1.5 KB");
        assert_eq!(humanize_bytes(2048), "2.0 KB");
        assert_eq!(humanize_bytes(2_097_152), "2.0 MB");
        assert_eq!(humanize_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(humanize_bytes(2_147_483_648), "2.00 GB");
    }
}
