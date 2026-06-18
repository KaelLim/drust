//! Regression test for the Docker-portability disk-path fix.
//!
//! `build_disk_view` and the upload guards used to `statvfs` a hardcoded
//! `/var/lib/garage` — a path that only exists on the original co-located-Garage
//! host. Inside the GHCR container that path is absent, so the admin disk panel
//! showed `?` and the Mode-A / function upload guards silently skipped. The fix
//! routes every disk check through `disk_check_root()`, set once at startup from
//! `Config.data_dir` (Docker `/data`, host `/var/lib/drust`).
//!
//! One test, one process: `disk_check_root` is a process-global `OnceLock`, so
//! the default-before-init assertion must run before any `init` in this binary.

use drust::storage::disk::{disk_check_root, disk_stats, init_disk_check_root};
use std::path::Path;

#[test]
fn disk_check_root_defaults_to_garage_then_honors_init_and_panel_shows_real_numbers() {
    // Before init: falls back to the historical path (preserves pre-fix
    // behavior for callers that never boot the full server).
    assert_eq!(
        disk_check_root(),
        Path::new("/var/lib/garage"),
        "uninitialised disk-check root must fall back to /var/lib/garage"
    );

    // After init: tracks the configured data dir. A tempdir is always a live,
    // statvfs-able filesystem — the stand-in for Docker's /data.
    let dir = tempfile::tempdir().unwrap();
    init_disk_check_root(dir.path().to_path_buf());
    assert_eq!(
        disk_check_root(),
        dir.path(),
        "after init, disk-check root must be the configured data dir"
    );

    // disk_stats now succeeds against a real filesystem (not the absent
    // /var/lib/garage), so free_pct is a real fraction.
    let stats = disk_stats(disk_check_root()).expect("statvfs of a live tempdir must succeed");
    assert!(
        stats.free_pct > 0.0 && stats.free_pct <= 100.0,
        "free_pct should be a real percentage, got {}",
        stats.free_pct
    );
    assert!(stats.total_bytes > 0, "total_bytes should be non-zero");

    // The admin disk panel renders real numbers instead of the "?" fallback —
    // exactly the symptom the user saw in the GHCR deployment.
    let view = drust::mgmt::public_files::build_disk_view();
    assert_ne!(
        view.used_gb, "?",
        "panel used_gb must be a real number once the root is a live dir"
    );
    assert_ne!(view.total_gb, "?", "panel total_gb must be a real number");
    assert_ne!(
        view.free_pct_display, "?",
        "panel free_pct must be a real number"
    );
}
