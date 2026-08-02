//! v1.58 P1-6 — a soft-deleted tenant must not be recreated on disk by a
//! background path.
//!
//! Several background call sites used the create-on-open accessor, while
//! `functions/executor.rs` and `functions/runtime.rs` deliberately used
//! `get_if_live` with a comment explaining exactly this hazard. A soft-delete
//! landing mid-loop rebuilt `tenants/<id>/data.sqlite` OUTSIDE `_trash`, and the
//! janitor only sweeps `_trash/*`, so the directory leaked permanently.

use drust::storage::pool::TenantRegistry;

#[test]
fn get_if_live_refuses_a_soft_deleted_tenant_and_get_or_create_still_creates() {
    let dir = tempfile::tempdir().unwrap();
    let reg = TenantRegistry::new(dir.path().to_path_buf(), 2);

    // A live tenant: created, then reachable both ways.
    let _ = reg.get_or_create("live").unwrap();
    assert!(reg.get_if_live("live").is_some());

    // Simulate the soft-delete: evict the cached pool and move the directory
    // aside exactly as `soft_delete` does.
    reg.evict("live");
    let src = dir.path().join("tenants").join("live");
    let dst = dir.path().join("_trash").join("live-20260802");
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    std::fs::rename(&src, &dst).unwrap();

    assert!(
        reg.get_if_live("live").is_none(),
        "get_if_live must report a soft-deleted tenant as gone"
    );
    assert!(
        !src.exists(),
        "get_if_live must not have recreated the tenant directory"
    );

    // The creation path is unchanged and still creates.
    let _ = reg.get_or_create("brand-new").unwrap();
    assert!(dir.path().join("tenants").join("brand-new").exists());
}
