//! v1.58 P1-1 (front half) — recycling a tenant id must not destroy the
//! soft-deleted tenant's recovery copy.
//!
//! Creating a tenant whose id collides with a soft-deleted one hard-purged
//! `_trash/<id>-<ts>/` as well as the live remnants, silently ending the 7-day
//! recovery window. That is a data-loss footgun independent of who is calling —
//! the missing ownership check on the same branch is deferred to #906.

use std::fs;

#[test]
fn recycling_an_id_leaves_the_trash_snapshot_intact() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let mut conn = drust::storage::meta::open_meta(&data.join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, data).unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) \
         VALUES (1, 'boss', 'h', 'owner')",
        [],
    )
    .unwrap();

    // Create, then soft-delete: the row is marked and the directory moves.
    drust::mgmt::tenants::crud::make_tenant_inner(&mut conn, data, "acme", "Acme", 10, 1000, 1)
        .unwrap();
    conn.execute(
        "UPDATE tenants SET deleted_at = datetime('now') WHERE id = 'acme'",
        [],
    )
    .unwrap();
    let trash = data.join("_trash").join("acme-20260802");
    fs::create_dir_all(&trash).unwrap();
    fs::write(trash.join("data.sqlite"), b"recoverable").unwrap();

    // Recycle the id.
    drust::mgmt::tenants::crud::make_tenant_inner(&mut conn, data, "acme", "Acme 2", 10, 1000, 1)
        .unwrap();

    assert!(
        trash.join("data.sqlite").exists(),
        "the recovery snapshot must survive an id recycle"
    );
    assert_eq!(
        fs::read(trash.join("data.sqlite")).unwrap(),
        b"recoverable",
        "and must be untouched"
    );
    // The new tenant exists and is live.
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE id='acme' AND deleted_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(live, 1);
}
