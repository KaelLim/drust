//! v1.58 P1-1 — the tenant-id recycle branch and the soft-delete snapshot it
//! leaves behind.
//!
//! Three defects, one code path:
//!
//! 1. Creating a tenant whose id collided with a soft-deleted one hard-purged
//!    `_trash/<id>-<ts>/` as well as the live remnants, silently ending the
//!    7-day recovery window.
//! 2. The same branch hard-DELETEs the old tenant's row and tokens with no
//!    ownership check, on a route (`POST /admin/api/tenants`) that carries no
//!    `{id}` and therefore inherits no guard from `tenant_ownership_layer` —
//!    CLAUDE.md invariant #7.
//! 3. Once (1) was fixed, `delete → create → delete` on one id inside one
//!    wall-clock second aimed the second snapshot rename at a path that
//!    already existed and was non-empty; `rename(2)` answered ENOTEMPTY and
//!    the error was discarded, stranding a deleted tenant's database in the
//!    live tree.

use drust::mgmt::tenants::crud::{make_tenant_inner, move_tenant_to_trash};
use std::fs;
use std::path::Path;

fn meta_with_admins(data: &Path) -> rusqlite::Connection {
    let conn = drust::storage::meta::open_meta(&data.join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, data).unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) \
         VALUES (1, 'boss', 'h', 'owner')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) \
         VALUES (2, 'mallory', 'h', 'member')",
        [],
    )
    .unwrap();
    conn
}

fn soft_delete_row(conn: &rusqlite::Connection, id: &str) {
    conn.execute(
        "UPDATE tenants SET deleted_at = datetime('now') WHERE id = ?1",
        rusqlite::params![id],
    )
    .unwrap();
}

#[test]
fn recycling_an_id_leaves_the_trash_snapshot_intact() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let mut conn = meta_with_admins(data);

    // Create, then soft-delete: the row is marked and the directory moves.
    make_tenant_inner(&mut conn, data, "acme", "Acme", 10, 1000, 1).unwrap();
    soft_delete_row(&conn, "acme");
    let trash = data.join("_trash").join("acme-20260802");
    fs::create_dir_all(&trash).unwrap();
    fs::write(trash.join("data.sqlite"), b"recoverable").unwrap();

    // Recycle the id.
    make_tenant_inner(&mut conn, data, "acme", "Acme 2", 10, 1000, 1).unwrap();

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

/// Invariant #7 on the recycle branch. Mallory is a `member`; tenant ids leak
/// through `/public/<tenant-id>/<key>` URLs, so knowing one is not a secret.
/// Recycling a foreign soft-deleted id would hard-DELETE its row and tokens —
/// destroying a tenant she can never see, mid-recovery-window, and making the
/// un-delete impossible because the row itself is gone.
#[test]
fn a_member_cannot_recycle_a_foreign_soft_deleted_tenant_id() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let mut conn = meta_with_admins(data);

    // The owner's tenant, soft-deleted exactly as the handler leaves it.
    make_tenant_inner(&mut conn, data, "victim", "Victim", 10, 1000, 1).unwrap();
    soft_delete_row(&conn, "victim");
    let snapshot = move_tenant_to_trash(data, "victim", "20260802T120000Z").unwrap();
    assert!(snapshot.join("data.sqlite").exists());

    let err = make_tenant_inner(&mut conn, data, "victim", "Mine Now", 10, 1000, 2)
        .expect_err("a member must not be able to recycle a foreign tenant's id");
    assert!(
        err.to_string().contains("already exists"),
        "unexpected error: {err}"
    );

    // Nothing was destroyed: the row, its owner, its tokens and its recovery
    // copy all survive, so the owner can still be given it back.
    let (owner, deleted): (Option<i64>, Option<String>) = conn
        .query_row(
            "SELECT owner_admin_id, deleted_at FROM tenants WHERE id='victim'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(owner, Some(1), "ownership must not be stamped over");
    assert!(
        deleted.is_some(),
        "the row must still be the soft-deleted one"
    );
    let tokens: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tokens WHERE tenant_id='victim'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tokens, 2, "the victim's tokens must not be deleted");
    assert!(
        snapshot.join("data.sqlite").exists(),
        "the recovery copy must not be touched"
    );
}

/// The refusal must not say *why* the id is unavailable: a soft-deleted tenant
/// the caller cannot see has to look exactly like a live one, or the create
/// endpoint reports the lifecycle state of tenants the management plane 404s.
#[test]
fn an_invisible_soft_deleted_tenant_looks_exactly_like_a_live_one() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let mut conn = meta_with_admins(data);

    make_tenant_inner(&mut conn, data, "alive", "Alive", 10, 1000, 1).unwrap();
    make_tenant_inner(&mut conn, data, "gone", "Gone", 10, 1000, 1).unwrap();
    soft_delete_row(&conn, "gone");

    let on_live = make_tenant_inner(&mut conn, data, "alive", "x", 10, 1000, 2)
        .expect_err("live id is taken")
        .to_string();
    let on_deleted = make_tenant_inner(&mut conn, data, "gone", "x", 10, 1000, 2)
        .expect_err("foreign soft-deleted id is not recyclable by a member")
        .to_string();
    assert_eq!(
        on_live.replace("alive", "<id>"),
        on_deleted.replace("gone", "<id>"),
        "the two refusals must be indistinguishable"
    );
}

/// The gate is visibility, not a blanket ban: a member recycling an id they
/// own themselves is the ordinary "start this database over" workflow.
#[test]
fn a_member_can_recycle_an_id_they_own() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let mut conn = meta_with_admins(data);

    make_tenant_inner(&mut conn, data, "mine", "Mine", 10, 1000, 2).unwrap();
    soft_delete_row(&conn, "mine");
    move_tenant_to_trash(data, "mine", "20260802T120000Z").unwrap();

    make_tenant_inner(&mut conn, data, "mine", "Mine Again", 10, 1000, 2)
        .expect("a member owns this id and may recycle it");
    let owner: Option<i64> = conn
        .query_row(
            "SELECT owner_admin_id FROM tenants WHERE id='mine' AND deleted_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(owner, Some(2));
}

/// Second-resolution snapshot names collide once the create stops purging the
/// previous one. Before the fix the second `rename(2)` returned ENOTEMPTY, the
/// error was discarded, and `tenants/acme` — the *second* tenant's live
/// database, argon2 hashes and unexpired sessions included — stayed in the live
/// tree that no janitor sweeps, while meta said it was deleted.
#[test]
fn two_soft_deletes_of_one_id_in_the_same_second_get_separate_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let ts = "20260802T120000Z";
    let live = data.join("tenants").join("acme");

    fs::create_dir_all(&live).unwrap();
    fs::write(live.join("data.sqlite"), b"generation-one").unwrap();
    let first = move_tenant_to_trash(data, "acme", ts).expect("first snapshot");
    assert_eq!(first, data.join("_trash").join(format!("acme-{ts}")));

    // Same id recycled and soft-deleted again inside the same wall-clock second.
    fs::create_dir_all(&live).unwrap();
    fs::write(live.join("data.sqlite"), b"generation-two").unwrap();
    let second = move_tenant_to_trash(data, "acme", ts)
        .expect("the second move must succeed, not be swallowed by `let _ =`");

    assert_ne!(first, second, "the two snapshots must not share a path");
    assert!(
        !live.exists(),
        "a deleted tenant's database must never be left in the live tree"
    );
    assert_eq!(
        fs::read(first.join("data.sqlite")).unwrap(),
        b"generation-one"
    );
    assert_eq!(
        fs::read(second.join("data.sqlite")).unwrap(),
        b"generation-two"
    );
    // Both shapes must stay under `_trash/` so either janitor still sweeps them.
    assert_eq!(second.parent().unwrap(), data.join("_trash"));
}
