//! v1.57 — the member tenant-creation cap, exercised through the real
//! `make_tenant_inner` write path against a real meta.sqlite.
//!
//! The gate lives inside `make_tenant_inner` (not in the two HTTP handlers) so
//! it is inside the same meta-mutex critical section as the INSERT, and so a
//! future third creation entry point inherits it.

use drust::mgmt::tenant_cap;

/// A meta.sqlite with the migrated schema plus one owner and one member.
fn setup() -> (rusqlite::Connection, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let conn = drust::storage::meta::open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) \
         VALUES (1, 'boss', 'h', 'owner')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) \
         VALUES (2, 'mem', 'h', 'member')",
        [],
    )
    .unwrap();
    (conn, dir)
}

#[test]
fn owned_count_ignores_soft_deleted_and_other_owners() {
    let (conn, _dir) = setup();
    conn.execute(
        "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('a', 'A', 2)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name, owner_admin_id, deleted_at) \
         VALUES ('b', 'B', 2, datetime('now'))",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('c', 'C', 1)",
        [],
    )
    .unwrap();

    assert_eq!(
        tenant_cap::owned_tenant_count(&conn, 2).unwrap(),
        1,
        "only live tenants owned by this admin count — deleting frees a slot"
    );
    assert_eq!(tenant_cap::owned_tenant_count(&conn, 1).unwrap(), 1);
}

#[test]
fn effective_cap_for_admin_reads_role_and_bonus() {
    let (conn, _dir) = setup();
    let default = tenant_cap::configured_default();

    let (role, cap) = tenant_cap::effective_cap_for_admin(&conn, 2).unwrap();
    assert_eq!(role, "member");
    assert_eq!(cap, default, "no bonus → the global default");

    conn.execute("UPDATE admins SET tenant_cap_bonus = 2 WHERE id = 2", [])
        .unwrap();
    let (_, cap) = tenant_cap::effective_cap_for_admin(&conn, 2).unwrap();
    assert_eq!(cap, default + 2, "a positive bonus raises the ceiling");

    conn.execute("UPDATE admins SET tenant_cap_bonus = -1 WHERE id = 2", [])
        .unwrap();
    let (_, cap) = tenant_cap::effective_cap_for_admin(&conn, 2).unwrap();
    assert_eq!(cap, default - 1, "a negative bonus restricts");
}

/// Drive the real write path. `make_tenant_inner` is `pub(crate)`-ish in module
/// terms but reachable via the public `mgmt::tenants::crud` re-export used by
/// the handlers; if it is not public, make it `pub` — it is already the shared
/// seam both entry points call.
fn create(
    conn: &mut rusqlite::Connection,
    dir: &std::path::Path,
    id: &str,
    admin_id: i64,
    role: &str,
) -> anyhow::Result<()> {
    drust::mgmt::tenants::crud::make_tenant_inner(
        conn,
        dir,
        id,
        "Display Name",
        500,
        1_000_000,
        Some(admin_id),
        role,
    )
    .map(|_| ())
}

#[test]
fn member_is_refused_at_the_cap_and_nothing_is_written() {
    let (mut conn, dir) = setup();
    let cap = tenant_cap::configured_default();

    for i in 0..cap {
        create(&mut conn, dir.path(), &format!("t{i}"), 2, "member")
            .unwrap_or_else(|e| panic!("create {i} within the cap must succeed: {e}"));
    }

    let err = create(&mut conn, dir.path(), "overflow", 2, "member")
        .expect_err("the create that crosses the cap must be refused");
    assert!(
        err.to_string().contains("TENANT_CAP_EXCEEDED"),
        "expected the sentinel error code, got: {err}"
    );

    // The refusal must be clean: no row, no directory, no tokens.
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE id = 'overflow'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "a refused create must leave no tenant row");
    assert!(
        !dir.path().join("tenants").join("overflow").exists(),
        "a refused create must leave no on-disk directory"
    );
    let toks: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tokens WHERE tenant_id = 'overflow'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(toks, 0, "a refused create must mint no tokens");
}

#[test]
fn deleting_a_tenant_frees_a_slot() {
    let (mut conn, dir) = setup();
    let cap = tenant_cap::configured_default();
    for i in 0..cap {
        create(&mut conn, dir.path(), &format!("t{i}"), 2, "member").unwrap();
    }
    assert!(create(&mut conn, dir.path(), "extra", 2, "member").is_err());

    conn.execute(
        "UPDATE tenants SET deleted_at = datetime('now') WHERE id = 't0'",
        [],
    )
    .unwrap();
    create(&mut conn, dir.path(), "extra", 2, "member")
        .expect("a freed slot must allow a new create");
}

#[test]
fn transferring_ownership_away_frees_a_slot() {
    let (mut conn, dir) = setup();
    let cap = tenant_cap::configured_default();
    for i in 0..cap {
        create(&mut conn, dir.path(), &format!("t{i}"), 2, "member").unwrap();
    }
    conn.execute("UPDATE tenants SET owner_admin_id = 1 WHERE id = 't0'", [])
        .unwrap();
    create(&mut conn, dir.path(), "extra", 2, "member")
        .expect("ownership transfer frees the old owner's slot");
}

#[test]
fn owner_and_admin_are_never_capped() {
    let (mut conn, dir) = setup();
    let over = tenant_cap::configured_default() + 3;
    for i in 0..over {
        create(&mut conn, dir.path(), &format!("o{i}"), 1, "owner").expect("owner is never capped");
    }
    conn.execute("UPDATE admins SET role = 'admin' WHERE id = 2", [])
        .unwrap();
    for i in 0..over {
        create(&mut conn, dir.path(), &format!("a{i}"), 2, "admin").expect("admin is never capped");
    }
}

#[test]
fn a_positive_bonus_raises_the_ceiling() {
    let (mut conn, dir) = setup();
    let cap = tenant_cap::configured_default();
    conn.execute("UPDATE admins SET tenant_cap_bonus = 1 WHERE id = 2", [])
        .unwrap();
    for i in 0..=cap {
        create(&mut conn, dir.path(), &format!("t{i}"), 2, "member")
            .unwrap_or_else(|e| panic!("create {i} must fit under cap+1: {e}"));
    }
    assert!(
        create(&mut conn, dir.path(), "overflow", 2, "member").is_err(),
        "cap+1 is still a cap"
    );
}

/// An over-cap member (cap lowered underneath them) keeps every existing tenant
/// — only new creation is refused. Nothing is ever auto-deleted.
#[test]
fn over_cap_member_keeps_existing_tenants() {
    let (mut conn, dir) = setup();
    let cap = tenant_cap::configured_default();
    for i in 0..cap {
        create(&mut conn, dir.path(), &format!("t{i}"), 2, "member").unwrap();
    }
    conn.execute("UPDATE admins SET tenant_cap_bonus = -2 WHERE id = 2", [])
        .unwrap();

    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE owner_admin_id = 2 AND deleted_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(live, cap, "lowering the cap must not delete anything");
    assert!(create(&mut conn, dir.path(), "nope", 2, "member").is_err());
}
