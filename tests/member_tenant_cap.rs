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
fn lookup_admin_cap_reads_role_and_bonus() {
    let (conn, _dir) = setup();
    let default = tenant_cap::configured_default();

    let (role, cap) = tenant_cap::lookup_admin_cap(&conn, 2).unwrap().unwrap();
    assert_eq!(role, "member");
    assert_eq!(cap, default, "no bonus → the global default");

    conn.execute("UPDATE admins SET tenant_cap_bonus = 2 WHERE id = 2", [])
        .unwrap();
    let (_, cap) = tenant_cap::lookup_admin_cap(&conn, 2).unwrap().unwrap();
    assert_eq!(cap, default + 2, "a positive bonus raises the ceiling");

    conn.execute("UPDATE admins SET tenant_cap_bonus = -1 WHERE id = 2", [])
        .unwrap();
    let (_, cap) = tenant_cap::lookup_admin_cap(&conn, 2).unwrap().unwrap();
    assert_eq!(cap, default - 1, "a negative bonus restricts");
}

/// A missing admin row is `Ok(None)`, distinct from `Err` — the two must not be
/// collapsed into a permissive fallback (2026-07-30 adversarial review,
/// findings 1 and 7: the first version returned `("member", global_default)` for
/// both, which let the approve path treat a deleted requester as a live admin
/// and handed a restricted admin the full default on any transient read error).
#[test]
fn lookup_admin_cap_returns_none_for_a_missing_admin() {
    let (conn, _dir) = setup();
    assert!(
        tenant_cap::lookup_admin_cap(&conn, 9999).unwrap().is_none(),
        "a nonexistent admin must be None, not a default-capped member"
    );
}

/// Drive the real write path. The gate reads the role from the DB itself, so
/// there is no role argument to get wrong (2026-07-30 adversarial review,
/// finding 2 — the earlier `creator_role: &str` parameter could be lied to).
fn create(
    conn: &mut rusqlite::Connection,
    dir: &std::path::Path,
    id: &str,
    admin_id: i64,
) -> anyhow::Result<()> {
    drust::mgmt::tenants::crud::make_tenant_inner(
        conn,
        dir,
        id,
        "Display Name",
        500,
        1_000_000,
        admin_id,
    )
    .map(|_| ())
}

#[test]
fn member_is_refused_at_the_cap_and_nothing_is_written() {
    let (mut conn, dir) = setup();
    let cap = tenant_cap::configured_default();

    for i in 0..cap {
        create(&mut conn, dir.path(), &format!("t{i}"), 2)
            .unwrap_or_else(|e| panic!("create {i} within the cap must succeed: {e}"));
    }

    let err = create(&mut conn, dir.path(), "overflow", 2)
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
        create(&mut conn, dir.path(), &format!("t{i}"), 2).unwrap();
    }
    assert!(create(&mut conn, dir.path(), "extra", 2).is_err());

    conn.execute(
        "UPDATE tenants SET deleted_at = datetime('now') WHERE id = 't0'",
        [],
    )
    .unwrap();
    create(&mut conn, dir.path(), "extra", 2).expect("a freed slot must allow a new create");
}

#[test]
fn transferring_ownership_away_frees_a_slot() {
    let (mut conn, dir) = setup();
    let cap = tenant_cap::configured_default();
    for i in 0..cap {
        create(&mut conn, dir.path(), &format!("t{i}"), 2).unwrap();
    }
    conn.execute("UPDATE tenants SET owner_admin_id = 1 WHERE id = 't0'", [])
        .unwrap();
    create(&mut conn, dir.path(), "extra", 2)
        .expect("ownership transfer frees the old owner's slot");
}

#[test]
fn owner_and_admin_are_never_capped() {
    let (mut conn, dir) = setup();
    let over = tenant_cap::configured_default() + 3;
    for i in 0..over {
        create(&mut conn, dir.path(), &format!("o{i}"), 1).expect("owner is never capped");
    }
    conn.execute("UPDATE admins SET role = 'admin' WHERE id = 2", [])
        .unwrap();
    for i in 0..over {
        create(&mut conn, dir.path(), &format!("a{i}"), 2).expect("admin is never capped");
    }
}

#[test]
fn a_positive_bonus_raises_the_ceiling() {
    let (mut conn, dir) = setup();
    let cap = tenant_cap::configured_default();
    conn.execute("UPDATE admins SET tenant_cap_bonus = 1 WHERE id = 2", [])
        .unwrap();
    for i in 0..=cap {
        create(&mut conn, dir.path(), &format!("t{i}"), 2)
            .unwrap_or_else(|e| panic!("create {i} must fit under cap+1: {e}"));
    }
    assert!(
        create(&mut conn, dir.path(), "overflow", 2).is_err(),
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
        create(&mut conn, dir.path(), &format!("t{i}"), 2).unwrap();
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
    assert!(create(&mut conn, dir.path(), "nope", 2).is_err());
}

/// The gate reads the role from the DB, so a caller cannot claim to be an owner.
/// This is the regression test for 2026-07-30 adversarial review finding 2: the
/// first implementation took a `creator_role: &str` argument and discarded the
/// role it had just read from `admins`, which meant a new caller passing
/// `"owner"` for a member's id got unlimited creation. There is no such
/// argument any more — this test pins that the DB is the only source of truth.
#[test]
fn the_gate_reads_the_role_from_the_database_not_the_caller() {
    let (mut conn, dir) = setup();
    let cap = tenant_cap::configured_default();
    for i in 0..cap {
        create(&mut conn, dir.path(), &format!("t{i}"), 2).unwrap();
    }
    // admin id 2 is a `member` in the DB. There is no way for this call to
    // assert otherwise, so it must be refused.
    assert!(
        create(&mut conn, dir.path(), "claims-owner", 2).is_err(),
        "a member must be capped regardless of what any caller believes"
    );

    // Promote them in the DB and the same call now succeeds — proving the gate
    // tracks the stored role rather than a parameter.
    conn.execute("UPDATE admins SET role = 'owner' WHERE id = 2", [])
        .unwrap();
    create(&mut conn, dir.path(), "now-owner", 2)
        .expect("a genuine owner (per the DB) is uncapped");
}

/// Two concurrent creates by a member at `cap - 1` must yield exactly one
/// success, with no overshoot, and the loser must fail on the CAP specifically
/// (2026-07-30 adversarial review, finding 5a; the spec named this test).
///
/// Scope, stated honestly: this holds the shared mutex across the whole
/// `make_tenant_inner` call, exactly as both real handlers do, and proves the
/// cap arithmetic is exact under contention. It does NOT by itself prove the
/// count is read *inside* that critical section — a version that read the count
/// before taking the lock would still pass here. That placement property is
/// established by code structure (the gate is the first statement inside the
/// function both handlers call while holding the lock) and by review, not by
/// this test; verifying it dynamically would need a pause hook in production
/// code, which is not worth the seam.
#[tokio::test]
async fn two_concurrent_creates_at_the_boundary_yield_exactly_one_success() {
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let dir = tempfile::tempdir().unwrap();
    let mut conn = drust::storage::meta::open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) VALUES (2, 'mem', 'h', 'member')",
        [],
    )
    .unwrap();
    // Fill to cap - 1 so exactly one slot remains.
    let cap = tenant_cap::configured_default();
    for i in 0..(cap - 1) {
        create(&mut conn, dir.path(), &format!("pre{i}"), 2)
            .unwrap_or_else(|e| panic!("seed {i}: {e}"));
    }

    // Share one connection behind a mutex — the same shape as
    // `TenantsState.session.meta`, which is what serialises the real handlers.
    let shared = Arc::new(Mutex::new(conn));
    let root = dir.path().to_path_buf();

    let mut handles = Vec::new();
    for n in 0..2 {
        let shared = Arc::clone(&shared);
        let root = root.clone();
        handles.push(tokio::spawn(async move {
            let mut guard = shared.lock().await;
            drust::mgmt::tenants::crud::make_tenant_inner(
                &mut guard,
                &root,
                &format!("race{n}"),
                "N",
                500,
                1_000_000,
                2,
            )
            .map(|_| ())
        }));
    }
    let mut ok = 0;
    let mut refused = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(()) => ok += 1,
            Err(e) => {
                assert!(
                    e.to_string().contains("TENANT_CAP_EXCEEDED"),
                    "the loser must lose on the cap, not something else: {e}"
                );
                refused += 1;
            }
        }
    }
    assert_eq!(ok, 1, "exactly one create may win the last slot");
    assert_eq!(refused, 1, "the other must be refused by the cap");

    let live: i64 = shared
        .lock()
        .await
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE owner_admin_id = 2 AND deleted_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(live, cap, "the cap must hold exactly, with no overshoot");
}
