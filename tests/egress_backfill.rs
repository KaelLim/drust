//! One-time run-once backfill of existing webhook origins into the per-tenant
//! egress allowlist (v1.49, Task 5). The deny-all default would sever live
//! webhook deployments on upgrade, so the FIRST boot seeds each tenant's
//! `_system_webhooks` target origins as `{system:"webhook"}` allowlist entries —
//! exactly once. A per-tenant run-once marker (`tenants.egress_backfill_done`)
//! makes a second boot a pure no-op, so an origin an admin deliberately removed
//! is never resurrected (the v1.41.5 idempotency invariant).

use drust::db::migrations::run_migrations;
use drust::tenant::egress::{parse_allowlist, read_egress_allowlist};
use rusqlite::Connection;
use tempfile::TempDir;

/// The set of `(system, origin)` pairs in a tenant's stored allowlist, sorted
/// for order-independent comparison.
fn allowlist_pairs(meta: &Connection, tid: &str) -> Vec<(String, String)> {
    let json = read_egress_allowlist(meta, tid).unwrap();
    let mut pairs: Vec<(String, String)> = parse_allowlist(&json)
        .into_iter()
        .map(|e| (e.system.as_str().to_string(), e.uri))
        .collect();
    pairs.sort();
    pairs
}

#[test]
fn backfill_seeds_deduped_webhook_origins_once_and_never_resurrects() {
    let dir = TempDir::new().unwrap();
    // Pre-egress meta shape: tenants + admins, one live tenant with an EMPTY
    // allowlist (the migration adds egress_allowlist_json defaulting to '[]').
    let meta = Connection::open(dir.path().join("meta.sqlite")).unwrap();
    meta.execute_batch(
        "CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, deleted_at TEXT);
         INSERT INTO tenants (id, name) VALUES ('t1', 'One');
         CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, \
             password_hash TEXT NOT NULL, email TEXT, \
             created_at TEXT NOT NULL DEFAULT (datetime('now')));",
    )
    .unwrap();

    // Tenant data.sqlite with three webhook rows over TWO distinct origins
    // (a.com appears twice → must dedup to one entry). `_system_collection_meta`
    // is present so migrate_tenant_db's additive column steps succeed.
    let tdir = dir.path().join("tenants").join("t1");
    std::fs::create_dir_all(&tdir).unwrap();
    {
        let c = Connection::open(tdir.join("data.sqlite")).unwrap();
        c.execute_batch(
            "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, \
                 anon_caps_json TEXT, updated_at TEXT);
             CREATE TABLE _system_webhooks (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 collection TEXT NOT NULL, events TEXT NOT NULL,
                 url TEXT NOT NULL, secret TEXT NOT NULL,
                 active INTEGER NOT NULL DEFAULT 1,
                 created_at TEXT NOT NULL DEFAULT (datetime('now')));
             INSERT INTO _system_webhooks (collection, events, url, secret) VALUES
                 ('c', 'record.created', 'https://a.com/hook1', 's1'),
                 ('c', 'record.created', 'https://a.com/hook2', 's2'),
                 ('c', 'record.created', 'https://b.com/x',     's3');",
        )
        .unwrap();
    }

    // First boot: backfill seeds the two deduped origins.
    run_migrations(&meta, dir.path()).unwrap();
    assert_eq!(
        allowlist_pairs(&meta, "t1"),
        vec![
            ("webhook".to_string(), "https://a.com".to_string()),
            ("webhook".to_string(), "https://b.com".to_string()),
        ],
        "backfill seeds exactly the deduped webhook origins"
    );

    // Admin deliberately removes b.com from the allowlist.
    meta.execute(
        "UPDATE tenants SET egress_allowlist_json = ?1 WHERE id = 't1'",
        [r#"[{"system":"webhook","uri":"https://a.com"}]"#],
    )
    .unwrap();

    // Second boot: the run-once marker holds → b.com is NOT resurrected and
    // a.com is left unchanged.
    run_migrations(&meta, dir.path()).unwrap();
    assert_eq!(
        allowlist_pairs(&meta, "t1"),
        vec![("webhook".to_string(), "https://a.com".to_string())],
        "a removed origin must never be resurrected by a second boot"
    );
}
