//! Per-tenant unified quota (v1.50, Spec B).
//!
//! Every tenant has a single hard cap of `quota_tier × 10 GiB` shared across its
//! `data.sqlite` bytes AND its `_system_files` byte total. Usage is measured
//! *in the writer transaction* off the tenant's own `data.sqlite` connection so
//! the check serializes with the write it guards (single-writer invariant, no
//! TOCTOU) and never has to reconcile two databases. The prior row-count /
//! file-size helpers were dead code (zero call sites) and have been removed in
//! favor of this tenant-level core.

use rusqlite::Connection;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

/// Bytes granted per quota tier. Limit = `quota_tier × QUOTA_TIER_BYTES`.
pub const QUOTA_TIER_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum QuotaError {
    #[error("tenant quota exceeded: usage {usage}B + incoming {incoming}B > limit {limit}B")]
    TenantQuotaExceeded {
        usage: u64,
        incoming: u64,
        limit: u64,
    },
}

/// Current tenant footprint in bytes = `data.sqlite` size + `_system_files` total.
///
/// - db: `PRAGMA page_count × page_size` on this connection — O(1), includes
///   freelist (a conservative over-estimate, never under-counts live data).
/// - files: `SUM(size_bytes)` over `_system_files`; a missing table (tenant has
///   never uploaded) contributes 0 rather than erroring.
///
/// Call with the SAME writer connection the guarded write uses.
pub fn usage_on_conn(c: &Connection) -> Result<u64, rusqlite::Error> {
    let db: u64 = c.query_row(
        "SELECT (SELECT * FROM pragma_page_count()) * (SELECT * FROM pragma_page_size())",
        [],
        |r| r.get::<_, i64>(0).map(|v| v.max(0) as u64),
    )?;
    let files: u64 = match c.query_row(
        "SELECT COALESCE(SUM(size_bytes),0) FROM \"_system_files\"",
        [],
        |r| r.get::<_, i64>(0),
    ) {
        Ok(v) => v.max(0) as u64,
        Err(rusqlite::Error::SqliteFailure(_, Some(ref m))) if m.contains("no such table") => 0,
        Err(e) => return Err(e),
    };
    Ok(db + files)
}

/// Hard-cap check. `incoming` is the estimated bytes about to be written
/// (upload = Content-Length; a plain DB write passes 0 → "reject the next
/// growth once already at the cap"). `tier <= 0` clamps to 1 so the limit is
/// never zero or negative. Additions saturate rather than wrap.
pub fn check_tenant_quota(usage: u64, incoming: u64, tier: i64) -> Result<(), QuotaError> {
    let tier = tier.max(1) as u64;
    let limit = tier.saturating_mul(QUOTA_TIER_BYTES);
    if usage.saturating_add(incoming) > limit {
        return Err(QuotaError::TenantQuotaExceeded {
            usage,
            incoming,
            limit,
        });
    }
    Ok(())
}

/// Read a tenant's `quota_tier` from meta.sqlite for the low-frequency
/// enforcement points (MCP write / edge enforce / write-RPC / tus finalize)
/// that don't ride the bearer CTE. Missing tenant, soft-deleted tenant, or any
/// query error → fail-safe to tier 1 (the default cap), never a wide-open tier.
pub async fn read_tier(meta: &Arc<Mutex<Connection>>, tenant_id: &str) -> i64 {
    let conn = meta.lock().await;
    conn.query_row(
        "SELECT COALESCE(quota_tier, 1) FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tenant_id],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn quota_tier_bytes_is_ten_gib() {
        assert_eq!(QUOTA_TIER_BYTES, 10 * GIB);
    }

    #[test]
    fn exactly_at_limit_allowed() {
        // tier 1 → 10 GiB. usage == limit with incoming 0 is allowed: the hard
        // cap rejects the NEXT growth, not the state that exactly reaches it.
        assert!(check_tenant_quota(QUOTA_TIER_BYTES, 0, 1).is_ok());
    }

    #[test]
    fn one_byte_over_rejected() {
        let over = QUOTA_TIER_BYTES + 1;
        let err = check_tenant_quota(over, 0, 1).unwrap_err();
        let QuotaError::TenantQuotaExceeded {
            usage,
            incoming,
            limit,
        } = err;
        assert_eq!(usage, over);
        assert_eq!(incoming, 0);
        assert_eq!(limit, QUOTA_TIER_BYTES);
    }

    #[test]
    fn incoming_stacks_onto_usage() {
        let usage = QUOTA_TIER_BYTES - 100;
        assert!(check_tenant_quota(usage, 100, 1).is_ok()); // == limit
        assert!(check_tenant_quota(usage, 101, 1).is_err()); // over by 1
    }

    #[test]
    fn tier_two_doubles_limit() {
        assert!(check_tenant_quota(QUOTA_TIER_BYTES + 1, 0, 2).is_ok()); // fits in 20 GiB
        assert!(check_tenant_quota(2 * QUOTA_TIER_BYTES + 1, 0, 2).is_err());
    }

    #[test]
    fn tier_zero_or_negative_treated_as_one() {
        // tier <= 0 clamps to 1 (never a 0-byte / negative limit).
        assert!(check_tenant_quota(QUOTA_TIER_BYTES, 0, 0).is_ok());
        assert!(check_tenant_quota(QUOTA_TIER_BYTES + 1, 0, 0).is_err());
        assert!(check_tenant_quota(QUOTA_TIER_BYTES, 0, -5).is_ok());
        assert!(check_tenant_quota(QUOTA_TIER_BYTES + 1, 0, -5).is_err());
    }

    #[test]
    fn saturating_add_no_overflow() {
        // usage + incoming must not wrap; u64::MAX stays over-limit.
        assert!(check_tenant_quota(u64::MAX, u64::MAX, 1).is_err());
    }

    #[test]
    fn usage_on_conn_counts_db_plus_files() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE \"_system_files\" (key TEXT, size_bytes INTEGER);
             INSERT INTO \"_system_files\" (key, size_bytes) VALUES ('a', 1000), ('b', 2000);",
        )
        .unwrap();
        let usage = usage_on_conn(&c).unwrap();
        // db bytes (page_count * page_size) are non-zero and files sum = 3000.
        assert!(usage >= 3000, "expected >= 3000, got {usage}");
    }

    #[test]
    fn usage_on_conn_no_files_table_is_db_only() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE t (id INTEGER)").unwrap();
        // No _system_files table → files contributes 0, not an error.
        let usage = usage_on_conn(&c).unwrap();
        assert!(usage > 0); // at least the db page bytes
    }

    #[tokio::test]
    async fn read_tier_returns_stored_value() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, deleted_at TEXT, quota_tier INTEGER NOT NULL DEFAULT 1);
             INSERT INTO tenants (id, quota_tier) VALUES ('t1', 3);",
        )
        .unwrap();
        let meta = std::sync::Arc::new(tokio::sync::Mutex::new(c));
        assert_eq!(read_tier(&meta, "t1").await, 3);
    }

    #[tokio::test]
    async fn read_tier_missing_tenant_defaults_to_one() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, deleted_at TEXT, quota_tier INTEGER NOT NULL DEFAULT 1);",
        )
        .unwrap();
        let meta = std::sync::Arc::new(tokio::sync::Mutex::new(c));
        assert_eq!(read_tier(&meta, "ghost").await, 1);
    }

    #[tokio::test]
    async fn read_tier_query_error_defaults_to_one() {
        // No tenants table at all → query errors → fail-safe to 1.
        let c = Connection::open_in_memory().unwrap();
        let meta = std::sync::Arc::new(tokio::sync::Mutex::new(c));
        assert_eq!(read_tier(&meta, "t1").await, 1);
    }

    #[tokio::test]
    async fn read_tier_excludes_soft_deleted() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, deleted_at TEXT, quota_tier INTEGER NOT NULL DEFAULT 1);
             INSERT INTO tenants (id, deleted_at, quota_tier) VALUES ('t1', '2026-01-01', 5);",
        )
        .unwrap();
        let meta = std::sync::Arc::new(tokio::sync::Mutex::new(c));
        // soft-deleted row is filtered by `deleted_at IS NULL` → default 1.
        assert_eq!(read_tier(&meta, "t1").await, 1);
    }
}
