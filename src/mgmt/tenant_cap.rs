//! v1.57 — per-member tenant creation cap.
//!
//! A `member` may own at most `effective_cap` live tenants at once. The
//! per-admin adjustment stored in `admins.tenant_cap_bonus` is a DELTA against
//! the global default, never an absolute ceiling: storing an absolute would mean
//! that raising `DRUST_MEMBER_TENANT_CAP` left previously-adjusted admins
//! behind. See docs/superpowers/specs/2026-07-30-member-tenant-cap-design.md.

/// Global fallback when `DRUST_MEMBER_TENANT_CAP` is unset or unparseable.
pub const DEFAULT_MEMBER_TENANT_CAP: i64 = 3;

/// Defensive upper bound on a requestable/settable cap.
pub const MAX_CAP: i64 = 100;

/// Global default cap, from `DRUST_MEMBER_TENANT_CAP`. Same `env_or` posture as
/// `DRUST_CRON_MAX_JOBS_PER_TENANT` (`src/cron/mod.rs`): unparseable → default.
pub fn configured_default() -> i64 {
    std::env::var("DRUST_MEMBER_TENANT_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMBER_TENANT_CAP)
}

/// Effective cap for an admin: the global default shifted by their stored delta,
/// clamped at zero.
pub fn effective_cap(default: i64, bonus: i64) -> i64 {
    (default + bonus).max(0)
}

/// The delta to STORE so that this admin's effective cap becomes `target_cap`
/// under the current `default`. The API speaks absolute numbers (that is what a
/// person means); storage holds the delta.
pub fn bonus_for_target(default: i64, target_cap: i64) -> i64 {
    target_cap - default
}

/// May this admin create one more tenant?
///
/// Only `member` is capped — `owner`/`admin` already see every tenant, so
/// creating one is a management act for them. Any OTHER role string fails
/// closed (capped), so a future role cannot silently gain unlimited creation by
/// not being listed here.
pub fn may_create_tenant(role: &str, owned: i64, effective_cap: i64) -> bool {
    if matches!(role, "owner" | "admin") {
        return true;
    }
    owned < effective_cap
}

/// Live tenants currently owned by `admin_id`. Soft-deleted rows do NOT count,
/// so deleting a tenant — or transferring its ownership away — frees a slot.
/// Same "current usage" semantics as the storage quota.
pub fn owned_tenant_count(conn: &rusqlite::Connection, admin_id: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM tenants WHERE owner_admin_id = ?1 AND deleted_at IS NULL",
        rusqlite::params![admin_id],
        |r| r.get(0),
    )
}

/// `(role, effective_cap)` for one admin. A missing admin row yields
/// `("member", …)` so an unknown caller is treated as the most restricted role
/// rather than silently uncapped.
pub fn effective_cap_for_admin(
    conn: &rusqlite::Connection,
    admin_id: i64,
) -> rusqlite::Result<(String, i64)> {
    let (role, bonus): (String, i64) = conn
        .query_row(
            "SELECT role, tenant_cap_bonus FROM admins WHERE id = ?1",
            rusqlite::params![admin_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or_else(|_| ("member".to_string(), 0));
    Ok((role, effective_cap(configured_default(), bonus)))
}

#[cfg(test)]
mod cap_arithmetic_tests {
    use super::*;

    #[test]
    fn effective_cap_applies_bonus_as_a_delta() {
        assert_eq!(effective_cap(3, 0), 3, "no adjustment → the default");
        assert_eq!(effective_cap(3, 2), 5, "positive bonus raises");
        assert_eq!(effective_cap(3, -1), 2, "negative bonus restricts");
    }

    /// The whole point of the delta model: a global-default change lifts
    /// everyone, including admins who already carry an adjustment. An
    /// absolute-storage implementation fails this test.
    #[test]
    fn raising_the_default_lifts_an_adjusted_admin() {
        let bonus = bonus_for_target(3, 4); // approved to 4 while default was 3
        assert_eq!(bonus, 1);
        assert_eq!(effective_cap(3, bonus), 4, "still 4 under the old default");
        assert_eq!(
            effective_cap(10, bonus),
            11,
            "default 3→10 lifts them to 11"
        );
    }

    #[test]
    fn effective_cap_never_goes_negative() {
        assert_eq!(effective_cap(3, -5), 0, "clamped at zero, never negative");
        assert_eq!(effective_cap(0, -1), 0);
    }

    #[test]
    fn bonus_for_target_round_trips() {
        for (default, target) in [(3, 4), (3, 10), (10, 11), (5, 2)] {
            let bonus = bonus_for_target(default, target);
            assert_eq!(
                effective_cap(default, bonus),
                target,
                "default {default} target {target}"
            );
        }
    }

    #[test]
    fn only_member_is_capped() {
        // At the cap.
        assert!(!may_create_tenant("member", 3, 3), "member at cap refused");
        assert!(may_create_tenant("owner", 999, 3), "owner never capped");
        assert!(may_create_tenant("admin", 999, 3), "admin never capped");
    }

    #[test]
    fn member_below_cap_may_create() {
        assert!(may_create_tenant("member", 0, 3));
        assert!(may_create_tenant("member", 2, 3));
    }

    /// Over-cap is reachable by lowering someone's cap or demoting an owner who
    /// owns many tenants. Creation must still refuse — and nothing is deleted.
    #[test]
    fn member_over_cap_still_refused() {
        assert!(!may_create_tenant("member", 18, 3));
    }

    /// A zero effective cap (bonus dragged it to 0) means no creation at all.
    #[test]
    fn zero_cap_refuses_everything() {
        assert!(!may_create_tenant("member", 0, 0));
    }

    /// An unknown role string must fail CLOSED (treated as capped), so a future
    /// role added without updating this function cannot silently gain unlimited
    /// tenant creation.
    #[test]
    fn unknown_role_fails_closed() {
        assert!(!may_create_tenant("editor", 3, 3));
        assert!(
            may_create_tenant("editor", 0, 3),
            "still bounded by the cap"
        );
    }
}
