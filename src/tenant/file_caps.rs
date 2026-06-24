//! Per-tenant file-storage capabilities (v1.42).
//!
//! A tenant may grant `anon` and `user` bearers an opt-in subset of
//! `{read, list, upload, delete}` over its file storage — a Supabase-style
//! cap-gated **shared** pool (access is decided by caps, NOT per-file
//! ownership). Service is unrestricted. make-public (set-visibility) is
//! deliberately NOT a verb here; it stays service-only.
//!
//! Caps are stored as JSON on the `tenants` row (`file_anon_caps_json` /
//! `file_user_caps_json`), loaded in `SQL_BEARER_AUTH_CTE`, and attached to
//! every request as a [`TenantFileCaps`] extension (cached in `CachedAuth`,
//! invalidated by `set_file_caps` via `auth_cache.clear_tenant`). Each file
//! handler gates its own verb inline via [`check_file_cap`].

use std::collections::BTreeSet;

use crate::storage::schema::{FileVerb, parse_file_caps_json};
use crate::tenant::router::TokenRole;

/// The effective file-cap sets for a tenant, attached to each request.
/// `Default` (both empty) = all-off = service-only, the behaviour every
/// tenant has until it opts in.
#[derive(Debug, Clone, Default)]
pub struct TenantFileCaps {
    pub anon: BTreeSet<FileVerb>,
    pub user: BTreeSet<FileVerb>,
}

impl TenantFileCaps {
    /// Build from the two JSON columns (already COALESCE'd to `'[]'` by the
    /// CTE). Unreadable JSON fails closed to an empty set.
    pub fn from_json(anon_json: &str, user_json: &str) -> Self {
        Self {
            anon: parse_file_caps_json(anon_json),
            user: parse_file_caps_json(user_json),
        }
    }
}

/// Outcome of a cap check. Three variants so the REST layer can emit a
/// role-specific deny code (mirrors `PublishGate`).
pub enum FileCapGate {
    Allow,
    DenyAnon,
    DenyUser,
}

/// Gate one file operation. **Service is always allowed** (unrestricted by
/// design — must short-circuit before consulting any cap). Anon/User are
/// allowed iff their own cap set contains `verb`. The anon and user sets are
/// independent — granting one never opens the other.
pub fn check_file_cap(role: TokenRole, caps: &TenantFileCaps, verb: FileVerb) -> FileCapGate {
    match role {
        TokenRole::Service => FileCapGate::Allow,
        TokenRole::Anon => {
            if caps.anon.contains(&verb) {
                FileCapGate::Allow
            } else {
                FileCapGate::DenyAnon
            }
        }
        TokenRole::User => {
            if caps.user.contains(&verb) {
                FileCapGate::Allow
            } else {
                FileCapGate::DenyUser
            }
        }
    }
}

/// Map a gate outcome to a typed REST error, or `None` when allowed. The
/// per-verb code aliases the legacy `WRITE_DENIED` so old clients still catch
/// it. A denied handler does `if let Some(r) = file_cap_denied_response(..) { return r; }`.
pub fn file_cap_denied_response(
    gate: FileCapGate,
    verb: FileVerb,
) -> Option<axum::response::Response> {
    if matches!(gate, FileCapGate::Allow) {
        return None;
    }
    let code = match verb {
        FileVerb::Read => "FILE_READ_DENIED",
        FileVerb::List => "FILE_LIST_DENIED",
        FileVerb::Upload => "FILE_UPLOAD_DENIED",
        FileVerb::Delete => "FILE_DELETE_DENIED",
    };
    Some(crate::error::json_error_with_aliases(
        axum::http::StatusCode::FORBIDDEN,
        code,
        &["WRITE_DENIED"],
        &format!("bearer lacks file.{} capability", verb.as_str()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_matrix() {
        let mut caps = TenantFileCaps::default();
        caps.anon.insert(FileVerb::Read);
        caps.user.insert(FileVerb::Upload);

        // service: always allow, even for an ungranted verb
        assert!(matches!(
            check_file_cap(TokenRole::Service, &caps, FileVerb::Delete),
            FileCapGate::Allow
        ));
        // anon: only its granted verb
        assert!(matches!(
            check_file_cap(TokenRole::Anon, &caps, FileVerb::Read),
            FileCapGate::Allow
        ));
        assert!(matches!(
            check_file_cap(TokenRole::Anon, &caps, FileVerb::Upload),
            FileCapGate::DenyAnon
        ));
        // user: only its granted verb, independent of the anon set
        assert!(matches!(
            check_file_cap(TokenRole::User, &caps, FileVerb::Upload),
            FileCapGate::Allow
        ));
        assert!(matches!(
            check_file_cap(TokenRole::User, &caps, FileVerb::Read),
            FileCapGate::DenyUser
        ));
    }

    #[test]
    fn denied_response_maps_codes_and_none_on_allow() {
        assert!(file_cap_denied_response(FileCapGate::Allow, FileVerb::Read).is_none());
        let r = file_cap_denied_response(FileCapGate::DenyAnon, FileVerb::Upload).unwrap();
        assert_eq!(r.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn from_json_fails_closed() {
        let c = TenantFileCaps::from_json(r#"["read","list"]"#, "[]");
        assert!(c.anon.contains(&FileVerb::Read) && c.anon.contains(&FileVerb::List));
        assert!(c.user.is_empty());
        // bad JSON -> empty, never panics
        assert!(TenantFileCaps::from_json("nope", "nope").anon.is_empty());
    }
}
