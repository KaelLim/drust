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

/// What gate a data-plane file route requires. `ServiceOnly` covers the
/// operations that are NOT cap-grantable (presigned URLs, make-public/
/// set-visibility, tus session listing + capability discovery) — anon/user are
/// always refused there regardless of caps.
#[derive(Debug, PartialEq, Eq)]
pub enum FileRouteGate {
    Capped(FileVerb),
    ServiceOnly,
}

/// Classify a files_router request to its required gate from `(method, path)`.
/// Driven off route shape, not a fragile single-string match — covered by a
/// unit matrix below. `{tenant}`/`{key}`/`{token}` are uuid/uuid.ext shaped and
/// never equal the literal markers `files`/`uploads`.
pub fn classify_file_route(method: &axum::http::Method, path: &str) -> FileRouteGate {
    use FileVerb::*;
    use axum::http::Method;
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // --- Mode A: .../files[/{key}[/bytes|/sign]] ---
    if let Some(i) = segs.iter().position(|&s| s == "files") {
        let tail = &segs[i + 1..];
        return match (tail.len(), tail.last().copied(), method) {
            (0, _, &Method::POST) => FileRouteGate::Capped(Upload), // upload
            (0, _, &Method::GET) => FileRouteGate::Capped(List),    // list
            (1, _, &Method::GET) => FileRouteGate::Capped(Read),    // get_one
            (1, _, &Method::DELETE) => FileRouteGate::Capped(Delete), // delete_one
            (1, _, &Method::PATCH) => FileRouteGate::ServiceOnly,   // set-visibility
            (2, Some("bytes"), &Method::GET) => FileRouteGate::Capped(Read), // stream_bytes
            (2, Some("sign"), &Method::POST) => FileRouteGate::ServiceOnly,  // sign_url
            _ => FileRouteGate::ServiceOnly,
        };
    }

    // --- Mode B (tus): .../uploads[/{token}] ---
    if let Some(i) = segs.iter().position(|&s| s == "uploads") {
        let tail = &segs[i + 1..];
        return match (tail.len(), method) {
            (0, &Method::POST) => FileRouteGate::Capped(Upload), // create
            (0, _) => FileRouteGate::ServiceOnly,                // list_sessions (GET) / options (OPTIONS)
            (1, &Method::PATCH) | (1, &Method::HEAD) => FileRouteGate::Capped(Upload), // append / probe
            (1, &Method::DELETE) => FileRouteGate::Capped(Delete), // terminate
            _ => FileRouteGate::ServiceOnly,
        };
    }

    FileRouteGate::ServiceOnly // unknown shape — fail closed
}

/// Data-plane files_router gate (v1.42). Replaces `require_service_layer`:
/// service passes through unrestricted; anon/user are gated per-verb against the
/// tenant's `TenantFileCaps` (attached by `bearer_auth_layer`). Mounted INNER to
/// `bearer_auth_layer`, so `TenantRef` is present — absence is fail-closed 403.
pub async fn file_caps_layer(
    axum::extract::State(auth): axum::extract::State<crate::tenant::router::TenantAuthState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use crate::tenant::router::{TenantRef, TokenRole};
    let role = match req.extensions().get::<TenantRef>() {
        Some(t) => t.role,
        None => {
            return crate::error::json_error(
                axum::http::StatusCode::FORBIDDEN,
                "WRITE_DENIED",
                "service key or file capability required",
            );
        }
    };
    // Service is unrestricted by design.
    if role == TokenRole::Service {
        return next.run(req).await;
    }
    match classify_file_route(req.method(), req.uri().path()) {
        FileRouteGate::ServiceOnly => crate::error::json_error_with_aliases(
            axum::http::StatusCode::FORBIDDEN,
            "WRITE_DENIED",
            &["SERVICE_REQUIRED"],
            "this file operation requires a service key",
        ),
        FileRouteGate::Capped(verb) => {
            let caps = req
                .extensions()
                .get::<TenantFileCaps>()
                .cloned()
                .unwrap_or_default();
            if let Some(resp) = file_cap_denied_response(check_file_cap(role, &caps, verb), verb) {
                return resp;
            }
            // v1.42 — per-IP rate-limit upload/delete for non-service callers
            // (cap already satisfied). Bounds the public anon-key DoS vector;
            // service never reaches here (returned above). IP via XFF, loopback
            // fallback (prod is always behind the nginx->Caddy chain).
            let limiter = match verb {
                FileVerb::Upload => Some(&auth.file_upload_rl),
                FileVerb::Delete => Some(&auth.file_delete_rl),
                _ => None,
            };
            if let Some(rl) = limiter {
                let ip = crate::safety::ip::client_ip(
                    req.headers(),
                    std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                );
                if !rl.check(ip) {
                    return crate::error::json_error(
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        "RATE_LIMITED_IP",
                        "file upload/delete rate limit exceeded; retry shortly",
                    );
                }
            }
            next.run(req).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_classification_matrix() {
        use FileRouteGate::*;
        use FileVerb::*;
        use axum::http::Method;
        let g = |m: Method, p: &str| classify_file_route(&m, p);
        // Mode A
        assert_eq!(g(Method::POST, "/t/x/files"), Capped(Upload));
        assert_eq!(g(Method::GET, "/t/x/files"), Capped(List));
        assert_eq!(g(Method::GET, "/t/x/files/abc.png"), Capped(Read));
        assert_eq!(g(Method::DELETE, "/t/x/files/abc.png"), Capped(Delete));
        assert_eq!(g(Method::PATCH, "/t/x/files/abc.png"), ServiceOnly); // set-visibility
        assert_eq!(g(Method::GET, "/t/x/files/abc.png/bytes"), Capped(Read));
        assert_eq!(g(Method::POST, "/t/x/files/abc.png/sign"), ServiceOnly);
        // Mode B tus
        assert_eq!(g(Method::POST, "/t/x/uploads"), Capped(Upload));
        assert_eq!(g(Method::GET, "/t/x/uploads"), ServiceOnly); // list_sessions
        assert_eq!(g(Method::OPTIONS, "/t/x/uploads"), ServiceOnly);
        assert_eq!(g(Method::PATCH, "/t/x/uploads/tok"), Capped(Upload));
        assert_eq!(g(Method::HEAD, "/t/x/uploads/tok"), Capped(Upload));
        assert_eq!(g(Method::DELETE, "/t/x/uploads/tok"), Capped(Delete));
    }

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
