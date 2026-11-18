//! Upload-ticket redemption on the tus routes.
//!
//! A `drust_upl_` ticket (issued by the account-level MCP endpoint) is a
//! service-equivalent credential for ONE tus upload on ONE tenant. When MCP
//! OAuth is enabled, `upload_ticket_dispatch` sits outside `bearer_auth_layer`
//! on the files router and takes over every request whose bearer has the
//! ticket's shape (`tokens::looks_like`, never a prefix test: a tenant bearer's
//! random body may itself begin with `upl_`). Everything else goes to the
//! bearer stack untouched.
//!
//! A ticket is re-checked against its grant, admin and tenant on every
//! request, may create exactly one tus session, and may touch only the session
//! it is bound to; every other files route answers 401. The request is then
//! rebuilt (fresh extensions, no `Authorization`) and re-routed through
//! `ticket_router`, the unchanged tus handlers behind `file_caps_layer`, which
//! is never merged into the files router.
//!
//! The `meta` lock is taken in short blocks (lookup, claim, bind or release)
//! and never held across the re-route: the tus handlers lock `meta` again
//! through `quota::read_tier`, and the tokio mutex is not reentrant.

use std::collections::HashMap;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{Extensions, HeaderMap, Method, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use tower::ServiceExt;

use crate::auth::bearer;
use crate::auth::middleware::{AdminId, AuthCtx};
use crate::error::json_error;
use crate::mgmt::mcp_oauth::store::{self, TicketAttribution, TicketRow};
use crate::mgmt::mcp_oauth::tokens::{self, TokenKind};
use crate::mgmt::tenant_authz::{AdminTenantAccess, tenant_access_for_admin};
use crate::mgmt::tenant_files::TenantFilesState;
use crate::storage::pool::SharedTenantPool;
use crate::tenant::file_caps::{TenantFileCaps, file_caps_layer};
use crate::tenant::router::{TenantAuthState, TenantRef, TokenRole, extract_bearer};

/// The dispatch layer's state: the two stacks it needs and the ticket router,
/// built once.
#[derive(Clone)]
pub(crate) struct TicketDispatch {
    auth: TenantAuthState,
    files: TenantFilesState,
    router: Router,
}

impl TicketDispatch {
    pub(crate) fn new(auth: TenantAuthState, files: TenantFilesState) -> Self {
        let router = ticket_router(
            auth.clone(),
            files.clone(),
            files.large_upload_chunk_max_bytes,
        );
        Self {
            auth,
            files,
            router,
        }
    }
}

/// The four tus routes a ticket may reach, behind `file_caps_layer`. Never
/// merged into the files router: it is reached only through
/// `upload_ticket_dispatch`, after the ticket checks.
pub(crate) fn ticket_router(
    auth: TenantAuthState,
    files: TenantFilesState,
    chunk_max: usize,
) -> Router {
    Router::new()
        .route("/t/{tenant}/uploads", post(super::create))
        .route(
            "/t/{tenant}/uploads/{token}",
            axum::routing::patch(super::patch)
                .head(super::head)
                .delete(super::terminate)
                .layer(DefaultBodyLimit::max(chunk_max)),
        )
        .layer(from_fn_with_state(auth, file_caps_layer))
        .with_state(files)
}

/// Which tus route a request is on, read from the raw path bytes (no decoding,
/// no normalisation).
#[cfg_attr(not(test), allow(dead_code))]
enum TicketRoute<'a> {
    Create { tenant: &'a str },
    Session { tenant: &'a str, token: &'a str },
    Other { tenant: Option<&'a str> },
}

fn ticket_route<'a>(method: &Method, path: &'a str) -> TicketRoute<'a> {
    let segs: Vec<&'a str> = path.split('/').collect();
    match segs.as_slice() {
        ["", "t", tenant, "uploads"] if !tenant.is_empty() && method == Method::POST => {
            TicketRoute::Create { tenant }
        }
        ["", "t", tenant, "uploads", token]
            if !tenant.is_empty()
                && !token.is_empty()
                && (method == Method::PATCH
                    || method == Method::HEAD
                    || method == Method::DELETE) =>
        {
            TicketRoute::Session { tenant, token }
        }
        ["", "t", tenant, ..] if !tenant.is_empty() => TicketRoute::Other {
            tenant: Some(tenant),
        },
        _ => TicketRoute::Other { tenant: None },
    }
}

/// What the lookup block found.
#[allow(dead_code)]
enum Lookup {
    /// A live ticket, with its admin's current access to the ticket's tenant.
    Live {
        row: TicketRow,
        access: AdminTenantAccess,
    },
    /// A ticket that exists but is not live.
    Known(TicketAttribution),
    Unknown,
}

/// `Upload-Metadata`, read exactly as the tus `create` handler reads it.
fn declared_metadata(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .get("upload-metadata")
        .and_then(|v| v.to_str().ok())
        .map(super::session::parse_upload_metadata)
        .unwrap_or_default()
}

/// `Upload-Length`, read exactly as the tus `create` handler reads it.
fn declared_upload_length(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("upload-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n >= 0)
}

/// Whether the upload's effective path and visibility, as the handler will
/// decide them, are exactly the ticket's. An empty path is no path, and
/// anything but `public` is private.
fn metadata_matches(headers: &HeaderMap, path: Option<&str>, public: bool) -> bool {
    let m = declared_metadata(headers);
    let eff_path = m.get("path").filter(|p| !p.is_empty()).map(String::as_str);
    let eff_public = m.get("visibility").map(String::as_str) == Some("public");
    eff_path == path && eff_public == public
}

/// A ticket may touch only the session it is bound to, byte for byte. The
/// tus handlers' own ownership check passes for any service caller, so this
/// is the only gate between a ticket and another session.
fn session_access_allowed(bound: Option<&str>, token: &str) -> bool {
    matches!(bound, Some(b) if super::session::is_valid_token(b) && b == token)
}

/// The extensions the re-routed request carries, and nothing else: the
/// service identity of the ticket's admin on the ticket's tenant, and empty
/// file caps (service passes `file_caps_layer` without them; any other
/// identity would fail closed).
fn service_extensions(
    admin_id: i64,
    tenant_id: &str,
    token_hint: String,
    pool: SharedTenantPool,
) -> Extensions {
    let mut ext = Extensions::new();
    ext.insert(AuthCtx::Service {
        admin_id: Some(admin_id),
    });
    ext.insert(TenantRef {
        tenant_id: tenant_id.to_owned(),
        token_hint,
        pool,
        role: TokenRole::Service,
    });
    ext.insert(TenantFileCaps::default());
    ext.insert(AdminId(admin_id));
    ext
}

/// Replace every extension (the outer router's URL params would otherwise be
/// appended to the ticket router's) and drop the ticket from the headers, so
/// the tus handlers never see it.
fn reroute_parts(parts: &mut axum::http::request::Parts, fresh: Extensions) {
    parts.extensions = fresh;
    parts.headers.remove(header::AUTHORIZATION);
}

/// The tus token of a 201: the last segment of its `Location`, if it has the
/// token's shape.
fn bound_token_from(headers: &HeaderMap) -> Option<String> {
    let loc = headers.get(header::LOCATION)?.to_str().ok()?;
    let last = loc.rsplit('/').next()?;
    super::session::is_valid_token(last).then(|| last.to_owned())
}

/// After the tus `create` ran: bind the ticket to the new session, or release
/// the claim if no session was made.
async fn finish_create(
    d: &TicketDispatch,
    ticket_hash: &str,
    tenant_id: &str,
    resp: Response,
) -> Response {
    if resp.status() != StatusCode::CREATED {
        let conn = d.auth.meta.lock().await;
        if let Err(e) = store::release_ticket_claim(&conn, ticket_hash) {
            // The ticket stays claimed: it can create nothing more.
            log_db_error("release", &e);
        }
        return resp;
    }
    let Some(upload_token) = bound_token_from(resp.headers()) else {
        // The claim stays in place: fail closed.
        return internal_error();
    };
    let bound = {
        let conn = d.auth.meta.lock().await;
        store::bind_ticket(
            &conn,
            ticket_hash,
            &upload_token,
            d.files.large_upload_session_ttl_secs,
        )
    };
    let refused = match bound {
        Ok(true) => return resp,
        Ok(false) => unauthenticated(),
        Err(e) => {
            log_db_error("bind", &e);
            internal_error()
        }
    };
    if super::abort_session(&d.files, tenant_id, &upload_token)
        .await
        .is_err()
    {
        tracing::warn!(
            tenant = %tenant_id,
            "upload ticket bind failed; session abort failed"
        );
    }
    refused
}

/// Every refusal of a ticket that is not live, not for this tenant, or not on
/// a tus route.
fn unauthenticated() -> Response {
    json_error(
        StatusCode::UNAUTHORIZED,
        "UNAUTHENTICATED",
        "invalid or expired upload ticket",
    )
}

fn internal_error() -> Response {
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL",
        "internal error",
    )
}

fn log_db_error(stage: &'static str, e: &rusqlite::Error) {
    tracing::error!(
        stage,
        err = %crate::error::sqlite_error_without_sql(e),
        "upload ticket store error"
    );
}

/// The files-router layer. Only a well-formed ticket is handled here; any
/// other request goes to `next` (the bearer stack) with no extra work.
pub(crate) async fn upload_ticket_dispatch(
    State(d): State<TicketDispatch>,
    req: Request,
    next: Next,
) -> Response {
    let Some(presented) = extract_bearer(&req) else {
        return next.run(req).await;
    };
    if !tokens::looks_like(TokenKind::UploadTicket, &presented) {
        return next.run(req).await;
    }
    let hint = bearer::token_hint(&presented);
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let route = ticket_route(&method, &path);

    // Block A: one short lock for the lookup.
    let lookup = {
        let conn = d.auth.meta.lock().await;
        let found = match store::find_live_ticket(&conn, &presented) {
            Ok(Some(row)) => {
                tenant_access_for_admin(&conn, row.grant_id, row.admin_id, &row.tenant_id)
                    .map(|access| Lookup::Live { row, access })
            }
            Ok(None) => store::ticket_attribution(&conn, &presented).map(|a| match a {
                Some(a) => Lookup::Known(a),
                None => Lookup::Unknown,
            }),
            Err(e) => Err(e),
        };
        match found {
            Ok(l) => l,
            Err(e) => {
                drop(conn);
                log_db_error("lookup", &e);
                return internal_error();
            }
        }
    };
    let (row, access) = match lookup {
        Lookup::Live { row, access } => (row, access),
        Lookup::Known(_) | Lookup::Unknown => return unauthenticated(),
    };

    let path_tenant = match route {
        TicketRoute::Create { tenant } | TicketRoute::Session { tenant, .. } => tenant,
        TicketRoute::Other { .. } => return unauthenticated(),
    };
    if path_tenant.as_bytes() != row.tenant_id.as_bytes()
        || matches!(access, AdminTenantAccess::Deny)
    {
        return unauthenticated();
    }
    // Outside the meta lock: opening a pool may touch the disk.
    let Some(pool) = d.auth.registry.get_if_live(&row.tenant_id) else {
        return unauthenticated();
    };
    if row.bound_upload.is_none() && !row.unbound_create_open {
        return unauthenticated();
    }

    match route {
        TicketRoute::Create { .. } => {
            if row.bound_upload.is_some() {
                return ticket_used();
            }
            if let Some(n) = declared_upload_length(req.headers())
                && n > row.max_bytes
            {
                return json_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "UPLOAD_TOO_LARGE",
                    &format!(
                        "Upload-Length {n} exceeds the ticket's max_bytes {}",
                        row.max_bytes
                    ),
                );
            }
            if !metadata_matches(req.headers(), row.path.as_deref(), row.public) {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "UPLOAD_TICKET_MISMATCH",
                    "Upload-Metadata path or visibility does not match the upload ticket",
                );
            }
            // Block B: the claim.
            let claimed = {
                let conn = d.auth.meta.lock().await;
                store::claim_ticket_create(&conn, &row.ticket_hash)
            };
            match claimed {
                Ok(true) => {}
                Ok(false) => return ticket_used(),
                Err(e) => {
                    log_db_error("claim", &e);
                    return internal_error();
                }
            }
        }
        TicketRoute::Session { token, .. } => {
            if !session_access_allowed(row.bound_upload.as_deref(), token) {
                return (StatusCode::NOT_FOUND, super::tus_headers()).into_response();
            }
        }
        TicketRoute::Other { .. } => return unauthenticated(),
    }
    let is_create = matches!(route, TicketRoute::Create { .. });

    let (mut parts, body) = req.into_parts();
    reroute_parts(
        &mut parts,
        service_extensions(row.admin_id, &row.tenant_id, hint, pool),
    );
    let resp = d
        .router
        .clone()
        .oneshot(Request::from_parts(parts, body))
        .await
        .unwrap_or_else(|e| match e {});
    if is_create {
        finish_create(&d, &row.ticket_hash, &row.tenant_id, resp).await
    } else {
        resp
    }
}

fn ticket_used() -> Response {
    json_error(
        StatusCode::CONFLICT,
        "UPLOAD_TICKET_USED",
        "this upload ticket has already started an upload",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn ticket_route_compares_raw_segments() {
        use axum::http::Method as M;
        assert!(matches!(
            ticket_route(&M::POST, "/t/acme/uploads"),
            TicketRoute::Create { tenant: "acme" }
        ));
        assert!(matches!(
            ticket_route(&M::PATCH, "/t/acme/uploads/abc"),
            TicketRoute::Session {
                tenant: "acme",
                token: "abc"
            }
        ));
        for m in [M::HEAD, M::DELETE] {
            assert!(matches!(
                ticket_route(&m, "/t/a/uploads/x"),
                TicketRoute::Session { .. }
            ));
        }
        assert!(matches!(
            ticket_route(&M::POST, "/t/%61cme/uploads"),
            TicketRoute::Create { tenant: "%61cme" }
        ));
        assert!(matches!(
            ticket_route(&M::GET, "/t/acme/uploads"),
            TicketRoute::Other {
                tenant: Some("acme")
            }
        ));
        assert!(matches!(
            ticket_route(&M::HEAD, "/t/acme/uploads"),
            TicketRoute::Other {
                tenant: Some("acme")
            }
        ));
        assert!(matches!(
            ticket_route(&M::OPTIONS, "/t/acme/uploads"),
            TicketRoute::Other {
                tenant: Some("acme")
            }
        ));
        assert!(matches!(
            ticket_route(&M::POST, "/t/acme/uploads/x"),
            TicketRoute::Other { .. }
        ));
        assert!(matches!(
            ticket_route(&M::PATCH, "/t/acme/uploads"),
            TicketRoute::Other { .. }
        ));
        assert!(matches!(
            ticket_route(&M::PATCH, "/t/acme/uploads/"),
            TicketRoute::Other { .. }
        ));
        assert!(matches!(
            ticket_route(&M::POST, "/t/acme/files"),
            TicketRoute::Other {
                tenant: Some("acme")
            }
        ));
        assert!(matches!(
            ticket_route(&M::POST, "/x"),
            TicketRoute::Other { tenant: None }
        ));
    }

    #[test]
    fn metadata_is_read_exactly_as_the_handler_reads_it() {
        let h = |vals: &[&str]| {
            let mut m = HeaderMap::new();
            for v in vals {
                m.append("upload-metadata", v.parse().unwrap());
            }
            m
        };
        let b = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        assert!(metadata_matches(&HeaderMap::new(), None, false));
        assert!(metadata_matches(
            &h(&[&format!("visibility {}", b("public"))]),
            None,
            true
        ));
        assert!(metadata_matches(
            &h(&[&format!("visibility {}", b("private"))]),
            None,
            false
        ));
        // The handler reads anything but "public" as private.
        assert!(!metadata_matches(
            &h(&[&format!("visibility {}", b("PUBLIC"))]),
            None,
            true
        ));
        // A public ticket with silent metadata.
        assert!(!metadata_matches(&HeaderMap::new(), None, true));
        // An empty path is no path.
        assert!(metadata_matches(
            &h(&[&format!("path {}", b(""))]),
            None,
            false
        ));
        // The ticket has no path: the upload may not declare one.
        assert!(!metadata_matches(
            &h(&[&format!("path {}", b("x/1"))]),
            None,
            false
        ));
        // The ticket has a path, the metadata none.
        assert!(!metadata_matches(&HeaderMap::new(), Some("docs/a"), false));
        // An undecodable value is skipped, so the path is absent.
        assert!(!metadata_matches(
            &h(&["path !!!notb64"]),
            Some("docs/a"),
            false
        ));
        // A repeated key: the last one wins.
        assert!(metadata_matches(
            &h(&[&format!("path {},path {}", b("x/1"), b("docs/a"))]),
            Some("docs/a"),
            false
        ));
        // Two header lines: only the first is read.
        assert!(metadata_matches(
            &h(&["filename eA==", &format!("visibility {}", b("public"))]),
            None,
            false
        ));
    }

    #[test]
    fn upload_length_is_read_exactly_as_the_handler_reads_it() {
        let h = |vals: &[&str]| {
            let mut m = HeaderMap::new();
            for v in vals {
                m.append("upload-length", v.parse().unwrap());
            }
            m
        };
        assert_eq!(declared_upload_length(&h(&["11"])), Some(11));
        // i64::from_str accepts a leading '+'.
        assert_eq!(declared_upload_length(&h(&["+11"])), Some(11));
        // No trimming.
        assert_eq!(declared_upload_length(&h(&[" 11"])), None);
        assert_eq!(declared_upload_length(&h(&["-1"])), None);
        assert_eq!(declared_upload_length(&h(&["1e3"])), None);
        // Two header lines: only the first is read.
        assert_eq!(declared_upload_length(&h(&["11", "99"])), Some(11));
        assert_eq!(declared_upload_length(&HeaderMap::new()), None);
    }

    #[test]
    fn session_access_requires_a_valid_bound_token() {
        let u = "0f8fad5b-d9cb-469f-a165-70867728950e";
        assert!(session_access_allowed(Some(u), u));
        assert!(!session_access_allowed(Some(u), &u.to_uppercase()));
        assert!(!session_access_allowed(Some("creating"), "creating"));
        assert!(!session_access_allowed(None, u));
    }

    #[derive(Clone)]
    struct Marker;

    #[test]
    fn reroute_drops_authorization_and_old_extensions() {
        let dir = tempfile::tempdir().unwrap();
        let registry = crate::storage::pool::TenantRegistry::new(dir.path().to_path_buf(), 2);
        let pool = registry.get_or_create("t1").unwrap();
        let t = tokens::new_token(TokenKind::UploadTicket);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/t/t1/uploads")
            .header(header::AUTHORIZATION, format!("Bearer {t}"))
            .header("tus-resumable", "1.0.0")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(Marker);
        let (mut parts, _body) = req.into_parts();
        reroute_parts(
            &mut parts,
            service_extensions(7, "t1", bearer::token_hint(&t), pool),
        );
        assert!(parts.headers.get(header::AUTHORIZATION).is_none());
        assert_eq!(parts.headers.get("tus-resumable").unwrap(), "1.0.0");
        assert!(parts.extensions.get::<Marker>().is_none());
        assert!(matches!(
            parts.extensions.get::<AuthCtx>(),
            Some(AuthCtx::Service { admin_id: Some(7) })
        ));
        assert!(matches!(
            parts.extensions.get::<AdminId>(),
            Some(AdminId(7))
        ));
        let caps = parts.extensions.get::<TenantFileCaps>().expect("file caps");
        assert!(caps.anon.is_empty() && caps.user.is_empty());
        let tr = parts.extensions.get::<TenantRef>().expect("tenant ref");
        assert_eq!(tr.tenant_id, "t1");
        assert_eq!(tr.role, TokenRole::Service);
        assert_eq!(tr.token_hint, bearer::token_hint(&t));
    }

    #[test]
    fn bound_token_comes_from_the_last_location_segment() {
        let u = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let loc = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert(header::LOCATION, v.parse().unwrap());
            m
        };
        assert_eq!(
            bound_token_from(&loc(&format!("/drust/t/a/uploads/{u}"))).as_deref(),
            Some(u)
        );
        assert_eq!(
            bound_token_from(&loc(&format!("/t/a/uploads/{u}"))).as_deref(),
            Some(u)
        );
        assert_eq!(bound_token_from(&loc("/t/a/uploads/../x")), None);
        assert_eq!(bound_token_from(&loc("/t/a/uploads/creating")), None);
        assert_eq!(bound_token_from(&HeaderMap::new()), None);
    }

    /// One owner, one live grant, a live tenant `t1` on disk and one ticket
    /// for it (no path, private, at most 64 bytes); the auth and files states
    /// share the meta handle (`files.meta` is `Some`, as in production).
    pub(super) struct Fx {
        pub meta: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
        pub registry: std::sync::Arc<crate::storage::pool::TenantRegistry>,
        pub auth: TenantAuthState,
        pub files: TenantFilesState,
        pub ticket: String,
        pub grant_id: i64,
        pub admin_id: i64,
    }

    pub(super) fn dispatch_fixture(dir: &std::path::Path) -> Fx {
        use crate::mgmt::mcp_oauth::caller::McpCaller;
        use std::sync::Arc;
        let root = dir.to_path_buf();
        let conn = crate::storage::meta::open_meta(&root.join("meta.sqlite")).unwrap();
        crate::db::migrations::run_migrations(&conn, &root).unwrap();
        conn.execute(
            "INSERT INTO admins (username, password_hash, role) \
             VALUES ('root', '$oauth-only$', 'owner')",
            [],
        )
        .unwrap();
        let admin_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO _mcp_oauth_grants \
               (admin_id, admin_created_at, client_id, redirect_host, \
                idle_expires_at, absolute_expires_at) \
             SELECT id, created_at, 'c', 'localhost', \
                    datetime('now', '+30 days'), datetime('now', '+90 days') FROM admins",
            [],
        )
        .unwrap();
        let grant_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('t1', 'T1', ?1)",
            [admin_id],
        )
        .unwrap();
        crate::storage::tenant_db::open_write(&root, "t1").unwrap();
        let AdminTenantAccess::Allow(inc) =
            tenant_access_for_admin(&conn, grant_id, admin_id, "t1").unwrap()
        else {
            panic!("the owner sees t1");
        };
        let req = store::TicketRequest {
            tenant_id: "t1",
            max_bytes: 64,
            path: None,
            public: false,
        };
        let ticket = store::issue_upload_ticket(
            &conn,
            &McpCaller::for_tests(admin_id, grant_id),
            &inc,
            &req,
        )
        .unwrap()
        .expect("issued")
        .plaintext()
        .to_string();
        let meta = Arc::new(tokio::sync::Mutex::new(conn));
        let registry = Arc::new(crate::storage::pool::TenantRegistry::new(root.clone(), 2));
        let auth = TenantAuthState::test_default(meta.clone(), registry.clone());
        let mut files = TenantFilesState::test_default(
            Some(Arc::new(crate::storage::garage::GarageClient::from_store(
                Arc::new(object_store::memory::InMemory::new()),
                "private",
            ))),
            root,
            registry.clone(),
        );
        files.disk_min_free_pct = 0;
        files.meta = Some(meta.clone());
        Fx {
            meta,
            registry,
            auth,
            files,
            ticket,
            grant_id,
            admin_id,
        }
    }

    #[tokio::test]
    async fn bind_failure_aborts_the_session_and_answers_401() {
        let dir = tempfile::tempdir().unwrap();
        let fx = dispatch_fixture(dir.path());
        let d = TicketDispatch::new(fx.auth.clone(), fx.files.clone());
        let hash = tokens::hash(TokenKind::UploadTicket, &fx.ticket);
        {
            let conn = fx.meta.lock().await;
            assert!(store::claim_ticket_create(&conn, &hash).unwrap());
        }
        let pool = fx.registry.get_if_live("t1").unwrap();
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/t/t1/uploads")
            .header("tus-resumable", "1.0.0")
            .header("upload-length", "4")
            .body(axum::body::Body::empty())
            .unwrap();
        *req.extensions_mut() = service_extensions(
            fx.admin_id,
            "t1",
            bearer::token_hint(&fx.ticket),
            pool.clone(),
        );
        let created = d.router.clone().oneshot(req).await.unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let tok = bound_token_from(created.headers()).expect("a tus token");
        assert!(
            crate::tenant::uploads::session::get_session(&pool, &tok)
                .await
                .unwrap()
                .is_some(),
            "anti-vacuous: the session exists"
        );
        {
            let conn = fx.meta.lock().await;
            conn.execute(
                "UPDATE _mcp_upload_tickets SET revoked_at = datetime('now')",
                [],
            )
            .unwrap();
        }
        let resp = finish_create(&d, &hash, "t1", created).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            crate::tenant::uploads::session::get_session(&pool, &tok)
                .await
                .unwrap()
                .is_none()
        );
        let _ = fx.grant_id;
    }
}
