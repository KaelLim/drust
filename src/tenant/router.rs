use crate::auth::bearer::{hash_token, token_hint};
use crate::auth::middleware::AuthCtx;
use crate::error::json_error;
use crate::safety::audit::{AuditEntry, AuditLog, DefaultAuditExtra};
use crate::safety::rate_limit::RateLimiter;
use crate::safety::rate_limit_ip::IpRateLimit;
use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rusqlite::Connection;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct TenantAuthState {
    pub meta: Arc<Mutex<Connection>>,
    pub registry: Arc<TenantRegistry>,
    pub limiter: Arc<RateLimiter>,
    pub audit: Arc<AuditLog>,
    /// Row count threshold above which index creation is considered "large
    /// table" and returns `LARGE_TABLE` unless `force=true`. Sourced from
    /// `DRUST_INDEX_LARGE_TABLE_ROWS` (default 1 000 000).
    pub index_large_table_rows: u64,
    /// Per-IP rate limiter for POST /auth/register. Default: 3 per 60 s.
    pub register_rl: Arc<IpRateLimit>,
    /// Per-IP rate limiter for POST /auth/login. Default: 5 per 60 s.
    pub login_rl: Arc<IpRateLimit>,
    /// Per-IP rate limiter for GET /oauth/{provider}/callback. Default: 5 per 60 s.
    /// Defends the provider-exchange path (one DB write + one outbound HTTP) from
    /// brute-force replay of attacker-supplied `code` + `state` pairs.
    pub oauth_callback_rl: Arc<IpRateLimit>,
    /// Public-facing base URL drust serves on, e.g. `https://drust.example.com`.
    /// Read once at TenantStack construction (from `DRUST_PUBLIC_URL`) and
    /// pinned here so OAuth handlers don't have to re-read env per request
    /// — keeps integration tests free of env-var pollution.
    pub public_url: String,
    /// Test-only override for `build_adapter` in `oauth_routes`. Empty in
    /// production (handlers fall back to `GoogleAdapter::production(...)` /
    /// `GitHubAdapter::production(...)`). Tests populate this with fake
    /// adapters pointed at a local `spawn_fake_google()` HTTP server.
    pub oauth_adapter_override:
        Arc<std::collections::HashMap<String, Arc<dyn crate::oauth::provider::OauthProvider>>>,
}

/// Test-only constructor available in debug builds (integration tests run
/// debug by default; the factory is excluded from `cargo build --release`
/// because release builds have `debug_assertions = false`).
///
/// Fills all secondary fields with safe, non-trivial defaults that mirror
/// production values:
/// - `limiter`: 10 000 req / 1 s (effectively unlimited for tests)
/// - `index_large_table_rows`: 1 000 000 (production default)
/// - `register_rl`: 3 / 60 s (production default)
/// - `login_rl`: 5 / 60 s (production default)
/// - `oauth_callback_rl`: 5 / 60 s (production default)
/// - `public_url`: `""` (OAuth start/callback use a fake adapter in tests)
/// - `oauth_adapter_override`: empty (no fake providers wired)
///
/// For tests that need a custom `limiter` (e.g. rate-limit threshold tests),
/// build with `test_default` then overwrite the field:
/// ```ignore
/// let mut state = TenantAuthState::test_default(meta, registry, audit);
/// state.limiter = Arc::new(RateLimiter::new(budget, window));
/// ```
#[cfg(any(test, debug_assertions))]
impl TenantAuthState {
    pub fn test_default(
        meta: Arc<Mutex<Connection>>,
        registry: Arc<TenantRegistry>,
        audit: Arc<AuditLog>,
    ) -> Self {
        use std::time::Duration;
        Self {
            meta,
            registry,
            limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
            audit,
            index_large_table_rows: 1_000_000,
            register_rl: Arc::new(IpRateLimit::new(3, Duration::from_secs(60), 4096)),
            login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
            oauth_callback_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
            public_url: String::new(),
            oauth_adapter_override: Arc::new(std::collections::HashMap::new()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenRole {
    Anon,
    Service,
    /// A user session token resolved from `_system_sessions` in the tenant db.
    User,
}

impl TokenRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anon => "anon",
            Self::Service => "service",
            Self::User => "user",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        // Only anon/service appear in meta.sqlite's `tokens.role` column;
        // user is resolved from `_system_sessions` and never persisted here.
        match s {
            "anon" => Some(Self::Anon),
            "service" => Some(Self::Service),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct TenantRef {
    pub tenant_id: String,
    pub token_hint: String,
    pub pool: SharedTenantPool,
    pub role: TokenRole,
}

pub async fn bearer_auth_layer(
    State(state): State<TenantAuthState>,
    Path(params): Path<std::collections::HashMap<String, String>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method_for_audit = req.method().clone();
    let path_for_audit = req.uri().path().to_string();
    let tenant_for_audit = params.get("tenant").cloned().unwrap_or_default();
    let hint_for_audit = extract_bearer(&req)
        .map(|b| token_hint(&b))
        .unwrap_or_else(|| "-".to_string());
    let audit_sink = state.audit.clone();

    // Resolved during auth; captured here so the audit-emit code below can
    // attach `auth_kind` / `auth_user_id` without re-reading request extensions
    // (request is consumed by `next.run`).
    let mut resolved_auth_ctx: Option<AuthCtx> = None;

    let resp = async {
        let tenant_id = match params.get("tenant") {
            Some(t) => t.clone(),
            None => return (StatusCode::BAD_REQUEST, "missing tenant in path").into_response(),
        };
        let bearer = match extract_bearer(&req) {
            Some(t) => t,
            None => {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHENTICATED",
                    "missing bearer",
                );
            }
        };
        let hash = hash_token(&bearer);
        // Per-token rate limit. Keyed on the SHA-256 hash so rerolled tokens
        // get their own bucket. Runs before the DB lookup so an abusive
        // client cannot keep us churning on meta.sqlite.
        if let Err(e) = state.limiter.try_acquire(&hash) {
            let secs = e.0.as_secs().max(1);
            let body = serde_json::json!({
                "error_code": "RATE_LIMITED",
                "message": format!("rate limit exceeded; retry after {secs}s"),
            });
            let mut r = axum::Json(body).into_response();
            *r.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            r.headers_mut().insert(
                header::RETRY_AFTER,
                axum::http::HeaderValue::from_str(&secs.to_string()).unwrap(),
            );
            return r;
        }
        // Validate tenant exists in meta BEFORE opening its pool — prevents
        // an attacker from spamming arbitrary tenant ids in the path and
        // forcing the pool to materialize ghost data.sqlite files on disk.
        {
            let conn = state.meta.lock().await;
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
                    rusqlite::params![tenant_id],
                    |_| Ok(()),
                )
                .is_ok();
            drop(conn);
            if !exists {
                return json_error(
                    StatusCode::NOT_FOUND,
                    "TENANT_NOT_FOUND",
                    "tenant not accessible",
                );
            }
        }
        // Open the tenant pool early so we can probe _system_sessions for
        // user tokens before hitting meta.sqlite.
        let pool = match state.registry.get_or_open(&tenant_id) {
            Ok(p) => p,
            Err(_) => {
                return json_error(
                    StatusCode::NOT_FOUND,
                    "TENANT_NOT_FOUND",
                    "tenant data missing",
                );
            }
        };
        // --- User-session path ---
        // Check tenant's _system_sessions table first. User tokens never
        // appear in the meta.sqlite `tokens` table.
        let bearer_for_lookup = bearer.clone();
        let session_result = pool
            .with_reader(move |c| {
                crate::auth::user_session::lookup_session(c, &bearer_for_lookup)
            })
            .await;
        if let Ok(Some(session_info)) = session_result {
            // Slide expiry best-effort on a background task.
            let token_for_slide = bearer.clone();
            let pool_for_slide = pool.clone();
            tokio::spawn(async move {
                let _ = pool_for_slide
                    .with_writer(move |c| {
                        crate::auth::user_session::slide_expiry(c, &token_for_slide, 30)
                    })
                    .await;
            });
            // Use user_session::hash_token (base64) — the same encoding used
            // when the session row was inserted — so logout handlers can DELETE
            // by hash without re-hashing from the plaintext bearer.
            let session_hash =
                crate::auth::user_session::hash_token(&bearer);
            let ctx = AuthCtx::User {
                user_id: session_info.user_id.clone(),
                token_hash: session_hash,
            };
            resolved_auth_ctx = Some(ctx.clone());
            req.extensions_mut().insert(ctx);
            req.extensions_mut().insert(TenantRef {
                tenant_id: tenant_id.clone(),
                token_hint: token_hint(&bearer),
                pool,
                role: TokenRole::User,
            });
            return next.run(req).await;
        }
        // --- v1.29 step 6: per-admin PAT lookup ---
        {
            let conn = state.meta.lock().await;
            let hit = crate::auth::admin_token::lookup(&conn, &bearer).ok().flatten();
            drop(conn);
            if let Some(crate::auth::admin_token::AdminTokenHit { token_id, admin_id }) = hit {
                // Best-effort throttled last_used_at update
                let meta_for_bump = state.meta.clone();
                tokio::spawn(async move {
                    let conn = meta_for_bump.lock().await;
                    let _ = conn.execute(
                        "UPDATE _admin_tokens SET last_used_at = datetime('now') \
                         WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at < datetime('now', '-60 seconds'))",
                        rusqlite::params![token_id],
                    );
                });
                let ctx = AuthCtx::Service { admin_id: Some(admin_id) };
                resolved_auth_ctx = Some(ctx.clone());
                req.extensions_mut().insert(ctx);
                req.extensions_mut().insert(crate::auth::middleware::AdminId(admin_id));
                req.extensions_mut().insert(TenantRef {
                    tenant_id: tenant_id.clone(),
                    token_hint: token_hint(&bearer),
                    pool,
                    role: TokenRole::Service,
                });
                return next.run(req).await;
            }
        }
        // --- Service / Anon path (meta.sqlite tokens table) ---
        // Verify: (token active) AND (tenant active). Fetch role alongside.
        let conn = state.meta.lock().await;
        let ok: Option<(String, String)> = conn
            .query_row(
                "SELECT t.tenant_id, t.role FROM tokens t
             JOIN tenants n ON n.id = t.tenant_id
             WHERE t.token_hash = ?1 AND t.revoked_at IS NULL AND n.deleted_at IS NULL",
                rusqlite::params![hash],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .ok();
        drop(conn);
        let (bound_tenant, role_str) = match ok {
            Some(row) => row,
            None => {
                return json_error(StatusCode::UNAUTHORIZED, "UNAUTHENTICATED", "invalid token");
            }
        };
        if bound_tenant != tenant_id {
            return json_error(
                StatusCode::NOT_FOUND,
                "TENANT_NOT_FOUND",
                "tenant not accessible",
            );
        }
        let role = match TokenRole::parse(&role_str) {
            Some(r) => r,
            None => {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHENTICATED",
                    "token has invalid role",
                );
            }
        };
        let ctx = match role {
            TokenRole::Anon => AuthCtx::Anon,
            TokenRole::Service => AuthCtx::Service { admin_id: None }, // shared per-tenant token, no attribution
            TokenRole::User => unreachable!("user sessions are resolved before meta lookup"),
        };
        resolved_auth_ctx = Some(ctx.clone());
        req.extensions_mut().insert(ctx);
        req.extensions_mut().insert(TenantRef {
            tenant_id: tenant_id.clone(),
            token_hint: token_hint(&bearer),
            pool,
            role,
        });
        next.run(req).await
    }
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;
    let op_path = path_for_audit
        .strip_prefix(&format!("/t/{tenant_for_audit}"))
        .unwrap_or(&path_for_audit);
    let op = format!("{method_for_audit} {op_path}");
    let status = resp.status();
    // Read handler-supplied extras BEFORE consuming `resp`.
    let handler_extra: Option<crate::safety::audit::AuditExtra> = resp
        .extensions()
        .get::<crate::safety::audit::AuditExtra>()
        .cloned();
    let default_extra: Option<DefaultAuditExtra> = resp
        .extensions()
        .get::<DefaultAuditExtra>()
        .cloned();
    let entry = if status.is_success() || status.is_redirection() {
        AuditEntry::success(&tenant_for_audit, &hint_for_audit, &op, duration_ms)
    } else {
        AuditEntry::failure(
            &tenant_for_audit,
            &hint_for_audit,
            &op,
            duration_ms,
            &format!("HTTP_{}", status.as_u16()),
            "",
        )
    };
    // Layer 1: default fields from auth context (auth_kind, auth_user_id).
    // Only present when auth actually succeeded (pre-auth failures have None).
    let entry = if let Some(ctx) = &resolved_auth_ctx {
        let default_fields = match ctx {
            AuthCtx::User { user_id, .. } => serde_json::json!({
                "auth_kind": "user",
                "auth_user_id": user_id,
            }),
            AuthCtx::Service { admin_id } => {
                let mut obj = serde_json::json!({"auth_kind": "service"});
                if let Some(id) = admin_id {
                    obj["auth_admin_id"] = serde_json::json!(id);
                }
                obj
            }
            AuthCtx::Anon => serde_json::json!({"auth_kind": "anon"}),
        };
        entry.with_extra(default_fields)
    } else {
        entry
    };
    // Layer 2: handler-set DefaultAuditExtra (overrides layer-1 fields if present).
    let entry = if let Some(de) = default_extra {
        entry.with_extra(de.0)
    } else {
        entry
    };
    // Layer 3: handler-set AuditExtra (overrides all previous fields).
    let entry = if let Some(extra) = handler_extra {
        entry.with_extra(extra.0)
    } else {
        entry
    };
    // v1.29: top-level actor attribution columns (SQL queryable).
    // Populate when the resolved context is a PAT/OAuth-bound service call.
    let mut entry = entry;
    if let Some(AuthCtx::Service { admin_id: Some(id) }) = &resolved_auth_ctx {
        entry.actor_admin_id = Some(*id);
        let conn = state.meta.lock().await;
        entry.actor_email_snapshot = conn
            .query_row(
                "SELECT email FROM admins WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .ok();
        drop(conn);
    }
    audit_sink.append(entry);
    resp
}

/// Guard used by write-path handlers. Returns `Err(response)` if the
/// current bearer is an anon or user key, ready to short-circuit the handler.
#[allow(clippy::result_large_err)]
pub fn require_service(t: &TenantRef) -> Result<(), Response> {
    if matches!(t.role, TokenRole::Anon | TokenRole::User) {
        let body = axum::Json(serde_json::json!({
            "error_code": "WRITE_DENIED",
            "message": "anon/user key cannot write; use a service key"
        }));
        let mut r = body.into_response();
        *r.status_mut() = StatusCode::FORBIDDEN;
        return Err(r);
    }
    Ok(())
}

fn extract_bearer<B>(req: &Request<B>) -> Option<String> {
    let raw = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(|s| s.to_string())
}

