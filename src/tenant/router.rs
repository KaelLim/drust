use crate::auth::bearer::{hash_token, token_hint};
use crate::auth::middleware::AuthCtx;
use crate::error::{json_error, json_error_with_aliases};
use crate::safety::audit::{AuditEntry, DefaultAuditExtra};
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
    /// HMAC-SHA256 key used to bind per-tenant OAuth `state` to the
    /// frontend's `redirect_uri`. Generated once at boot (32 random bytes,
    /// in-memory only). A restart invalidates any in-flight OAuth
    /// round-trips — acceptable given the 5-minute cookie TTL on PKCE.
    /// See [`crate::oauth::state::TenantOauthStateToken`] for the wire format.
    pub tenant_oauth_state_secret: Arc<[u8; 32]>,
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
/// let mut state = TenantAuthState::test_default(meta, registry);
/// state.limiter = Arc::new(RateLimiter::new(budget, window));
/// ```
#[cfg(any(test, debug_assertions))]
impl TenantAuthState {
    pub fn test_default(
        meta: Arc<Mutex<Connection>>,
        registry: Arc<TenantRegistry>,
    ) -> Self {
        use std::time::Duration;
        Self {
            meta,
            registry,
            limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
            index_large_table_rows: 1_000_000,
            register_rl: Arc::new(IpRateLimit::new(3, Duration::from_secs(60), 4096)),
            login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
            oauth_callback_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
            public_url: String::new(),
            oauth_adapter_override: Arc::new(std::collections::HashMap::new()),
            // Tests use a fixed secret: differences between TenantAuthState
            // instances would break the OAuth chain in any test that calls
            // /start and /callback on the same router (which they all do).
            tenant_oauth_state_secret: Arc::new(*b"drust-test-state-secret-32bytesx"),
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
    // v1.32.1 D5: defer alloc to audit-emit branch — cheap captures only pre-next.run.
    // Method is small enum-like and Uri is internally Arc-shared (path-and-query),
    // so both clone in O(1). The bearer needs one alloc to outlive `next.run(req)`
    // (which consumes `req`); the auth path inside the closure re-extracts on its own.
    // path / tenant / hint String allocs are pushed below to the audit-emit site.
    let method_captured = req.method().clone();
    let uri_captured = req.uri().clone();
    let bearer_captured: Option<String> = extract_bearer(&req);

    // Resolved during auth; captured here so the audit-emit code below can
    // attach `auth_kind` / `auth_user_id` without re-reading request extensions
    // (request is consumed by `next.run`).
    let mut resolved_auth_ctx: Option<AuthCtx> = None;
    // v1.32.3 D9 — admin email snapshot for the audit row. Pre-D9 this was
    // loaded post-handler via a 4th meta.lock(); the D9 CTE includes it so
    // the audit branch consumes this captured local instead.
    let mut resolved_email_snapshot: Option<String> = None;

    let resp = async {
        let tenant_id = match params.get("tenant") {
            Some(t) => t.clone(),
            None => return (StatusCode::BAD_REQUEST, "missing tenant in path").into_response(),
        };
        let bearer = match extract_bearer(&req) {
            Some(t) => t,
            None => {
                // v1.32 C1 — bearer denied counter
                crate::mgmt::metrics::metrics()
                    .bearer_denied_total
                    .with_label_values(&["none", "HTTP_401"])
                    .inc();
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
        // v1.32.3 D9 — collapsed meta lookup. Pre-D9 this section took
        // the meta mutex THREE separate times per request: once for the
        // tenant-exists check, once for the per-admin PAT lookup, once
        // for the shared service/anon tokens lookup. A FOURTH lock was
        // taken in the post-handler audit path for the email snapshot
        // (see below). meta.sqlite is the single global serializer for
        // every tenant request — under cross-tenant load that was the
        // top contention point.
        //
        // The CTE below returns everything those four lookups produced
        // in ONE round-trip:
        //   * tenant_ok       — boolean (EXISTS on tenants)
        //   * kind            — "admin_pat" / "service" / "anon" / NULL
        //   * pat_token_id    — for the spawned last_used_at bump
        //   * pat_admin_id    — for AuthCtx::Service { admin_id }
        //   * bound_tenant    — service/anon token's tenant_id
        //                       (for the cross-tenant 404 invariant)
        //   * pat_email       — admin email snapshot (audit row)
        //
        // PAT and service/anon use DIFFERENT hash schemes (base64-no-pad
        // vs hex), so the two UNION branches can never match the same
        // bearer — the LIMIT 1 on each scalar subquery is just defensive.
        // PAT prefix check stays in Rust to avoid wasting a hash compute
        // on non-PAT bearers.
        const SQL_BEARER_AUTH_CTE: &str = "\
WITH bearer_match AS ( \
    SELECT 'admin_pat' AS kind, p.id AS token_id, p.admin_id, \
           NULL AS bound_tenant \
    FROM _admin_tokens p \
    WHERE p.token_hash = ?2 AND p.revoked_at IS NULL \
    UNION ALL \
    SELECT k.role AS kind, NULL AS token_id, NULL AS admin_id, \
           k.tenant_id AS bound_tenant \
    FROM tokens k \
    JOIN tenants n ON n.id = k.tenant_id \
    WHERE k.token_hash = ?3 AND k.revoked_at IS NULL AND n.deleted_at IS NULL \
) \
SELECT \
    EXISTS(SELECT 1 FROM tenants WHERE id = ?1 AND deleted_at IS NULL), \
    (SELECT kind FROM bearer_match LIMIT 1), \
    (SELECT token_id FROM bearer_match LIMIT 1), \
    (SELECT admin_id FROM bearer_match LIMIT 1), \
    (SELECT bound_tenant FROM bearer_match LIMIT 1), \
    (SELECT email FROM admins WHERE id = (SELECT admin_id FROM bearer_match LIMIT 1))";

        let pat_hash = bearer
            .starts_with(crate::auth::admin_token::TOKEN_PREFIX)
            .then(|| crate::auth::admin_token::hash_token(&bearer));

        let meta_row: Option<(
            bool,           // tenant_ok
            Option<String>, // kind
            Option<i64>,    // pat_token_id
            Option<i64>,    // pat_admin_id
            Option<String>, // bound_tenant
            Option<String>, // pat_email
        )> = {
            let conn = state.meta.lock().await;
            conn.query_row(
                SQL_BEARER_AUTH_CTE,
                rusqlite::params![
                    tenant_id,
                    pat_hash.as_deref().unwrap_or(""),
                    hash,
                ],
                |r| Ok((
                    r.get::<_, i64>(0)? != 0,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                )),
            )
            .ok()
        };
        let (tenant_ok, kind, pat_token_id, pat_admin_id, bound_tenant, pat_email_snapshot) =
            meta_row.unwrap_or_default();
        if !tenant_ok {
            return json_error(
                StatusCode::NOT_FOUND,
                "TENANT_NOT_FOUND",
                "tenant not accessible",
            );
        }
        // Open the tenant pool. Needed regardless of bearer kind (user
        // session lookup, downstream handlers).
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
        // Per-tenant _system_sessions, in a separate connection — not
        // covered by the meta CTE. User-session bearers use yet another
        // hash scheme, so when they're presented `kind` from the CTE is
        // None; we fall through to the user-session lookup.
        // User sessions take precedence over meta-side roles by design
        // (same as pre-D9 ordering: pool-side resolved before meta-side).
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
        // Apply the kind resolved by the CTE.
        match kind.as_deref() {
            Some("admin_pat") => {
                // PAT path — admin_id/email already loaded by the CTE.
                let admin_id = match pat_admin_id {
                    Some(id) => id,
                    None => {
                        crate::mgmt::metrics::metrics()
                            .bearer_denied_total
                            .with_label_values(&["unknown", "HTTP_401"])
                            .inc();
                        return json_error(
                            StatusCode::UNAUTHORIZED,
                            "UNAUTHENTICATED",
                            "invalid token",
                        );
                    }
                };
                // Best-effort throttled last_used_at update (unchanged).
                if let Some(token_id) = pat_token_id {
                    let meta_for_bump = state.meta.clone();
                    tokio::spawn(async move {
                        let conn = meta_for_bump.lock().await;
                        let _ = conn.execute(
                            "UPDATE _admin_tokens SET last_used_at = datetime('now') \
                             WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at < datetime('now', '-60 seconds'))",
                            rusqlite::params![token_id],
                        );
                    });
                }
                // Email snapshot from CTE travels to the audit branch via
                // the captured local (no extra meta.lock at audit time).
                resolved_email_snapshot = pat_email_snapshot;
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
            }
            Some(role_str @ ("service" | "anon")) => {
                // Cross-tenant token guard (preserves pre-D9 wire 404).
                if bound_tenant.as_deref() != Some(tenant_id.as_str()) {
                    return json_error(
                        StatusCode::NOT_FOUND,
                        "TENANT_NOT_FOUND",
                        "tenant not accessible",
                    );
                }
                let role = match TokenRole::parse(role_str) {
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
                    TokenRole::Service => AuthCtx::Service { admin_id: None },
                    TokenRole::User => unreachable!(
                        "user sessions are resolved via pool reader before this branch"
                    ),
                };
                resolved_auth_ctx = Some(ctx.clone());
                req.extensions_mut().insert(ctx);
                req.extensions_mut().insert(TenantRef {
                    tenant_id: tenant_id.clone(),
                    token_hint: token_hint(&bearer),
                    pool,
                    role,
                });
            }
            // None or any unexpected kind — bearer unresolved.
            _ => {
                crate::mgmt::metrics::metrics()
                    .bearer_denied_total
                    .with_label_values(&["unknown", "HTTP_401"])
                    .inc();
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHENTICATED",
                    "invalid token",
                );
            }
        }
        next.run(req).await
    }
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;
    // v1.32.1 D5: deferred String allocs — only computed here, post-next.run.
    // The hot path inside the closure (auth lookup, handler dispatch) no longer
    // pays for these; the C1 denial counters use static labels and don't need them.
    let path_for_audit = uri_captured.path().to_string();
    let tenant_for_audit = params.get("tenant").cloned().unwrap_or_default();
    let hint_for_audit = bearer_captured
        .as_deref()
        .map(token_hint)
        .unwrap_or_else(|| "-".to_string());
    let op_path = path_for_audit
        .strip_prefix(&format!("/t/{tenant_for_audit}"))
        .unwrap_or(&path_for_audit);
    let op = format!("{method_captured} {op_path}");
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
    // v1.32.3 D9 — email snapshot was already loaded by the auth CTE; pull
    // from the captured local instead of taking the meta mutex again.
    let mut entry = entry;
    if let Some(AuthCtx::Service { admin_id: Some(id) }) = &resolved_auth_ctx {
        entry.actor_admin_id = Some(*id);
        entry.actor_email_snapshot = resolved_email_snapshot;
    }
    crate::safety::audit_db::try_send(&entry);
    resp
}

/// Guard used by write-path handlers. Returns `Err(response)` if the
/// current bearer is an anon or user key, ready to short-circuit the handler.
#[allow(clippy::result_large_err)]
pub fn require_service(t: &TenantRef) -> Result<(), Response> {
    if matches!(t.role, TokenRole::Anon | TokenRole::User) {
        return Err(json_error_with_aliases(
            StatusCode::FORBIDDEN,
            "WRITE_DENIED",
            &["SERVICE_REQUIRED"],
            "anon/user key cannot write; use a service key",
        ));
    }
    Ok(())
}

fn extract_bearer<B>(req: &Request<B>) -> Option<String> {
    let raw = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(|s| s.to_string())
}

