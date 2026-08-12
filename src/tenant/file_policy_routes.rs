//! Files RLS (#950-B) — the service-only REST face of the per-tenant prefix
//! policy registry.
//!
//! * `PUT    /t/<id>/file-policies`                 — register / replace one prefix rule
//! * `GET    /t/<id>/file-policies`                 — list every rule
//! * `DELETE /t/<id>/file-policies?prefix=<prefix>` — clear one rule
//!
//! These sit on the `core` router (NOT wrapped by `require_service_layer`), so
//! each handler enforces service-only inline via `TenantRef.role`, exactly like
//! the sibling collection-policy routes. **All three verbs**, list included: the
//! registry IS the tenant's file-access map, and handing it to an end user is a
//! reconnaissance gift even where they cannot write it.
//!
//! The prefix travels as a QUERY parameter on DELETE, not a path segment,
//! because a prefix contains `/` and the tenant root is the EMPTY string —
//! neither survives a path segment. An absent `prefix` parameter is refused
//! rather than defaulted, so a truncated URL can never clear the root by
//! accident.

use crate::error::{json_error, json_error_with_aliases};
use crate::storage::file_policy::{
    FilePolicyError, FilePolicyRow, delete_file_policy, load_file_policies, upsert_file_policy,
    validate_file_policy,
};
use crate::tenant::router::{TenantRef, TokenRole};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

/// Service-only gate, matching the sibling collection-policy route's 403 shape.
fn require_service(t: &TenantRef) -> Result<(), Response> {
    if matches!(t.role, TokenRole::Service) {
        Ok(())
    } else {
        Err(json_error_with_aliases(
            StatusCode::FORBIDDEN,
            "WRITE_DENIED",
            &["SERVICE_REQUIRED"],
            "service token required",
        ))
    }
}

/// Map a registry refusal onto its HTTP shape. One function so REST cannot
/// drift from the MCP face (T6), which reports the same codes.
fn policy_error_response(e: &FilePolicyError) -> Response {
    let status = match e {
        FilePolicyError::NotFound(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_REQUEST,
    };
    json_error(status, e.code(), &e.message())
}

/// PUT `/t/<id>/file-policies` — register or replace one prefix rule.
pub async fn put_file_policy(
    Extension(t): Extension<TenantRef>,
    Path(_tenant): Path<String>,
    Json(row): Json<FilePolicyRow>,
) -> Response {
    if let Err(resp) = require_service(&t) {
        return resp;
    }
    // Validate BEFORE taking the writer lock: it is pure, and a refusal must
    // leave no row behind.
    if let Err(e) = validate_file_policy(&row) {
        return policy_error_response(&e);
    }
    match t
        .pool
        .with_writer(move |c| upsert_file_policy(c, &row))
        .await
    {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}

/// GET `/t/<id>/file-policies` — every registered prefix rule.
pub async fn list_file_policies(
    Extension(t): Extension<TenantRef>,
    Path(_tenant): Path<String>,
) -> Response {
    if let Err(resp) = require_service(&t) {
        return resp;
    }
    match t.pool.with_reader(load_file_policies).await {
        Ok(policies) => Json(json!({ "policies": policies })).into_response(),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct ClearQuery {
    /// Required, and `?prefix=` (empty) is a legitimate value: it names the
    /// tenant root. `None` = the parameter was omitted, which is a 400 — never
    /// an implicit root clear.
    pub prefix: Option<String>,
}

/// DELETE `/t/<id>/file-policies?prefix=<prefix>` — clear one prefix rule.
pub async fn clear_file_policy(
    Extension(t): Extension<TenantRef>,
    Path(_tenant): Path<String>,
    Query(q): Query<ClearQuery>,
) -> Response {
    if let Err(resp) = require_service(&t) {
        return resp;
    }
    let Some(prefix) = q.prefix else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "MISSING_PARAM",
            "prefix is required (use ?prefix= for the tenant root)",
        );
    };
    let for_error = prefix.clone();
    match t
        .pool
        .with_writer(move |c| delete_file_policy(c, &prefix))
        .await
    {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        Ok(false) => policy_error_response(&FilePolicyError::NotFound(for_error)),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}
