//! RLS Phase 8 (Config) — service-only REST surface for per-collection,
//! per-operation row-level-security policies.
//!
//! `PUT/GET /t/<id>/collections/<c>/policies` replace / read the policy set;
//! `DELETE /t/<id>/collections/<c>/policies/<op>` clears one op's policy.
//!
//! These routes live on the `core` router (which is NOT wrapped by
//! `require_service_layer`), so each handler enforces service-only inline via
//! `TenantRef.role` — exactly like the sibling collection-meta routes
//! (`realtime_routes::put_realtime_handler`, `owner_field::set_owner_field_handler`).
//! Existence + validation run INSIDE the writer closure (TOCTOU-safe, mirrors
//! `set_anon_caps` / `set_owner_field`).

use crate::error::{json_error, json_error_with_aliases};
use crate::query::policy::{Policy, validate_policy};
use crate::storage::schema::{DmlVerb, is_protected_collection};
use crate::tenant::router::{TenantRef, TokenRole};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct PutPoliciesBody {
    #[serde(default)]
    pub select: Option<Policy>,
    #[serde(default)]
    pub insert: Option<Policy>,
    #[serde(default)]
    pub update: Option<Policy>,
    #[serde(default)]
    pub delete: Option<Policy>,
}

/// Service-only gate, matching the sibling `realtime` route's 403 shape.
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

/// PUT `/t/<id>/collections/<c>/policies` — replace the policy set. Service-only.
pub async fn put_policies(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(body): Json<PutPoliciesBody>,
) -> Response {
    if let Err(resp) = require_service(&t) {
        return resp;
    }
    if is_protected_collection(&coll) {
        return json_error(
            StatusCode::NOT_FOUND,
            "COLLECTION_NOT_FOUND",
            "no such collection",
        );
    }
    let pool = t.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_c = coll.clone();
    let res = pool
        .with_writer(move |c| {
            // Existence + validation INSIDE the writer closure (TOCTOU-safe,
            // mirrors set_anon_caps / set_owner_field).
            let schema = match crate::storage::schema::describe_collection(c, &coll_c)? {
                Some(s) => s,
                None => {
                    return Ok(Err((
                        "COLLECTION_NOT_FOUND",
                        "no such collection".to_string(),
                    )));
                }
            };
            for (op, p) in [
                (DmlVerb::Select, &body.select),
                (DmlVerb::Insert, &body.insert),
                (DmlVerb::Update, &body.update),
                (DmlVerb::Delete, &body.delete),
            ] {
                if let Some(policy) = p {
                    if let Err(e) = validate_policy(&schema, op, policy) {
                        return Ok(Err(("POLICY_INVALID", e.to_string())));
                    }
                }
                crate::storage::schema::write_policy(c, &coll_c, op, p.as_ref())?;
            }
            Ok(Ok(()))
        })
        .await;
    cache.invalidate(&coll);
    match res {
        Ok(Ok(())) => Json(json!({"ok": true})).into_response(),
        Ok(Err((code, msg))) => json_error(
            if code == "COLLECTION_NOT_FOUND" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            },
            code,
            &msg,
        ),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}

/// GET `/t/<id>/collections/<c>/policies` — stored policy set. Service-only.
pub async fn get_policies(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = require_service(&t) {
        return resp;
    }
    let pool = t.pool.clone();
    let coll_c = coll.clone();
    let out = pool
        .with_reader(move |c| crate::storage::schema::read_policies(c, &coll_c))
        .await;
    match out {
        Ok(p) => Json(json!({ "stored": p })).into_response(),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}

/// DELETE `/t/<id>/collections/<c>/policies/<op>` — clear one op's policy.
/// Service-only.
pub async fn delete_policy(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll, op)): Path<(String, String, String)>,
) -> Response {
    if let Err(resp) = require_service(&t) {
        return resp;
    }
    let verb = match op.as_str() {
        "select" => DmlVerb::Select,
        "insert" => DmlVerb::Insert,
        "update" => DmlVerb::Update,
        "delete" => DmlVerb::Delete,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "BAD_OP",
                "op must be select|insert|update|delete",
            );
        }
    };
    let pool = t.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_c = coll.clone();
    let res = pool
        .with_writer(move |c| crate::storage::schema::write_policy(c, &coll_c, verb, None))
        .await;
    cache.invalidate(&coll);
    match res {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}
