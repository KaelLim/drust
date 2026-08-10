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
use crate::tenant::events::EventBus;
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
    Path((tenant, coll)): Path<(String, String)>,
    Json(body): Json<PutPoliciesBody>,
    bus: EventBus,
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
            // (audit3 F2) If this PUT attaches any policy, refuse it while an
            // anon-callable RPC references this collection — call_rpc applies no
            // RLS policy to stored-RPC SQL, so the RPC would leak policy-hidden
            // rows. Runs before any write_policy (autocommit path).
            let attaching = body.select.is_some()
                || body.insert.is_some()
                || body.update.is_some()
                || body.delete.is_some();
            if attaching
                && let Err(e) =
                    crate::rpc::prepare::guard_policy_change_against_anon_rpcs(c, &coll_c)
            {
                return Ok(Err(("RPC_ANON_OWNER_SCOPED", e.to_string())));
            }
            // Validate the SELECT policy AHEAD of the grant guard below, so a
            // malformed one (notably the clause-less `{"select":{}}`) reports
            // its own shape error rather than the guard's — whose remedy
            // ("disarm the RPC") would not fix it. Pure and idempotent, so the
            // loop below re-running it costs nothing.
            if let Some(p) = &body.select
                && let Err(e) = validate_policy(&schema, DmlVerb::Select, p)
            {
                return Ok(Err(("POLICY_INVALID", e.to_string())));
            }
            // #950 — a PUT REPLACES the set, so an OMITTED `select` clears a
            // stored select policy. That is the same widening
            // `DELETE /policies/select` is guarded against, reached by another
            // verb: guarding only the DELETE would leave this door open, and
            // `validate_policy` cannot see it (it is never called on an absent
            // policy). Keyed on the effective USING clause, so a clause-less
            // legacy row is judged by what it actually filters.
            if let Err(e) = crate::rpc::prepare::guard_select_policy_clear(
                c,
                &coll_c,
                body.select
                    .as_ref()
                    .and_then(|p| p.using.as_ref())
                    .is_some(),
            ) {
                return Ok(Err(("RPC_QUERY_GRANT_ACTIVE", e.to_string())));
            }
            for (op, p) in [
                (DmlVerb::Select, &body.select),
                (DmlVerb::Insert, &body.insert),
                (DmlVerb::Update, &body.update),
                (DmlVerb::Delete, &body.delete),
            ] {
                if let Some(policy) = p
                    && let Err(e) = validate_policy(&schema, op, policy)
                {
                    return Ok(Err(("POLICY_INVALID", e.to_string())));
                }
                crate::storage::schema::write_policy(c, &coll_c, op, p.as_ref())?;
            }
            Ok(Ok(()))
        })
        .await;
    cache.invalidate(&coll);
    // audit3 F3 — drop in-flight anon SSE subscribers so they reconnect and
    // re-gate against the new policy set (mirrors put_realtime's evict).
    bus.evict_collection(&tenant, &coll);
    match res {
        Ok(Ok(())) => Json(json!({"ok": true})).into_response(),
        Ok(Err((code, msg))) => json_error(
            match code {
                "COLLECTION_NOT_FOUND" => StatusCode::NOT_FOUND,
                "RPC_ANON_OWNER_SCOPED" | "RPC_QUERY_GRANT_ACTIVE" => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
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
    Path((tenant, coll, op)): Path<(String, String, String)>,
    bus: EventBus,
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
        .with_writer(move |c| {
            // #950 — clearing the SELECT policy WIDENS every anon-callable
            // query-kind RPC over this collection (its grant goes from "the
            // policy's rows" to "the whole table"). Refuse until the RPC is
            // disarmed; the other verbs do not gate reads, so their clears are
            // untouched. `new_using_present = false` (a clear leaves no
            // filter); the shared helper no-ops when there was none to lose,
            // so clearing an absent policy is not a spurious refusal. Before
            // the write — this path is autocommit.
            if verb == DmlVerb::Select
                && let Err(e) = crate::rpc::prepare::guard_select_policy_clear(c, &coll_c, false)
            {
                return Ok(Err(("RPC_QUERY_GRANT_ACTIVE", e.to_string())));
            }
            crate::storage::schema::write_policy(c, &coll_c, verb, None)?;
            Ok(Ok(()))
        })
        .await;
    cache.invalidate(&coll);
    // audit3 F3 — evict in-flight anon SSE subscribers so they reconnect and
    // re-gate against the cleared policy.
    bus.evict_collection(&tenant, &coll);
    match res {
        Ok(Ok(())) => Json(json!({"ok": true})).into_response(),
        Ok(Err((code, msg))) => json_error(StatusCode::CONFLICT, code, &msg),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}
