use crate::auth::middleware::AuthCtx;
use crate::error::json_error;
use crate::storage::schema::{DmlVerb, is_protected_collection};
use crate::tenant::events::{Event, EventBus};
use crate::tenant::router::TenantRef;
use axum::Extension;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

/// Per-event anon SELECT filter (#950 T5c), owned so it can move into the
/// stream closure. Derived from the shared `select_read_access` classifier so
/// the clause-less deny stays in lockstep with the SQL read faces.
enum AnonSelectFilter {
    /// No select policy (or service): every event passes.
    PassAll,
    /// A clause-less (deny-all) select policy: every event is dropped.
    DenyAll,
    /// A `using` clause: filter each event's record in memory.
    Using(crate::query::vector_filter::FilterAst),
}

pub async fn subscribe_handler(
    bus: EventBus,
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((tenant, coll)): Path<(String, String)>,
) -> Response {
    // 1. Protected (_system_*) collections never broadcast and do not
    //    leak existence — 404, matches /records/* behaviour.
    if is_protected_collection(&coll) {
        return json_error(StatusCode::NOT_FOUND, "NOT_FOUND", "collection not found")
            .into_response();
    }
    // 2. Load the cached schema. Missing collection → 404.
    let pool = t.pool.clone();
    let coll_owned = coll.clone();
    let cache = pool.schema_cache.clone();
    let schema = match pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return json_error(StatusCode::NOT_FOUND, "NOT_FOUND", "collection not found")
                .into_response();
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SCHEMA_READ_ERROR",
                &e.to_string(),
            )
            .into_response();
        }
    };
    // 3. Toggle off → every auth kind gets 403 REALTIME_DISABLED.
    if !schema.realtime_enabled {
        return json_error(
            StatusCode::FORBIDDEN,
            "REALTIME_DISABLED",
            "SSE broadcast is disabled for this collection",
        )
        .into_response();
    }
    // 4. User tokens are always denied — mirrors /query and /mcp policy.
    if matches!(ctx, AuthCtx::User { .. }) {
        return json_error(
            StatusCode::FORBIDDEN,
            "SSE_USER_DENIED",
            "user tokens cannot subscribe to SSE; use a BFF holding the \
             service or anon token",
        )
        .into_response();
    }
    // 5. Anon needs anon_caps[select] in addition to realtime_enabled.
    if matches!(ctx, AuthCtx::Anon) && !schema.anon_caps.contains(&DmlVerb::Select) {
        return json_error(
            StatusCode::FORBIDDEN,
            "REALTIME_ANON_DENIED",
            "anon token lacks select capability for this collection",
        )
        .into_response();
    }
    // 6. Anon on an owner-scoped collection has no user_id to filter Created/
    //    Updated events by, so it must not subscribe at all — mirrors the REST
    //    read deny (require_dml_cap). BUG-1 (audit 2026-06-22): deny on ANY
    //    owner_field regardless of read_scope — the previous `read_scope=="own"`
    //    narrowing let anon subscribe to an owner-scoped read_scope="all"
    //    collection and receive every owner's events (no policy → no per-event
    //    filter). Now matches POST /list and the documented invariant.
    if matches!(ctx, AuthCtx::Anon) && schema.owner_field.is_some() {
        return json_error(
            StatusCode::FORBIDDEN,
            "ANON_FORBIDDEN_OWNER_SCOPED",
            "anon cannot subscribe to an owner-scoped collection; register a user",
        )
        .into_response();
    }

    // Pass — open the stream.
    //
    // Anon subscribers are filtered per-event by the select-policy USING
    // (auth_id = None). Service bypasses; users are denied above. Deleted
    // events (id-only, no record) are DROPPED when a policy is active (audit
    // F3) — they can't be policy-evaluated and would leak deletion id/timing
    // for hidden rows; with no policy they pass through as before.
    //
    // #950 T5c — the three-state comes from the SHARED `select_read_access`
    // classifier the SQL read faces use, so a clause-less (deny-all) select
    // policy hides every event here too, in lockstep with `policy_using_sql`.
    let anon_select = if matches!(ctx, AuthCtx::Anon) {
        match crate::query::policy::select_read_access(&ctx, &schema) {
            crate::query::policy::SelectReadAccess::Unrestricted => AnonSelectFilter::PassAll,
            crate::query::policy::SelectReadAccess::Filtered(ast) => {
                AnonSelectFilter::Using(ast.clone())
            }
            crate::query::policy::SelectReadAccess::DenyAll => AnonSelectFilter::DenyAll,
        }
    } else {
        AnonSelectFilter::PassAll
    };
    let rx = bus.subscribe(&tenant, &coll);
    let stream = BroadcastStream::new(rx)
        .filter_map(|r| r.ok())
        .filter(move |ev: &Event| match &anon_select {
            // No select policy (or service): everything passes, as before.
            AnonSelectFilter::PassAll => true,
            // A clause-less (deny-all) select policy hides every row, so drop
            // every event — including Deleted (F3 covers it a fortiori).
            AnonSelectFilter::DenyAll => false,
            AnonSelectFilter::Using(using) => match ev {
                Event::Created { record } | Event::Updated { record } => {
                    let map = record.as_object().cloned().unwrap_or_default();
                    crate::query::policy::eval_policy(
                        using,
                        &map,
                        &crate::query::policy::PolicyCtx {
                            auth_id: None,
                            data: None,
                        },
                    )
                }
                // F3 (audit 2026-06-22) — a Deleted event carries only the id,
                // so the select policy cannot be evaluated against the
                // (now-gone) row. Drop it rather than leak deletion id/timing
                // for policy-hidden rows.
                Event::Deleted { .. } => false,
            },
        })
        .map(to_sse_event);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(30)))
        .into_response()
}

fn to_sse_event(ev: Event) -> Result<SseEvent, Infallible> {
    let data = match &ev {
        Event::Created { record } | Event::Updated { record } => {
            serde_json::json!({ "record": record })
        }
        Event::Deleted { id } => serde_json::json!({ "id": id }),
    };
    Ok(SseEvent::default().event(ev.name()).data(data.to_string()))
}
