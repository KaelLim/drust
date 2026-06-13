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

    // Pass — open the stream.
    //
    // Anon subscribers are filtered per-event by the select-policy USING
    // (auth_id = None). Service bypasses; users are denied above. Deleted
    // events (id-only, no record) always pass — documented v1 limitation.
    let select_using: Option<crate::query::vector_filter::FilterAst> =
        if matches!(ctx, AuthCtx::Anon) {
            schema.policies.select.as_ref().and_then(|p| p.using.clone())
        } else {
            None
        };
    let rx = bus.subscribe(&tenant, &coll);
    let stream = BroadcastStream::new(rx)
        .filter_map(|r| r.ok())
        .filter(move |ev: &Event| match (&select_using, ev) {
            (Some(using), Event::Created { record }) | (Some(using), Event::Updated { record }) => {
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
            _ => true,
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
