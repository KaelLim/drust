use crate::tenant::events::{Event, EventBus};
use crate::tenant::router::TenantRef;
use axum::extract::Path;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::Extension;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

pub async fn subscribe_handler(
    bus: EventBus,
    Extension(t): Extension<TenantRef>,
    Path((tenant, coll)): Path<(String, String)>,
) -> impl IntoResponse {
    let _ = &t;
    let rx = bus.subscribe(&tenant, &coll);
    let stream = BroadcastStream::new(rx).filter_map(|r| r.ok()).map(to_sse_event);
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(30)))
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
