pub mod collections;
pub mod events;
pub mod mcp_dispatch;
pub mod query_endpoint;
pub mod records;
pub mod router;
pub mod sse;

use crate::mcp::http_registry::McpHttpRegistry;
use axum::Router;
use axum::routing::{any, get, post};
use events::EventBus;
use router::TenantAuthState;
use std::sync::Arc;

#[derive(Clone)]
pub struct TenantStack {
    pub auth: TenantAuthState,
    pub bus: EventBus,
    pub mcp: Arc<McpHttpRegistry>,
}

pub fn build_tenant_router(state: TenantStack) -> Router {
    let auth_state = state.auth.clone();
    let bus = state.bus.clone();
    let mcp = state.mcp.clone();

    Router::new()
        .route("/t/{tenant}/collections", get(collections::list_handler))
        .route(
            "/t/{tenant}/collections/{coll}",
            get(collections::describe_handler),
        )
        .route(
            "/t/{tenant}/records/{coll}",
            get(records::list_handler).post({
                let b = bus.clone();
                move |ext, p, body| records::create_handler(ext, p, body, b.clone())
            }),
        )
        .route(
            "/t/{tenant}/records/{coll}/{id}",
            get(records::get_handler)
                .patch({
                    let b = bus.clone();
                    move |ext, p, body| records::update_handler(ext, p, body, b.clone())
                })
                .delete({
                    let b = bus.clone();
                    move |ext, p| records::delete_handler(ext, p, b.clone())
                }),
        )
        .route(
            "/t/{tenant}/records/{coll}/subscribe",
            get({
                let b = bus.clone();
                move |ext, path| sse::subscribe_handler(b.clone(), ext, path)
            }),
        )
        .route("/t/{tenant}/query", post(query_endpoint::query_handler))
        .route(
            "/t/{tenant}/mcp",
            any({
                let mcp = mcp.clone();
                move |ext, path, req| mcp_dispatch::dispatch(mcp.clone(), ext, path, req)
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            router::bearer_auth_layer,
        ))
        .with_state(auth_state)
}
