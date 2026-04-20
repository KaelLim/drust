pub mod collections;
pub mod events;
pub mod router;

use axum::routing::get;
use axum::Router;
use events::EventBus;
use router::TenantAuthState;

#[derive(Clone)]
pub struct TenantStack {
    pub auth: TenantAuthState,
    pub bus: EventBus,
}

pub fn build_tenant_router(state: TenantStack) -> Router {
    let auth_state = state.auth.clone();
    Router::new()
        .route("/t/{tenant}/collections", get(collections::list_handler))
        .route(
            "/t/{tenant}/collections/{coll}",
            get(collections::describe_handler),
        )
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            router::bearer_auth_layer,
        ))
        .with_state(auth_state)
}
