//! v1.27 — Route handlers for /openapi.json, /types.ts, /zod.ts.

use crate::auth::middleware::AuthCtx;
use crate::codegen::{build_ir, openapi, typescript, zod};
use crate::error::json_error;
use crate::tenant::router::TenantRef;
use axum::extract::{Extension, Path};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

const HDR_SOURCE: &str = "X-Drust-Schema-Source";

fn base_url() -> String {
    std::env::var("DRUST_PUBLIC_URL").unwrap_or_else(|_| "http://localhost".into())
}

fn source_value(ctx: &AuthCtx) -> &'static str {
    match ctx {
        AuthCtx::Service { .. } => "service",
        AuthCtx::Anon | AuthCtx::User { .. } => "anon",
    }
}

pub async fn openapi_handler(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path(tenant_id): Path<String>,
) -> Response {
    let include = matches!(ctx, AuthCtx::Service { .. });
    match build_ir(&t.pool, &tenant_id, &base_url(), include).await {
        Ok(ir) => {
            let body = openapi::render_openapi(&ir);
            let mut r = axum::Json(body).into_response();
            r.headers_mut()
                .insert(HDR_SOURCE, HeaderValue::from_static(source_value(&ctx)));
            r
        }
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SCHEMA_RENDER_FAILED",
            &e.to_string(),
        ),
    }
}

pub async fn types_handler(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path(tenant_id): Path<String>,
) -> Response {
    let include = matches!(ctx, AuthCtx::Service { .. });
    match build_ir(&t.pool, &tenant_id, &base_url(), include).await {
        Ok(ir) => {
            let body = typescript::render_typescript(&ir);
            let mut r = (StatusCode::OK, body).into_response();
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/typescript"),
            );
            r.headers_mut()
                .insert(HDR_SOURCE, HeaderValue::from_static(source_value(&ctx)));
            r
        }
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SCHEMA_RENDER_FAILED",
            &e.to_string(),
        ),
    }
}

pub async fn zod_handler(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path(tenant_id): Path<String>,
) -> Response {
    let include = matches!(ctx, AuthCtx::Service { .. });
    match build_ir(&t.pool, &tenant_id, &base_url(), include).await {
        Ok(ir) => {
            let body = zod::render_zod(&ir);
            let mut r = (StatusCode::OK, body).into_response();
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/typescript"),
            );
            r.headers_mut()
                .insert(HDR_SOURCE, HeaderValue::from_static(source_value(&ctx)));
            r
        }
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SCHEMA_RENDER_FAILED",
            &e.to_string(),
        ),
    }
}
