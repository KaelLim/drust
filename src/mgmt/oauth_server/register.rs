//! RFC 7591 Dynamic Client Registration.
//!
//! Public endpoint — no auth required (that's the point of DCR). Rate-limited
//! at 10 per IP per hour to prevent bulk client-ID minting.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::error::json_error;
use crate::mgmt::oauth_server::storage;
use crate::mgmt::routes::MgmtState;
use crate::safety::audit::AuditEntry;

#[derive(Deserialize)]
pub struct RegisterBody {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    // RFC 7591 fields accepted but ignored — we always return our fixed values.
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResp {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: &'static str,
    pub grant_types: Vec<&'static str>,
    pub response_types: Vec<&'static str>,
}

fn validate_redirect_uri(uri: &str) -> Result<(), &'static str> {
    if uri.starts_with("https://") {
        return Ok(());
    }
    if uri.starts_with("http://localhost")
        || uri.starts_with("http://127.0.0.1")
        || uri.starts_with("http://[::1]")
    {
        return Ok(());
    }
    Err("redirect_uri must be https:// or http://localhost(:port)")
}

pub async fn register_client(
    State(s): State<MgmtState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Response {
    // Resolve client IP using drust's standard pattern (second-from-right XFF).
    let fallback_addr: std::net::SocketAddr =
        std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr);

    if !s.oauth_register_rl.check(ip) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "OAUTH_CLIENT_REGISTRATION_RATE_LIMIT",
            "max 10 registrations per IP per hour",
        );
    }

    if body.client_name.is_empty() || body.client_name.len() > 256 {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_CLIENT",
            "client_name 1-256 chars",
        );
    }
    if body.redirect_uris.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REDIRECT_URI",
            "at least one redirect_uri required",
        );
    }
    for u in &body.redirect_uris {
        if let Err(reason) = validate_redirect_uri(u) {
            return json_error(StatusCode::BAD_REQUEST, "INVALID_REDIRECT_URI", reason);
        }
    }

    let client_id = storage::new_client_id();
    let redirect_uris_json = serde_json::to_string(&body.redirect_uris).unwrap();
    {
        let conn = s.meta.lock().await;
        if let Err(e) = conn.execute(
            "INSERT INTO _oauth_clients (id, client_name, redirect_uris_json, created_by_admin_id)
             VALUES (?1, ?2, ?3, NULL)",
            params![&client_id, &body.client_name, &redirect_uris_json],
        ) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    }

    let entry = AuditEntry::success("-", "-", "admin.oauth.client_register", 0).with_extra(
        serde_json::json!({
            "client_id": &client_id,
            "client_name": &body.client_name,
            "source": "dynamic",
        }),
    );
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    (
        StatusCode::CREATED,
        Json(RegisterResp {
            client_id,
            client_name: body.client_name,
            redirect_uris: body.redirect_uris,
            token_endpoint_auth_method: "none",
            grant_types: vec!["authorization_code", "refresh_token"],
            response_types: vec!["code"],
        }),
    )
        .into_response()
}
