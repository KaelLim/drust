//! User and anon credentials get no MCP: the account-level endpoint accepts
//! MCP OAuth access tokens only.

use axum::http::StatusCode;

mod helpers;

async fn refused(h: &helpers::AccountMcpHarness, bearer: &str) {
    let auth = format!("Bearer {bearer}");
    let (status, headers, body) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[("authorization", auth.as_str())],
        Some(helpers::mcp_init("2025-06-18")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "MCP_OAUTH_REQUIRED");
    let www = headers["www-authenticate"].to_str().unwrap();
    assert!(www.contains("error=\"invalid_token\""), "{www}");
}

#[tokio::test]
async fn mcp_rejects_user_token() {
    let h = helpers::spin_up_account_mcp("t-mcp1").await;
    helpers::account_allow_self_register(&h).await;
    let user =
        helpers::register_and_login_via_app(&h.app, &h.tid, "u1@example.test", "pw-123456").await;
    assert!(
        user.starts_with(concat!("drust_", "user_")),
        "a real user session token"
    );
    refused(&h, &user).await;
}

#[tokio::test]
async fn mcp_rejects_anon_tenant_key() {
    let h = helpers::spin_up_account_mcp("t-mcp2").await;
    refused(&h, &h.anon).await;
}
