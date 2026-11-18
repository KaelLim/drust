//! Upload-ticket redemption on the tus routes, end to end. No audit writer
//! here: audit-row assertions live in the `mcp_account_audit` target.
#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use drust::mgmt::mcp_oauth::store::TicketRequest;
use helpers::{AccountMcpHarness, seed_upload_ticket, spin_up_ticket_harness};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const MSG: &str = "invalid or expired upload ticket";

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// A tus `Upload-Metadata` value from key/value pairs.
fn md(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k} {}", b64(v)))
        .collect::<Vec<_>>()
        .join(",")
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    headers: &[(&str, String)],
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("tus-resumable", "1.0.0");
    if let Some(t) = bearer {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in headers {
        b = b.header(*k, v.as_str());
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let hd = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, hd, v)
}

async fn ticket(h: &AccountMcpHarness, max: i64, path: Option<&str>, public: bool) -> String {
    seed_upload_ticket(
        &h.meta,
        &h.access,
        &TicketRequest {
            tenant_id: "acme",
            max_bytes: max,
            path,
            public,
        },
    )
    .await
}

async fn create(
    h: &AccountMcpHarness,
    t: &str,
    len: i64,
    meta: &str,
) -> (StatusCode, HeaderMap, Value) {
    let mut hs = vec![("upload-length", len.to_string())];
    if !meta.is_empty() {
        hs.push(("upload-metadata", meta.to_string()));
    }
    send(&h.app, "POST", "/t/acme/uploads", Some(t), &hs, vec![]).await
}

fn tok_of(hd: &HeaderMap) -> String {
    hd.get("location")
        .expect("a Location")
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string()
}

async fn patch(
    h: &AccountMcpHarness,
    bearer: &str,
    tok: &str,
    offset: usize,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Value) {
    send(
        &h.app,
        "PATCH",
        &format!("/t/acme/uploads/{tok}"),
        Some(bearer),
        &[
            ("upload-offset", offset.to_string()),
            (
                "content-type",
                "application/offset+octet-stream".to_string(),
            ),
        ],
        body,
    )
    .await
}

fn tenant_conn(h: &AccountMcpHarness, tenant: &str) -> rusqlite::Connection {
    drust::storage::tenant_db::open_write(h.tenants.data_root(), tenant).unwrap()
}

/// `(path, visibility, uploader)` of every `_system_files` row.
fn file_rows(h: &AccountMcpHarness) -> Vec<(Option<String>, String, String)> {
    let c = tenant_conn(h, "acme");
    let mut st = c
        .prepare("SELECT path, visibility, uploader FROM _system_files ORDER BY rowid")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// A tus session made with the tenant's service key; its token.
async fn svc_session(h: &AccountMcpHarness) -> String {
    let (s, hd, _) = send(
        &h.app,
        "POST",
        "/t/acme/uploads",
        Some(&h.svc),
        &[("upload-length", "4".into())],
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    tok_of(&hd)
}

#[tokio::test]
async fn ticket_on_files_route_gets_the_ticket_401() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 10, None, false).await;
    let (s, _, v) = send(&h.app, "POST", "/t/acme/files", Some(&t), &[], vec![]).await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(MSG))
    );
}

#[tokio::test]
async fn disabled_server_answers_a_ticket_exactly_as_today() {
    let h = spin_up_ticket_harness(&["acme"], false).await;
    let t = ticket(&h, 10, None, false).await;
    let (s, _, v) = send(
        &h.app,
        "POST",
        "/t/acme/uploads",
        Some(&t),
        &[("upload-length", "1".into())],
        vec![],
    )
    .await;
    assert_eq!(
        (s, v["error_code"].as_str(), v["message"].as_str()),
        (
            StatusCode::UNAUTHORIZED,
            Some("UNAUTHENTICATED"),
            Some("invalid token")
        )
    );
}

#[tokio::test]
async fn ticket_never_reaches_non_tus_file_routes() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 10, None, false).await;
    for (m, u) in [
        ("GET", "/t/acme/files"),
        ("GET", "/t/acme/files/k"),
        ("DELETE", "/t/acme/files/k"),
        ("PATCH", "/t/acme/files/k"),
        ("GET", "/t/acme/files/k/bytes"),
        ("POST", "/t/acme/files/k/sign"),
        ("GET", "/t/acme/uploads"),
        ("OPTIONS", "/t/acme/uploads"),
    ] {
        let (s, _, v) = send(&h.app, m, u, Some(&t), &[], vec![]).await;
        assert_eq!(
            (s, v["message"].as_str()),
            (StatusCode::UNAUTHORIZED, Some(MSG)),
            "{m} {u}"
        );
    }
    // Served by the GET route; a HEAD body may be stripped, so status only.
    let (s, _, _) = send(&h.app, "HEAD", "/t/acme/uploads", Some(&t), &[], vec![]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ticket_on_sse_and_rooms_is_rejected() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 10, None, false).await;
    for u in ["/t/acme/records/c/subscribe", "/t/acme/realtime"] {
        let (s, _, _) = send(&h.app, "GET", u, Some(&t), &[], vec![]).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{u}");
    }
}

#[tokio::test]
async fn ticket_to_unknown_path_is_still_404() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 10, None, false).await;
    let (s, _, _) = send(&h.app, "GET", "/t/acme/nope", Some(&t), &[], vec![]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn service_key_whose_body_starts_with_upl_uses_the_bearer_stack() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    // 49 bytes like every tenant key (`drust_` + 43), so not a ticket's shape.
    let key = format!("drust_upl_{}", "A".repeat(39));
    assert_eq!(key.len(), 49);
    {
        let g = h.meta.lock().await;
        g.execute(
            "INSERT INTO tokens (tenant_id, token_hash, role) VALUES ('acme', ?1, 'service')",
            [drust::auth::bearer::hash_token(&key)],
        )
        .unwrap();
    }
    let (s, _, _) = send(&h.app, "GET", "/t/acme/uploads", Some(&key), &[], vec![]).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn full_ticket_upload_finalizes_as_service() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 10, Some("docs/a.txt"), true).await;
    let (s, hd, _) = create(
        &h,
        &t,
        10,
        &md(&[
            ("filename", "a.txt"),
            ("path", "docs/a.txt"),
            ("visibility", "public"),
        ]),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let tok = tok_of(&hd);
    assert_eq!(
        patch(&h, &t, &tok, 0, b"hello".to_vec()).await.0,
        StatusCode::NO_CONTENT
    );
    let (s, hd, _) = send(
        &h.app,
        "HEAD",
        &format!("/t/acme/uploads/{tok}"),
        Some(&t),
        &[],
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hd.get("upload-offset").unwrap(), "5");
    assert_eq!(
        patch(&h, &t, &tok, 5, b"world".to_vec()).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        file_rows(&h),
        vec![(
            Some("docs/a.txt".to_string()),
            "public".to_string(),
            "service".to_string()
        )]
    );
}

#[tokio::test]
async fn private_ticket_upload_finalizes_private() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    let (s, hd, _) = create(&h, &t, 4, &md(&[("visibility", "private")])).await;
    assert_eq!(s, StatusCode::CREATED);
    let tok = tok_of(&hd);
    assert_eq!(
        patch(&h, &t, &tok, 0, b"abcd".to_vec()).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        file_rows(&h),
        vec![(None, "private".to_string(), "service".to_string())]
    );
}

#[tokio::test]
async fn second_create_is_refused() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    assert_eq!(create(&h, &t, 4, "").await.0, StatusCode::CREATED);
    let (s, _, v) = create(&h, &t, 4, "").await;
    assert_eq!(
        (s, v["error_code"].as_str()),
        (StatusCode::CONFLICT, Some("UPLOAD_TICKET_USED"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_creates_bind_exactly_one() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let app = h.app.clone();
        let t = t.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            send(
                &app,
                "POST",
                "/t/acme/uploads",
                Some(&t),
                &[("upload-length", "4".into())],
                vec![],
            )
            .await
            .0
        }));
    }
    let mut got = Vec::new();
    for task in tasks {
        got.push(task.await.unwrap().as_u16());
    }
    got.sort();
    assert_eq!(got, vec![201, 409]);
}

#[tokio::test]
async fn failed_create_releases_the_claim() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    let (s, _, v) = send(&h.app, "POST", "/t/acme/uploads", Some(&t), &[], vec![]).await;
    assert_eq!(
        (s, v["error_code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("UPLOAD_LENGTH_REQUIRED"))
    );
    assert_eq!(create(&h, &t, 4, "").await.0, StatusCode::CREATED);
}

#[tokio::test]
async fn upload_length_over_ticket_is_413() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 10, None, false).await;
    let with_len = |len: &str| vec![("upload-length", len.to_string())];
    for (len, want, code) in [
        ("11", StatusCode::PAYLOAD_TOO_LARGE, "UPLOAD_TOO_LARGE"),
        ("+11", StatusCode::PAYLOAD_TOO_LARGE, "UPLOAD_TOO_LARGE"),
        (" 10", StatusCode::BAD_REQUEST, "UPLOAD_LENGTH_REQUIRED"),
    ] {
        let (s, _, v) = send(
            &h.app,
            "POST",
            "/t/acme/uploads",
            Some(&t),
            &with_len(len),
            vec![],
        )
        .await;
        assert_eq!((s, v["error_code"].as_str()), (want, Some(code)), "{len:?}");
    }
    assert_eq!(create(&h, &t, 10, "").await.0, StatusCode::CREATED);
}

#[tokio::test]
async fn metadata_mismatch_is_400() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let mismatch = |v: &Value| v["error_code"].as_str() == Some("UPLOAD_TICKET_MISMATCH");

    let t = ticket(&h, 4, Some("docs/a"), false).await;
    for meta in [
        md(&[("path", "docs/b")]),
        md(&[("path", "docs/a"), ("visibility", "public")]),
        "path !!!notb64".to_string(),
    ] {
        let (s, _, v) = create(&h, &t, 4, &meta).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{meta}");
        assert!(mismatch(&v), "{meta}: {v}");
    }
    assert_eq!(
        create(&h, &t, 4, &md(&[("path", "docs/a")])).await.0,
        StatusCode::CREATED
    );

    let no_path = ticket(&h, 4, None, false).await;
    let (s, _, v) = create(&h, &no_path, 4, &md(&[("path", "docs/x")])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(mismatch(&v), "{v}");
    assert_eq!(create(&h, &no_path, 4, "").await.0, StatusCode::CREATED);

    let public = ticket(&h, 4, None, true).await;
    let (s, _, v) = create(&h, &public, 4, &md(&[("filename", "a.txt")])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(mismatch(&v), "{v}");
    assert_eq!(
        create(&h, &public, 4, &md(&[("visibility", "public")]))
            .await
            .0,
        StatusCode::CREATED
    );

    let c = tenant_conn(&h, "acme");
    let n: i64 = c
        .query_row(
            "SELECT (SELECT COUNT(*) FROM _system_upload_sessions WHERE path = 'docs/x') \
                  + (SELECT COUNT(*) FROM _system_files WHERE path = 'docs/x')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn ticket_cannot_touch_another_session() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let other = svc_session(&h).await;
    let t = ticket(&h, 4, None, false).await;
    assert_eq!(create(&h, &t, 4, "").await.0, StatusCode::CREATED);
    for m in ["PATCH", "HEAD", "DELETE"] {
        let (s, hd, _) = send(
            &h.app,
            m,
            &format!("/t/acme/uploads/{other}"),
            Some(&t),
            &[("upload-offset", "0".into())],
            vec![],
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{m}");
        assert_eq!(hd.get("tus-resumable").unwrap(), "1.0.0", "{m}");
    }
    let (s, hd, _) = send(
        &h.app,
        "HEAD",
        &format!("/t/acme/uploads/{other}"),
        Some(&h.svc),
        &[],
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hd.get("upload-offset").unwrap(), "0");
}

#[tokio::test]
async fn token_case_variant_is_404() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    let (s, hd, _) = create(&h, &t, 4, "").await;
    assert_eq!(s, StatusCode::CREATED);
    let tok = tok_of(&hd);
    assert_ne!(
        tok,
        tok.to_uppercase(),
        "anti-vacuous: the token has letters"
    );
    let (s, _, _) = send(
        &h.app,
        "HEAD",
        &format!("/t/acme/uploads/{}", tok.to_uppercase()),
        Some(&t),
        &[],
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unbound_or_claimed_ticket_cannot_touch_sessions() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let other = svc_session(&h).await;
    let t = ticket(&h, 4, None, false).await;
    let three = |label: &'static str| {
        let h = &h;
        let t = t.clone();
        let other = other.clone();
        async move {
            for m in ["PATCH", "HEAD", "DELETE"] {
                let (s, hd, _) = send(
                    &h.app,
                    m,
                    &format!("/t/acme/uploads/{other}"),
                    Some(&t),
                    &[("upload-offset", "0".into())],
                    vec![],
                )
                .await;
                assert_eq!(s, StatusCode::NOT_FOUND, "{label} {m}");
                assert_eq!(hd.get("tus-resumable").unwrap(), "1.0.0", "{label} {m}");
            }
        }
    };
    three("unbound").await;
    {
        let g = h.meta.lock().await;
        g.execute(
            "UPDATE _mcp_upload_tickets SET bound_upload = 'creating'",
            [],
        )
        .unwrap();
    }
    three("claimed").await;
    let (s, _, _) = send(
        &h.app,
        "PATCH",
        "/t/acme/uploads/creating",
        Some(&t),
        &[("upload-offset", "0".into())],
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, hd, _) = send(
        &h.app,
        "HEAD",
        &format!("/t/acme/uploads/{other}"),
        Some(&h.svc),
        &[],
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hd.get("upload-offset").unwrap(), "0");
}

#[tokio::test]
async fn patch_chunk_limit_is_chunk_max() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let max = helpers::ACCOUNT_FILES_CHUNK_MAX;
    let total = 7 * 1024 * 1024;
    let t = ticket(&h, total as i64, None, false).await;
    let (s, hd, _) = create(&h, &t, total as i64, "").await;
    assert_eq!(s, StatusCode::CREATED);
    let tok = tok_of(&hd);
    assert_eq!(
        patch(&h, &t, &tok, 0, vec![0u8; max + 1]).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        patch(&h, &t, &tok, 0, vec![0u8; max]).await.0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn tus_calls_through_the_ticket_do_not_deadlock_on_meta() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    let r = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (s, hd, _) = create(&h, &t, 4, "").await;
        assert_eq!(s, StatusCode::CREATED);
        let tok = tok_of(&hd);
        patch(&h, &t, &tok, 0, b"abcd".to_vec()).await.0
    })
    .await;
    assert!(r.is_ok(), "ticket path self-locked meta");
    assert_eq!(r.unwrap(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn ticket_upload_respects_the_tenant_quota() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    {
        let c = tenant_conn(&h, "acme");
        c.execute(
            "INSERT INTO _system_files (key, original_name, size_bytes, uploader) \
             VALUES ('quota-pad', 'pad', 10737418240, 'service')",
            [],
        )
        .unwrap();
    }
    let (s, _, v) = create(&h, &t, 1, "").await;
    assert_eq!(
        (s, v["error_code"].as_str()),
        (
            StatusCode::INSUFFICIENT_STORAGE,
            Some("TENANT_QUOTA_EXCEEDED")
        )
    );
    {
        let c = tenant_conn(&h, "acme");
        c.execute("DELETE FROM _system_files WHERE key = 'quota-pad'", [])
            .unwrap();
    }
    assert_eq!(create(&h, &t, 1, "").await.0, StatusCode::CREATED);
}

#[tokio::test]
async fn non_canonical_scheme_is_not_redeemed() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    for auth in [format!("bearer {t}"), format!("Bearer  {t}")] {
        let req = Request::builder()
            .method("POST")
            .uri("/t/acme/uploads")
            .header("tus-resumable", "1.0.0")
            .header("authorization", auth)
            .header("upload-length", "4")
            .body(Body::empty())
            .unwrap();
        let resp = h.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_ne!(v["message"].as_str(), Some(MSG));
    }
    // Anti-vacuous: the canonical scheme redeems this very ticket.
    assert_eq!(create(&h, &t, 4, "").await.0, StatusCode::CREATED);
}

#[tokio::test]
async fn pool_gone_answers_401_not_404() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    h.tenants.evict("acme");
    std::fs::remove_dir_all(drust::storage::tenant_db::tenant_dir(
        h.tenants.data_root(),
        "acme",
    ))
    .unwrap();
    let (s, _, v) = create(&h, &t, 4, "").await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(MSG))
    );
}

#[tokio::test]
async fn other_tenant_path_is_401() {
    let h = spin_up_ticket_harness(&["acme", "beta"], true).await;
    let t = ticket(&h, 4, None, false).await;
    for u in ["/t/beta/uploads", "/t/nosuch/uploads"] {
        let (s, _, v) = send(
            &h.app,
            "POST",
            u,
            Some(&t),
            &[("upload-length", "4".into())],
            vec![],
        )
        .await;
        assert_eq!(
            (s, v["message"].as_str()),
            (StatusCode::UNAUTHORIZED, Some(MSG)),
            "{u}"
        );
    }
}

/// `n` fresh, well-formed tickets nobody issued, each answered 401.
async fn unknown_misses(h: &AccountMcpHarness, n: usize) {
    use drust::mgmt::mcp_oauth::tokens::{TokenKind, new_token};
    for i in 0..n {
        let u = new_token(TokenKind::UploadTicket);
        let (s, _, v) = create(h, &u, 1, "").await;
        assert_eq!(
            (s, v["message"].as_str()),
            (StatusCode::UNAUTHORIZED, Some(MSG)),
            "miss {i}"
        );
    }
}

/// The next unknown ticket hits the exhausted miss bucket.
async fn assert_miss_limited(h: &AccountMcpHarness) {
    use drust::mgmt::mcp_oauth::tokens::{TokenKind, new_token};
    let u = new_token(TokenKind::UploadTicket);
    let (s, hd, v) = create(h, &u, 1, "").await;
    assert_eq!(
        (s, v["error_code"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("RATE_LIMITED"))
    );
    let secs: u64 = hd["retry-after"].to_str().unwrap().parse().unwrap();
    assert!(secs >= 1);
}

#[tokio::test]
async fn unknown_tickets_charge_the_miss_bucket_and_known_ones_do_not() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let known = ticket(&h, 4, None, false).await;
    {
        let g = h.meta.lock().await;
        g.execute(
            "UPDATE _mcp_upload_tickets SET revoked_at = datetime('now')",
            [],
        )
        .unwrap();
    }
    let (s, _, v) = create(&h, &known, 1, "").await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(MSG))
    );
    unknown_misses(&h, 60).await;
    assert_miss_limited(&h).await;
    let (s, _, v) = create(&h, &known, 1, "").await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(MSG))
    );
}

#[tokio::test]
async fn ticket_misses_do_not_throttle_the_account_endpoint() {
    use drust::mgmt::mcp_oauth::tokens::{TokenKind, new_token};
    let h = spin_up_ticket_harness(&["acme"], true).await;
    unknown_misses(&h, 60).await;
    assert_miss_limited(&h).await;
    // The account-level bearer layer reads no per-IP bucket, so a ticket
    // flood never reaches it. Green by construction; kept as a regression pin.
    let (s, _, _) = helpers::mcp_rpc(
        &h.app,
        Some(&new_token(TokenKind::Access)),
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// A ticket bound to its own 8-byte session: `(ticket, tus token)`.
async fn bound(h: &AccountMcpHarness) -> (String, String) {
    let t = ticket(h, 8, None, false).await;
    let (s, hd, _) = create(h, &t, 8, "").await;
    assert_eq!(s, StatusCode::CREATED);
    (t, tok_of(&hd))
}

async fn meta_exec(h: &AccountMcpHarness, sql: &str) {
    let g = h.meta.lock().await;
    g.execute(sql, []).unwrap();
}

async fn assert_patch_is_401(h: &AccountMcpHarness, t: &str, tok: &str, offset: usize) {
    let (s, _, v) = patch(h, t, tok, offset, b"efgh".to_vec()).await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(MSG))
    );
}

#[tokio::test]
async fn recycled_tenant_id_kills_the_ticket() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    meta_exec(
        &h,
        "UPDATE tenants SET deleted_at = datetime('now') WHERE id = 'acme'",
    )
    .await;
    {
        let mut g = h.meta.lock().await;
        let made = drust::mgmt::tenants::crud::make_tenant_inner(
            &mut g,
            h.tenants.data_root(),
            "acme",
            "Acme 2",
            10,
            1000,
            h.admin_id,
        )
        .unwrap();
        assert!(made.recycled, "anti-vacuous: the id-recycle branch ran");
        let n: i64 = g
            .query_row(
                "SELECT COUNT(*) FROM _mcp_upload_tickets WHERE tenant_id = 'acme'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }
    // What the create route does after the lock: drop the old incarnation's pool.
    h.tenants.evict("acme");
    let (s, _, v) = create(&h, &t, 4, "").await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(MSG))
    );
}

#[tokio::test]
async fn grant_revocation_ends_the_next_patch() {
    use drust::auth::middleware::AdminId;
    use drust::mgmt::mcp_oauth::store::{GrantOwner, RevokeReason, RevokedGrant, revoke_mcp_grant};
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let (t, tok) = bound(&h).await;
    assert_eq!(
        patch(&h, &t, &tok, 0, b"abcd".to_vec()).await.0,
        StatusCode::NO_CONTENT
    );
    {
        let mut g = h.meta.lock().await;
        let tx = g.transaction().unwrap();
        assert_eq!(
            revoke_mcp_grant(
                &tx,
                &GrantOwner::caller(&AdminId(h.admin_id)),
                h.grant_id,
                RevokeReason::User
            )
            .unwrap(),
            RevokedGrant::Revoked
        );
        tx.commit().unwrap();
    }
    assert_patch_is_401(&h, &t, &tok, 4).await;
}

#[tokio::test]
async fn grant_revoked_without_touching_tickets_still_401() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let (t, tok) = bound(&h).await;
    meta_exec(
        &h,
        "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now')",
    )
    .await;
    assert_patch_is_401(&h, &t, &tok, 0).await;
}

#[tokio::test]
async fn removed_admin_ends_the_ticket() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let (t, tok) = bound(&h).await;
    {
        let g = h.meta.lock().await;
        g.execute(
            "DELETE FROM _mcp_oauth_grants WHERE admin_id = ?1",
            [h.admin_id],
        )
        .unwrap();
        g.execute("DELETE FROM admins WHERE id = ?1", [h.admin_id])
            .unwrap();
    }
    assert_patch_is_401(&h, &t, &tok, 0).await;
}

#[tokio::test]
async fn lost_visibility_ends_the_ticket() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let (t, tok) = bound(&h).await;
    meta_exec(&h, "UPDATE admins SET role = 'member'").await;
    meta_exec(&h, "UPDATE tenants SET owner_admin_id = NULL").await;
    assert_patch_is_401(&h, &t, &tok, 0).await;
}

#[tokio::test]
async fn owner_transfer_ends_the_ticket() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let (t, tok) = bound(&h).await;
    {
        let g = h.meta.lock().await;
        g.execute(
            "INSERT INTO admins (username, password_hash, email, role) \
             VALUES ('other-owner', '$oauth-only$', 'o@example.test', 'owner')",
            [],
        )
        .unwrap();
        let other = g.last_insert_rowid();
        g.execute(
            "UPDATE admins SET role = 'member' WHERE id = ?1",
            [h.admin_id],
        )
        .unwrap();
        g.execute(
            "UPDATE tenants SET owner_admin_id = ?1 WHERE id = 'acme'",
            [other],
        )
        .unwrap();
    }
    assert_patch_is_401(&h, &t, &tok, 0).await;
}

#[tokio::test]
async fn bound_ticket_past_expires_at_is_401_even_with_session_row() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let (t, tok) = bound(&h).await;
    meta_exec(
        &h,
        "UPDATE _mcp_upload_tickets SET expires_at = datetime('now', '-1 seconds')",
    )
    .await;
    let (s, _, _) = send(
        &h.app,
        "HEAD",
        &format!("/t/acme/uploads/{tok}"),
        Some(&t),
        &[],
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let n: i64 = tenant_conn(&h, "acme")
        .query_row(
            "SELECT COUNT(*) FROM _system_upload_sessions WHERE upload_token = ?1",
            [&tok],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn bound_ticket_outlives_create_by() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let (t, tok) = bound(&h).await;
    meta_exec(
        &h,
        "UPDATE _mcp_upload_tickets SET create_by = datetime('now', '-1 minutes')",
    )
    .await;
    assert_eq!(
        patch(&h, &t, &tok, 0, b"abcd".to_vec()).await.0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn unbound_ticket_past_create_by_is_401() {
    let h = spin_up_ticket_harness(&["acme"], true).await;
    let t = ticket(&h, 4, None, false).await;
    meta_exec(
        &h,
        "UPDATE _mcp_upload_tickets SET create_by = datetime('now', '-1 seconds')",
    )
    .await;
    let (s, _, v) = create(&h, &t, 4, "").await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(MSG))
    );
}

// ─── create_upload_url, end to end ──────────────────────────────────────────

async fn upl_harness() -> AccountMcpHarness {
    helpers::spin_up_account_mcp_with(helpers::AccountMcpOpts {
        admins: vec![("mcp-owner", "owner")],
        tenants: vec![("upl-e2e", Some(0))],
        files: true,
        mcp_enabled: true,
    })
    .await
}

/// The tools/call result of create_upload_url with `args`.
async fn upl_call(h: &AccountMcpHarness, args: Value) -> Value {
    let m = helpers::mcp_call(&h.app, &h.access, &h.tid, "create_upload_url", args).await;
    m["result"].clone()
}

/// Calls create_upload_url through mcp_call and parses the reply JSON (content[0].text).
async fn issue(h: &AccountMcpHarness, args: Value) -> Value {
    let r = upl_call(h, args).await;
    assert_ne!(r["isError"], true, "create_upload_url refused");
    serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap()
}

/// The isError body of a refused create_upload_url call.
async fn issue_err(h: &AccountMcpHarness, args: Value) -> Value {
    let r = upl_call(h, args).await;
    assert_eq!(r["isError"], true, "{r}");
    serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap()
}

/// Absolute URL from the reply → router path: strip helpers::MCP_PUBLIC_URL, then drust::base_path::base_path().
fn router_path(url: &str) -> String {
    url.strip_prefix(helpers::MCP_PUBLIC_URL)
        .and_then(|p| p.strip_prefix(drust::base_path::base_path()))
        .unwrap_or_else(|| panic!("not a URL of this server: {url}"))
        .to_string()
}

/// One request with exactly `headers` (name, value) and `body`.
async fn tus_send(
    h: &AccountMcpHarness,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (StatusCode, HeaderMap) {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let resp = h
        .app
        .clone()
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    (resp.status(), resp.headers().clone())
}

/// POSTs with exactly reply["create"]["headers"]; returns (status, Location header).
async fn tus_create(h: &AccountMcpHarness, reply: &Value) -> (StatusCode, Option<String>) {
    let hs: Vec<(&str, &str)> = reply["create"]["headers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str().unwrap()))
        .collect();
    let uri = router_path(reply["upload_url"].as_str().unwrap());
    let (st, hd) = tus_send(h, "POST", &uri, &hs, vec![]).await;
    let loc = hd.get("location").map(|v| v.to_str().unwrap().to_string());
    (st, loc)
}

/// PATCHes one chunk with the reply's append headers ("same" → the create Authorization).
async fn tus_patch(
    h: &AccountMcpHarness,
    reply: &Value,
    location: &str,
    offset: u64,
    chunk: &[u8],
) -> StatusCode {
    let off = offset.to_string();
    let hs: Vec<(&str, &str)> = reply["append"]["headers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| {
            let v = match (k.as_str(), v.as_str().unwrap()) {
                ("Authorization", "same") => reply["create"]["headers"]["Authorization"]
                    .as_str()
                    .unwrap(),
                ("Upload-Offset", _) => off.as_str(),
                (_, v) => v,
            };
            (k.as_str(), v)
        })
        .collect();
    let last = location.rsplit('/').next().unwrap();
    let url = format!("{}{last}", reply["append"]["url_prefix"].as_str().unwrap());
    tus_send(h, "PATCH", &router_path(&url), &hs, chunk.to_vec())
        .await
        .0
}

/// GET /t/{tid}/files with the tenant's service key (h.svc); returns the rows array.
async fn list_files(h: &AccountMcpHarness) -> Vec<Value> {
    let auth = format!("Bearer {}", h.svc);
    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/{}/files", h.tid))
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["files"].as_array().expect("a files array").clone()
}

fn tickets_in(c: &rusqlite::Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM _mcp_upload_tickets", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn create_upload_url_end_to_end_multi_chunk() {
    let h = upl_harness().await;
    let r = issue(
        &h,
        serde_json::json!({"tenant": h.tid, "size":10,"filename":"報告 v1,final.txt","path":"docs/q3/report.txt"}),
    )
    .await;
    assert_eq!(
        r["upload_url"],
        format!(
            "{}{}/t/{}/uploads",
            helpers::MCP_PUBLIC_URL,
            drust::base_path::base_path(),
            h.tid
        )
    );
    let (st, loc) = tus_create(&h, &r).await;
    assert_eq!(st, StatusCode::CREATED);
    let loc = loc.unwrap();
    assert_eq!(
        tus_patch(&h, &r, &loc, 0, b"0123").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        tus_patch(&h, &r, &loc, 4, b"4567").await,
        StatusCode::NO_CONTENT
    );
    assert!(tus_patch(&h, &r, &loc, 8, b"89").await.is_success());
    let rows = list_files(&h).await;
    assert_eq!(rows.len(), 1);
    let f = &rows[0];
    assert_eq!(f["original_name"], "報告 v1,final.txt");
    assert_eq!(f["size_bytes"], 10);
    assert_eq!(f["path"], "docs/q3/report.txt");
    assert_eq!(f["visibility"], "private");
    assert_eq!(f["uploader"], "service");
}

#[tokio::test]
async fn create_upload_url_empty_file_finalizes_with_one_empty_patch() {
    let h = upl_harness().await;
    let r = issue(
        &h,
        serde_json::json!({"tenant": h.tid, "size":0,"filename":"empty.txt"}),
    )
    .await;
    let (st, loc) = tus_create(&h, &r).await;
    assert_eq!(st, StatusCode::CREATED);
    assert!(tus_patch(&h, &r, &loc.unwrap(), 0, b"").await.is_success());
    let rows = list_files(&h).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["original_name"], "empty.txt");
    assert_eq!(rows[0]["size_bytes"], 0);
}

#[tokio::test]
async fn create_upload_url_twice_issues_two_independent_tickets() {
    let h = upl_harness().await;
    let a = issue(&h, serde_json::json!({"tenant": h.tid, "size":1})).await;
    let b = issue(&h, serde_json::json!({"tenant": h.tid, "size":1})).await;
    assert_ne!(
        a["create"]["headers"]["Authorization"],
        b["create"]["headers"]["Authorization"]
    );
    assert_eq!(tus_create(&h, &b).await.0, StatusCode::CREATED); // the second works first
    assert_eq!(tus_create(&h, &a).await.0, StatusCode::CREATED); // the first is unaffected
    assert_eq!(tickets_in(&*h.meta.lock().await), 2);
}

#[tokio::test]
async fn create_upload_url_public_finalizes_public() {
    let h = upl_harness().await;
    assert_eq!(
        issue_err(
            &h,
            serde_json::json!({"tenant": h.tid, "size":1,"visibility":"Public"})
        )
        .await["error_code"],
        "INVALID_VISIBILITY"
    );
    assert_eq!(tickets_in(&*h.meta.lock().await), 0); // no silent private ticket
    let r = issue(
        &h,
        serde_json::json!({"tenant": h.tid, "size":1,"filename":"p.txt","visibility":"public"}),
    )
    .await;
    assert_eq!(r["ticket"]["visibility"], "public");
    let (st, loc) = tus_create(&h, &r).await;
    assert_eq!(st, StatusCode::CREATED);
    assert!(tus_patch(&h, &r, &loc.unwrap(), 0, b"x").await.is_success());
    let rows = list_files(&h).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["original_name"], "p.txt");
    assert_eq!(rows[0]["visibility"], "public");
}

#[tokio::test]
async fn create_upload_url_rejects_size_over_the_limit() {
    let h = upl_harness().await;
    // the harness's large_upload_max_bytes is the MgmtState default 2 GiB
    let b = issue_err(
        &h,
        serde_json::json!({"tenant": h.tid, "size": 2_147_483_649u64}),
    )
    .await;
    assert_eq!(b["error_code"], "UPLOAD_TOO_LARGE");
    assert_eq!(tickets_in(&*h.meta.lock().await), 0);
}

#[tokio::test]
async fn create_upload_url_mistyped_size_writes_no_ticket() {
    let h = upl_harness().await;
    let b = issue_err(&h, serde_json::json!({"tenant": h.tid, "size":"10"})).await;
    assert_eq!(b["error_code"], "INVALID_PARAMS");
    assert!(
        b["message"]
            .as_str()
            .unwrap()
            .starts_with("failed to deserialize parameters:")
    );
    assert_eq!(tickets_in(&*h.meta.lock().await), 0);
}
