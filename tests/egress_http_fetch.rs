//! Task 6 (v1.49) — the gated `http-fetch` edge-function host import.
//!
//! Drives the production `host::Host::http_fetch` decision path directly via a
//! test-gated `StoreData` constructor (`new_for_test` + `http_fetch_for_test`),
//! mirroring the `tests/functions_wasm_real.rs` seed but without a wasm
//! toolchain. Every case asserts a GATE decision so the suite stays hermetic:
//!   1. origin not on the tenant's `system=function` allowlist → Err, no network.
//!   2. an allowlisted origin whose host is a private IP → Err (PinnedPublicResolver
//!      drops it before the dial — the second DiD gate).
//!   3. a response over `max_response_bytes` → Err (streaming size cap).
//!   4. a 3xx is returned to the caller un-followed (redirect::Policy::none()).
//!   5. a successful fetch lands an audit row op `function.http_fetch`.
//!   6. a method outside the allowlist → Err, no network.
//!
//! Cases 3/4/5 hit a loopback axum server; since `http-fetch` (unlike webhook
//! delivery) has NO loopback carve-out and ALWAYS runs the resolver, the test
//! injects a `PinTo127` resolver override to reach 127.0.0.1 — exactly the
//! webhook rebind-test shape (`tests/webhook_dns_rebind.rs`).

use drust::functions::caller::CallerCtx;
use drust::functions::runtime::{HostStateSeed, HttpFetchState, StoreData};
use drust::mcp::server::DrustMcp;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;

// ─── seed / mcp builder (mirrors tests/functions_wasm_real.rs) ────────────────

async fn mcp_for(tenant: &str) -> (DrustMcp, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        tmp.path().to_path_buf(),
        2,
    ));
    // build_mcp resolves create-free (get_if_live): the tenant DB must exist.
    tenants.get_or_open(tenant).unwrap();
    let rooms_cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let seed = HostStateSeed {
        tenants: tenants.clone(),
        bus: drust::tenant::events::EventBus::new(),
        webhooks: drust::tenant::WebhookDispatcher::new(tenants.clone(), None),
        garage: None,
        public_base_url: String::new(),
        url_sign_secret: Arc::new([0u8; 32]),
        meta: None,
        max_upload_bytes: 52_428_800,
        index_large_table_rows: 1_000_000,
        audit_meta_read: Arc::new(tokio::sync::Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket,
        rooms_cfg,
        disk_min_free_pct: 20,
    };
    let mcp = seed.build_mcp(tenant).unwrap();
    (mcp, tmp)
}

fn http_state(
    allowlist_json: &str,
    resolver: Option<Arc<dyn Resolve + Send + Sync>>,
    max_bytes: u64,
) -> HttpFetchState {
    HttpFetchState {
        allowlist_json: allowlist_json.to_string(),
        max_response_bytes: max_bytes,
        resolver_override: resolver,
        ..HttpFetchState::test_default()
    }
}

// ─── loopback test server + pinning resolver ──────────────────────────────────

/// reqwest resolver that pins every hostname to `127.0.0.1:<port>`. reqwest
/// dials the SocketAddr the resolver returns (port included — see
/// tests/webhook_dns_rebind.rs::PinTo127), so this reaches a loopback server
/// through the same `dns_resolver` seam production feeds `PinnedPublicResolver`.
#[derive(Clone)]
struct PinTo127 {
    port: u16,
}
impl Resolve for PinTo127 {
    fn resolve(&self, _name: Name) -> Resolving {
        let port = self.port;
        Box::pin(async move {
            let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
            Ok(Box::new(vec![addr].into_iter()) as Addrs)
        })
    }
}

/// Start a loopback axum server with `/ok` (200 "hello"), `/big` (200, 100 KB),
/// and `/redir` (302 → https://example.com, empty body). Returns its port and
/// the JoinHandle (keep it alive for the test's duration).
async fn start_server() -> (u16, tokio::task::JoinHandle<()>) {
    use axum::Router;
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;
    use axum::routing::get;

    async fn ok_handler() -> impl IntoResponse {
        (StatusCode::OK, "hello")
    }
    async fn big_handler() -> impl IntoResponse {
        (StatusCode::OK, "x".repeat(100_000))
    }
    async fn redir_handler() -> impl IntoResponse {
        (
            StatusCode::FOUND,
            [(header::LOCATION, "https://example.com/elsewhere")],
            "",
        )
    }

    let router = Router::new()
        .route("/ok", get(ok_handler))
        .route("/big", get(big_handler))
        .route("/redir", get(redir_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (port, handle)
}

// ─── global audit writer (pattern copied from tests/egress_config.rs) ─────────

fn ensure_global_audit_writer() -> &'static PathBuf {
    use drust::safety::audit_db::{AuditWriter, init_globals, open_audit_db_write};
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_egress_http_fetch_audit.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("test-egress-fetch-audit-writer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build writer runtime");
                rt.block_on(async move {
                    let writer = AuditWriter::new(conn);
                    init_globals(writer);
                    let _ = tx_ready.send(());
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn audit writer thread");
        rx_ready.recv().expect("audit writer init signal");
        let path_clone = path.clone();
        Box::leak(dir);
        path_clone
    })
}

async fn audit_ops(tenant: &str) -> Vec<String> {
    use drust::safety::audit_db::open_audit_db_read;
    let path = ensure_global_audit_writer();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let r = open_audit_db_read(path).unwrap();
    let _ = r.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
    let mut stmt = r
        .prepare("SELECT op FROM audit WHERE tenant = ?1 ORDER BY id ASC")
        .unwrap();
    stmt.query_map(rusqlite::params![tenant], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect()
}

// ─── tests ────────────────────────────────────────────────────────────────────

/// (1) An origin absent from the `system=function` allowlist is denied before
/// any network I/O — even for a Privileged caller (egress is host-outbound
/// authz, not tenant-data authz, so god-mode does NOT exempt it).
#[tokio::test(flavor = "multi_thread")]
async fn origin_not_allowlisted_is_denied() {
    let (mcp, _tmp) = mcp_for("t-fetch-deny").await;
    let mut store = StoreData::new_for_test(
        mcp,
        CallerCtx::Privileged,
        http_state("[]", None, 5 * 1024 * 1024),
    );
    let err = store
        .http_fetch_for_test(
            "https://api.github.com".into(),
            "/".into(),
            "GET".into(),
            vec![],
            vec![],
        )
        .await
        .expect_err("empty allowlist must deny");
    assert!(err.contains("not allowlisted"), "got: {err}");
}

/// (1b) SSRF regression: an ALLOWLISTED origin with a guest `path` that would
/// rewrite the authority (any non-rooted path — `@host`, `.host`, an IP-literal
/// userinfo) is denied BEFORE any network I/O — the checked origin and the
/// dialed host must never disagree. Reverting the path-shape / re-derive guard
/// in `http_fetch` re-opens this. (A rooted `//host/x` is NOT an injection: it
/// dials the allowlisted host with `//host/x` as the path, so it is allowed.)
/// (1c) Parser-differential guard: the re-derive check compares
/// `egress::normalize_origin(&url)` (a hand-rolled splitter) against the origin,
/// but the ACTUAL dial uses reqwest's WHATWG `Url` parser. If the two parsers
/// ever disagreed on the host of `origin + rooted_path`, `dialed == origin`
/// could pass while reqwest dials a different host — a full bypass. This pins
/// that they AGREE: for adversarial rooted paths, normalize_origin(origin+path)
/// stays == origin AND reqwest::Url::parse(origin+path).host_str() == the origin
/// host. A future parser change that breaks the agreement fails here.
#[test]
fn normalize_origin_and_reqwest_agree_on_host_for_rooted_paths() {
    let origin = "https://allowed.com";
    for path in [
        "/",
        "/normal/path?q=1",
        "/\\evil.com",     // backslash (WHATWG maps \ → / in path)
        "/%2F%2Fevil.com", // percent-encoded slashes
        "/%40evil.com",    // percent-encoded @
        "/..//@evil.com",  // dot-segments + @ in path position
        "/\t/evil.com",    // embedded tab
        "//evil.com/x",    // protocol-relative-looking, but rooted
    ] {
        let url = format!("{origin}{path}");
        // Our guard's re-derive: normalize_origin must keep the origin intact.
        let dialed = drust::tenant::egress::normalize_origin(&url);
        // reqwest's real parser: the host it would actually dial.
        let reqwest_host = reqwest::Url::parse(&url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string));
        // Either both agree the host is allowed.com, or normalize_origin
        // rejected the URL outright (also safe — the fetch errors). What must
        // NEVER happen: normalize_origin says allowed.com while reqwest dials
        // something else.
        match (dialed, reqwest_host) {
            (Ok(d), Some(h)) => {
                assert_eq!(d, origin, "normalize_origin drifted for path {path:?}");
                assert_eq!(
                    h, "allowed.com",
                    "reqwest dials a different host for path {path:?}"
                );
            }
            (Err(_), _) => { /* normalize_origin rejected → fetch fails, safe */ }
            (Ok(d), None) => {
                panic!("normalize_origin accepted {d} but reqwest could not parse {url:?}")
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn guest_path_cannot_alter_the_request_host() {
    let (mcp, _tmp) = mcp_for("t-fetch-pathinj").await;
    let allow = r#"[{"system":"function","uri":"https://allowed.com"}]"#;
    for evil in [
        "@attacker.com/collect",   // userinfo trick → host=attacker.com
        ".attacker.com/x",         // label-append → host=allowed.com.attacker.com
        "@169.254.169.254/latest", // cloud-metadata via IP literal in userinfo
    ] {
        let mut store = StoreData::new_for_test(
            mcp.clone(),
            CallerCtx::Privileged,
            http_state(allow, None, 5 * 1024 * 1024),
        );
        let err = store
            .http_fetch_for_test(
                "https://allowed.com".into(),
                evil.into(),
                "POST".into(),
                b"secret".to_vec(),
                vec![],
            )
            .await
            .expect_err("path-authority injection must be denied");
        assert!(
            err.contains("path must") || err.contains("not allowlisted"),
            "evil path {evil:?} not rejected: {err}"
        );
    }
}

/// (2) An allowlisted origin whose host is a PRIVATE IP LITERAL is rejected
/// explicitly BEFORE any dial. hyper's connector skips the custom
/// `PinnedPublicResolver` when the host is already an IP literal (`try_parse`
/// short-circuits DNS — the resolver only runs for DNS names), so relying on the
/// resolver alone silently lets an allowlisted `http://169.254.169.254` /
/// `http://127.0.0.1` SSRF straight through to cloud metadata / host loopback
/// (codex full-scan F2). The block must be an explicit `is_private_ip` check on
/// the origin host. This test proves the block is (a) hit for several private
/// ranges, (b) NOT the allowlist gate (the origin IS allowlisted), and (c) fast —
/// a spurious pass on the 5s connect timeout (the old bug) is caught by the
/// elapsed assertion.
#[tokio::test(flavor = "multi_thread")]
async fn allowlisted_private_ip_literal_rejected_before_dial() {
    for ip_origin in [
        "http://10.0.0.1",
        "http://127.0.0.1",
        "http://169.254.169.254",
        "http://192.168.1.1",
        // alternate encodings the url crate canonicalizes to the SAME private IPs;
        // these must be blocked too (parser-differential SSRF, F2).
        "http://2130706433",  // = 127.0.0.1
        "http://2852039166",  // = 169.254.169.254
    ] {
        let (mcp, _tmp) = mcp_for("t-fetch-priv").await;
        let list = format!(r#"[{{"system":"function","uri":"{ip_origin}"}}]"#);
        let mut store = StoreData::new_for_test(
            mcp,
            CallerCtx::Privileged,
            http_state(&list, None, 5 * 1024 * 1024),
        );
        let started = std::time::Instant::now();
        let err = store
            .http_fetch_for_test(ip_origin.into(), "/".into(), "GET".into(), vec![], vec![])
            .await
            .expect_err("private-IP literal origin must be rejected before dial");
        // Rejected by our explicit IP-literal gate, NOT the allowlist gate (the
        // origin IS allowlisted) and NOT a slow connect timeout.
        assert!(
            err.contains("private"),
            "want explicit private-IP block for {ip_origin}, got: {err}"
        );
        assert!(
            !err.contains("not allowlisted"),
            "must pass the allowlist gate for {ip_origin}, got: {err}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "must fail fast before any dial for {ip_origin}, took {:?}",
            started.elapsed()
        );
    }
}

/// (3) A response larger than `max_response_bytes` aborts with an Err (the
/// streaming size cap), not an unbounded buffer.
#[tokio::test(flavor = "multi_thread")]
async fn response_over_size_cap_errs() {
    let (port, _server) = start_server().await;
    // A DNS-name origin (not an IP literal) so the request routes through the
    // PinTo127 resolver seam — production `PinnedPublicResolver` gets the same
    // shape. An IP-literal origin is now rejected pre-dial (F2 fix).
    let origin = "http://fetch.test".to_string();
    let list = format!(r#"[{{"system":"function","uri":"{origin}"}}]"#);
    let (mcp, _tmp) = mcp_for("t-fetch-big").await;
    let mut store = StoreData::new_for_test(
        mcp,
        CallerCtx::Privileged,
        http_state(&list, Some(Arc::new(PinTo127 { port })), 1024),
    );
    let err = store
        .http_fetch_for_test(origin, "/big".into(), "GET".into(), vec![], vec![])
        .await
        .expect_err("a 100 KB body over a 1 KB cap must Err");
    assert!(
        err.contains("exceeds") || err.contains("size cap"),
        "got: {err}"
    );
}

/// (4) A 3xx is returned to the caller verbatim — the client never follows the
/// redirect (redirect::Policy::none()), so a bounce out of the allowlist is
/// impossible.
#[tokio::test(flavor = "multi_thread")]
async fn redirect_is_returned_unfollowed() {
    let (port, _server) = start_server().await;
    // A DNS-name origin (not an IP literal) so the request routes through the
    // PinTo127 resolver seam — production `PinnedPublicResolver` gets the same
    // shape. An IP-literal origin is now rejected pre-dial (F2 fix).
    let origin = "http://fetch.test".to_string();
    let list = format!(r#"[{{"system":"function","uri":"{origin}"}}]"#);
    let (mcp, _tmp) = mcp_for("t-fetch-redir").await;
    let mut store = StoreData::new_for_test(
        mcp,
        CallerCtx::Privileged,
        http_state(&list, Some(Arc::new(PinTo127 { port })), 5 * 1024 * 1024),
    );
    let (status, _headers, body) = store
        .http_fetch_for_test(origin, "/redir".into(), "GET".into(), vec![], vec![])
        .await
        .expect("3xx must be returned, not followed");
    assert_eq!(status, 302, "status must be the un-followed 302");
    assert!(
        body.is_empty(),
        "redirect body should be empty, got {body:?}"
    );
}

/// (5) A successful fetch lands an audit row op `function.http_fetch`.
#[tokio::test(flavor = "multi_thread")]
async fn successful_fetch_emits_audit_row() {
    ensure_global_audit_writer();
    let (port, _server) = start_server().await;
    // A DNS-name origin (not an IP literal) so the request routes through the
    // PinTo127 resolver seam — production `PinnedPublicResolver` gets the same
    // shape. An IP-literal origin is now rejected pre-dial (F2 fix).
    let origin = "http://fetch.test".to_string();
    let list = format!(r#"[{{"system":"function","uri":"{origin}"}}]"#);
    let tenant = "t-fetch-audit";
    let (mcp, _tmp) = mcp_for(tenant).await;
    let mut store = StoreData::new_for_test(
        mcp,
        CallerCtx::Privileged,
        http_state(&list, Some(Arc::new(PinTo127 { port })), 5 * 1024 * 1024),
    );
    let (status, _headers, body) = store
        .http_fetch_for_test(origin, "/ok".into(), "GET".into(), vec![], vec![])
        .await
        .expect("loopback fetch should succeed");
    assert_eq!(status, 200);
    assert_eq!(body, b"hello");

    let ops = audit_ops(tenant).await;
    assert!(
        ops.iter().any(|o| o == "function.http_fetch"),
        "expected an audit row op=function.http_fetch, got: {ops:?}"
    );
}

/// (6) A method outside the allowlist is rejected before any network I/O.
#[tokio::test(flavor = "multi_thread")]
async fn method_not_allowed_is_denied() {
    let (mcp, _tmp) = mcp_for("t-fetch-method").await;
    let list = r#"[{"system":"function","uri":"https://api.github.com"}]"#;
    let mut store = StoreData::new_for_test(
        mcp,
        CallerCtx::Privileged,
        http_state(list, None, 5 * 1024 * 1024),
    );
    let err = store
        .http_fetch_for_test(
            "https://api.github.com".into(),
            "/".into(),
            "TRACE".into(),
            vec![],
            vec![],
        )
        .await
        .expect_err("TRACE is not in the method allowlist");
    assert!(err.contains("method not allowed"), "got: {err}");
}

/// (7) Rate-limit ordering (v1.49.1 review fix): a malformed `path` is rejected
/// by the path-shape guard BEFORE the rate limiter is charged, so it never
/// burns quota. With a budget of 1, two malformed-path calls both return the
/// path error; if the guard ran AFTER the limiter, the first call would consume
/// the sole token and the second would wrongly return "rate limited".
#[tokio::test(flavor = "multi_thread")]
async fn malformed_path_does_not_consume_rate_limit_quota() {
    let (mcp, _tmp) = mcp_for("t-fetch-rl-order").await;
    let allow = r#"[{"system":"function","uri":"https://allowed.com"}]"#;
    let http = HttpFetchState {
        allowlist_json: allow.to_string(),
        rate_limiter: Arc::new(drust::safety::rate_limit::RateLimiter::new(
            1,
            std::time::Duration::from_secs(60),
        )),
        ..HttpFetchState::test_default()
    };
    let mut store = StoreData::new_for_test(mcp, CallerCtx::Privileged, http);
    for _ in 0..2 {
        let err = store
            .http_fetch_for_test(
                "https://allowed.com".into(),
                "bad-nonrooted".into(),
                "GET".into(),
                vec![],
                vec![],
            )
            .await
            .expect_err("malformed path must error");
        assert!(
            err.contains("path must"),
            "expected path error (not rate limited): {err}"
        );
    }
}
