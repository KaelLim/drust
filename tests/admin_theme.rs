//! Integration tests for the v1.23 theme system. Each test stands up a
//! mini admin router, fires a single request via `oneshot`, and inspects
//! the response (status + headers + body) directly.
//!
//! These tests bypass Caddy — they hit the axum router on its own. Any
//! cookie-path bug that depends on Caddy's `handle_path` stripping
//! `/drust` will NOT surface here; that's an integration-vs-Caddy
//! tradeoff we accept (it's the same posture as admin_oauth.rs).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

// Helper: build a minimal admin router with our test meta DB.
async fn test_router() -> (axum::Router, std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>) {
    // Build in-memory meta + populate one admin row.
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE admins (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT,
            locale TEXT,
            theme TEXT
        );
        INSERT INTO admins (id, username, password_hash) VALUES (1, 'admin', 'unused-hash');",
    )
    .unwrap();
    let meta = std::sync::Arc::new(tokio::sync::Mutex::new(conn));

    // Tiny router that just attaches Extension<Theme> via theme_layer and
    // echoes the resolved value as a response header.
    // Uses allow_db_fallback=false (outer-layer posture) — no AdminId injected
    // in these basic tests.
    let state = drust::mgmt::theme_layer::ThemeLayerState {
        meta: meta.clone(),
        allow_db_fallback: false,
    };
    let app = axum::Router::new()
        .route(
            "/probe",
            axum::routing::get(|req: Request<Body>| async move {
                let theme = req
                    .extensions()
                    .get::<drust::mgmt::theme::Theme>()
                    .copied()
                    .unwrap_or(drust::mgmt::theme::Theme::System);
                axum::http::Response::builder()
                    .header("x-resolved-theme", theme.code())
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            drust::mgmt::theme_layer::theme_layer,
        ));

    (app, meta)
}

#[tokio::test]
async fn theme_default_is_system() {
    let (app, _meta) = test_router().await;
    let resp = app
        .oneshot(Request::builder().uri("/probe").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-resolved-theme").unwrap(),
        "system"
    );
}

#[tokio::test]
async fn cookie_wins_over_default() {
    let (app, _meta) = test_router().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/probe")
                .header(header::COOKIE, "drust_theme=cozy-dark")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-resolved-theme").unwrap(),
        "cozy-dark"
    );
}

#[tokio::test]
async fn unknown_cookie_falls_to_default() {
    let (app, _meta) = test_router().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/probe")
                .header(header::COOKIE, "drust_theme=ocean")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-resolved-theme").unwrap(),
        "system"
    );
}

#[tokio::test]
async fn three_themes_each_resolve() {
    let (app, _meta) = test_router().await;
    for code in &["system", "cozy-dark", "soft-light"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .header(header::COOKIE, format!("drust_theme={code}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers().get("x-resolved-theme").unwrap().to_str().unwrap(),
            *code,
            "round-trip failed for theme `{code}`"
        );
    }
}

#[tokio::test]
async fn palette_for_system_contains_both_partners() {
    use drust::mgmt::theme::{palette_for, ResolvedPalette, Theme};
    let resolved = palette_for(Theme::System);
    match resolved {
        ResolvedPalette::System(sys) => {
            // Spot-check: light side is the cream-base palette, dark side
            // is the warm-charcoal palette.
            assert_eq!(*sys.light.ui.get("bg").unwrap(), "#faf4e8");
            assert_eq!(*sys.dark.ui.get("bg").unwrap(), "#1c1816");
        }
        _ => panic!("System should resolve to System"),
    }
}

#[tokio::test]
async fn palette_for_static_returns_owned_keys() {
    use drust::mgmt::theme::{palette_for, ResolvedPalette, Theme};
    match palette_for(Theme::CozyDark) {
        ResolvedPalette::Static(p) => {
            assert_eq!(p.ui.len(), 12);
            assert_eq!(p.accent.len(), 10);
            assert_eq!(p.mascot.len(), 7);
        }
        _ => panic!("CozyDark should resolve to Static"),
    }
}

#[tokio::test]
async fn all_themes_in_enum_have_resolvable_palette() {
    use drust::mgmt::theme::{palette_for, Theme};
    for t in Theme::ALL {
        let _ = palette_for(*t); // panics if any partner is missing
    }
}

// ---------------------------------------------------------------------------
// v1.25 — F5/F6: inner-layer (allow_db_fallback=true) tests
// ---------------------------------------------------------------------------

/// Probe middleware: forces Extension<AdminId>(id) into request extensions.
/// Replaces the real admin_session_layer in the F6 tests, which exercise
/// the inner theme_layer in isolation.
async fn inject_admin_id(
    id: i64,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    req.extensions_mut()
        .insert(drust::auth::middleware::AdminId(id));
    next.run(req).await
}

/// Build an in-memory meta DB with one admin row (theme optionally set).
async fn setup_meta_with_admin(
    id: i64,
    theme: Option<&str>,
) -> (
    std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE admins (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT,
            locale TEXT,
            theme TEXT
        );",
    )
    .unwrap();
    if let Some(t) = theme {
        conn.execute(
            "INSERT INTO admins(id, username, password_hash, theme) VALUES (?1, 'test', '$argon2id$dummy$', ?2)",
            rusqlite::params![id, t],
        )
        .unwrap();
    } else {
        conn.execute(
            "INSERT INTO admins(id, username, password_hash) VALUES (?1, 'test', '$argon2id$dummy$')",
            rusqlite::params![id],
        )
        .unwrap();
    }
    (
        std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
        tmp,
    )
}

/// Handler that echoes the resolved Theme as plain text.
async fn theme_echo_handler(
    axum::extract::Extension(theme): axum::extract::Extension<drust::mgmt::theme::Theme>,
) -> String {
    theme.code().to_string()
}

async fn body_to_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// F6-a: inner layer (allow_db_fallback=true) falls back to DB when no cookie.
#[tokio::test]
async fn inner_layer_falls_back_to_db_when_cookie_absent() {
    let (meta, _tmp) = setup_meta_with_admin(1, Some("soft-light")).await;
    let state = drust::mgmt::theme_layer::ThemeLayerState {
        meta: meta.clone(),
        allow_db_fallback: true,
    };
    let app = axum::Router::new()
        .route("/", axum::routing::get(theme_echo_handler))
        .layer(axum::middleware::from_fn_with_state(
            state,
            drust::mgmt::theme_layer::theme_layer,
        ))
        .layer(axum::middleware::from_fn(|req, next| {
            inject_admin_id(1, req, next)
        }));

    let resp = app
        .oneshot(
            axum::http::Request::get("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_to_string(resp).await, "soft-light");
}

/// F6-b: inner layer — cookie wins over DB value.
#[tokio::test]
async fn inner_layer_cookie_wins_over_db() {
    let (meta, _tmp) = setup_meta_with_admin(1, Some("soft-light")).await;
    let state = drust::mgmt::theme_layer::ThemeLayerState {
        meta: meta.clone(),
        allow_db_fallback: true,
    };
    let app = axum::Router::new()
        .route("/", axum::routing::get(theme_echo_handler))
        .layer(axum::middleware::from_fn_with_state(
            state,
            drust::mgmt::theme_layer::theme_layer,
        ))
        .layer(axum::middleware::from_fn(|req, next| {
            inject_admin_id(1, req, next)
        }));

    let resp = app
        .oneshot(
            axum::http::Request::get("/")
                .header("Cookie", "drust_theme=cozy-dark")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_to_string(resp).await, "cozy-dark");
}

/// F5: outer layer (allow_db_fallback=false) ignores DB even if AdminId present.
#[tokio::test]
async fn outer_layer_does_not_read_db_even_if_admin_id_present() {
    let (meta, _tmp) = setup_meta_with_admin(1, Some("soft-light")).await;
    let state = drust::mgmt::theme_layer::ThemeLayerState {
        meta: meta.clone(),
        allow_db_fallback: false,
    };
    let app = axum::Router::new()
        .route("/", axum::routing::get(theme_echo_handler))
        .layer(axum::middleware::from_fn_with_state(
            state,
            drust::mgmt::theme_layer::theme_layer,
        ))
        .layer(axum::middleware::from_fn(|req, next| {
            inject_admin_id(1, req, next)
        }));

    let resp = app
        .oneshot(
            axum::http::Request::get("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_to_string(resp).await, "system");
}
