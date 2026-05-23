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
    let state = drust::mgmt::theme_layer::ThemeLayerState { meta: meta.clone() };
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
