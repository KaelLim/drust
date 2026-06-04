//! Theme resolution + `Extension<Theme>` attachment for admin requests.
//!
//! Resolution order:
//!   1. `drust_theme` cookie (long-lived, set by settings dropdown & login)
//!   2. logged-in admin's `admins.theme` column (if Extension<AdminId> present
//!      AND `allow_db_fallback` is true)
//!   3. Default `Theme::System`
//!
//! v1.25 — two-layer registration:
//!
//! • **Outer layer** (`allow_db_fallback=false`, outermost on the full router):
//!   covers `/login` and OAuth callback where `AdminId` is not yet resolved.
//!   Cookie-or-System only.
//!
//! • **Inner layer** (`allow_db_fallback=true`, inside `protected` after
//!   `admin_session_layer`): `AdminId` is now in request extensions; falls back
//!   from cookie → DB → System and overwrites whatever the outer layer set.

use axum::{extract::Request, http::HeaderMap, middleware::Next, response::Response};
use axum_extra::extract::cookie::CookieJar;

use crate::mgmt::theme::Theme;

/// State the theme middleware needs to look up `admins.theme`.
#[derive(Clone)]
pub struct ThemeLayerState {
    pub meta: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    /// When `false`, this layer ignores `AdminId` and resolves cookie-or-System
    /// only. Used by the outer layer (covers `/login`, OAuth callback) where
    /// `AdminId` is not yet in request extensions.
    /// When `true`, falls back to `SELECT theme FROM admins WHERE id = ?`
    /// — required for the inner layer (inside `protected`, after
    /// `admin_session_layer`).
    pub allow_db_fallback: bool,
}

pub async fn theme_layer(
    axum::extract::State(state): axum::extract::State<ThemeLayerState>,
    jar: CookieJar,
    _headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Response {
    let admin_id = req
        .extensions()
        .get::<crate::auth::middleware::AdminId>()
        .map(|a| a.0);
    let theme = resolve_theme(&jar, &state, admin_id).await;
    req.extensions_mut().insert(theme);
    next.run(req).await
}

/// Pure-ish resolver: cookie wins, else DB if admin is logged in AND
/// `allow_db_fallback` is set, else default.
pub async fn resolve_theme(
    jar: &CookieJar,
    state: &ThemeLayerState,
    admin_id: Option<i64>,
) -> Theme {
    // (1) cookie wins
    if let Some(c) = jar.get("drust_theme") {
        if let Some(t) = Theme::from_tag(c.value()) {
            return t;
        }
    }
    // (2) DB lookup if logged in AND this layer is allowed to do it.
    // The outer layer (allow_db_fallback=false) skips this branch because
    // AdminId has not been populated by admin_session_layer yet.
    if state.allow_db_fallback {
        if let Some(id) = admin_id {
            let conn = state.meta.lock().await;
            let row: Option<String> = conn
                .query_row(
                    "SELECT theme FROM admins WHERE id = ?1",
                    rusqlite::params![id],
                    |r| r.get::<_, Option<String>>(0),
                )
                .ok()
                .flatten();
            drop(conn);
            if let Some(s) = row {
                if let Some(t) = Theme::from_tag(&s) {
                    return t;
                }
                tracing::warn!(value = %s, "admins.theme contains unknown code — falling back to System");
            }
        }
    }
    // (3) default
    Theme::System
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum_extra::extract::cookie::{Cookie, CookieJar};

    fn jar_with(name: &str, val: &str) -> CookieJar {
        CookieJar::new().add(Cookie::new(name.to_string(), val.to_string()))
    }

    async fn empty_state() -> ThemeLayerState {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE admins (id INTEGER PRIMARY KEY, theme TEXT);")
            .unwrap();
        ThemeLayerState {
            meta: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
            allow_db_fallback: true,
        }
    }

    #[tokio::test]
    async fn cookie_wins_over_db() {
        let s = empty_state().await;
        s.meta
            .lock()
            .await
            .execute(
                "INSERT INTO admins (id, theme) VALUES (1, 'soft-light')",
                [],
            )
            .unwrap();
        let jar = jar_with("drust_theme", "cozy-dark");
        assert_eq!(resolve_theme(&jar, &s, Some(1)).await, Theme::CozyDark);
    }

    #[tokio::test]
    async fn db_used_when_no_cookie() {
        let s = empty_state().await;
        s.meta
            .lock()
            .await
            .execute(
                "INSERT INTO admins (id, theme) VALUES (1, 'soft-light')",
                [],
            )
            .unwrap();
        assert_eq!(
            resolve_theme(&CookieJar::new(), &s, Some(1)).await,
            Theme::SoftLight
        );
    }

    #[tokio::test]
    async fn default_is_system() {
        let s = empty_state().await;
        assert_eq!(
            resolve_theme(&CookieJar::new(), &s, None).await,
            Theme::System
        );
    }

    #[tokio::test]
    async fn invalid_cookie_falls_through_to_db() {
        let s = empty_state().await;
        s.meta
            .lock()
            .await
            .execute("INSERT INTO admins (id, theme) VALUES (1, 'cozy-dark')", [])
            .unwrap();
        let jar = jar_with("drust_theme", "xyz");
        assert_eq!(resolve_theme(&jar, &s, Some(1)).await, Theme::CozyDark);
    }

    #[tokio::test]
    async fn invalid_db_value_falls_back_to_system() {
        let s = empty_state().await;
        s.meta
            .lock()
            .await
            .execute("INSERT INTO admins (id, theme) VALUES (1, 'ocean')", [])
            .unwrap();
        assert_eq!(
            resolve_theme(&CookieJar::new(), &s, Some(1)).await,
            Theme::System
        );
    }

    #[tokio::test]
    async fn null_db_value_falls_through() {
        let s = empty_state().await;
        s.meta
            .lock()
            .await
            .execute("INSERT INTO admins (id, theme) VALUES (1, NULL)", [])
            .unwrap();
        assert_eq!(
            resolve_theme(&CookieJar::new(), &s, Some(1)).await,
            Theme::System
        );
    }

    #[tokio::test]
    async fn admin_not_in_db_falls_to_default() {
        let s = empty_state().await;
        // admin_id=99 doesn't exist in our setup
        assert_eq!(
            resolve_theme(&CookieJar::new(), &s, Some(99)).await,
            Theme::System
        );
    }
}
