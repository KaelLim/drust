//! v1.28.9 — admin profile extension surfaced through the sidebar.
//!
//! Loaded by `admin_profile_layer` after `admin_session_layer` has populated
//! `Extension<AdminId>`. Read by every admin page struct alongside
//! `Translator`, then rendered in the sidebar (`_admin_sidebar.html`,
//! `_collection_sidebar.html`).

use rusqlite::Connection;

#[derive(Clone, Debug)]
pub struct AdminProfileExt {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub picture_url: Option<String>,
    /// Computed at load time. Total — never empty. See `compute_initials`.
    pub initials: String,
    /// v1.29: 'owner' | 'member'. Read from admins.role at request time
    /// (no caching) so a demote takes effect on the target's next nav.
    pub role: String,
    /// Convenience flag; mirrors `role == "owner"` for template `{% if admin.is_owner %}` use.
    pub is_owner: bool,
}

impl AdminProfileExt {
    /// Initials derivation (v1.28.15 — single-char):
    /// 1. display_name present → first char, uppercased.
    /// 2. email present → first char of the local-part, uppercased.
    /// 3. Both NULL → "?". Never expected in production but keeps the
    ///    type total.
    ///
    /// CJK names ("林宇軒") render as "林" — single CJK char reads cleaner
    /// in a 28-px avatar circle than the previous "林宇" two-char shape.
    /// Western names ("Kael Lim") render as "K".
    pub fn compute_initials(display_name: Option<&str>, email: Option<&str>) -> String {
        if let Some(name) = display_name {
            let trimmed = name.trim();
            if let Some(c) = trimmed.chars().next() {
                return c.to_uppercase().to_string();
            }
        }
        if let Some(e) = email {
            let local = e.split('@').next().unwrap_or("");
            if let Some(c) = local.chars().next() {
                return c.to_uppercase().to_string();
            }
        }
        "?".to_string()
    }

    /// Default profile when the DB lookup fails or the session points to a
    /// row that doesn't exist. Never expected in production; keeps the
    /// middleware soft-fail path simple.
    pub fn placeholder() -> Self {
        Self {
            display_name: None,
            email: None,
            picture_url: None,
            initials: "?".to_string(),
            role: "member".to_string(),
            is_owner: false,
        }
    }
}

/// Load profile from `admins` by id. Returns `Ok(Some(_))` when the row
/// exists, `Ok(None)` when it doesn't or when the query errors —
/// `.ok()` swallows the rusqlite error since the middleware treats
/// `Ok(None)` and `Err(_)` identically (both resolve to `placeholder()`).
pub fn load_admin_profile(
    conn: &Connection,
    admin_id: i64,
) -> rusqlite::Result<Option<AdminProfileExt>> {
    // v1.28.14: rusqlite maps NULL → None but empty-string → Some("").
    // OAuth providers occasionally return picture/name as "" (e.g. Google
    // user with no avatar) — without this normalization the sidebar
    // template's `Some(url)` arm fires and renders `<img src="">`.
    fn blank_to_none(o: Option<String>) -> Option<String> {
        o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
    let row = conn
        .query_row(
            "SELECT display_name, email, picture_url, role FROM admins WHERE id = ?1",
            rusqlite::params![admin_id],
            |r| {
                let display_name: Option<String> = r.get(0)?;
                let email: Option<String> = r.get(1)?;
                let picture_url: Option<String> = r.get(2)?;
                let role: String = r.get(3)?;
                Ok((display_name, email, picture_url, role))
            },
        )
        .ok()
        .map(|(d, e, p, r)| (blank_to_none(d), blank_to_none(e), blank_to_none(p), r));
    Ok(row.map(|(display_name, email, picture_url, role)| {
        let initials = AdminProfileExt::compute_initials(
            display_name.as_deref(),
            email.as_deref(),
        );
        let is_owner = role == "owner";
        AdminProfileExt {
            display_name,
            email,
            picture_url,
            initials,
            role,
            is_owner,
        }
    }))
}

// ─── middleware ──────────────────────────────────────────────────────────────

use axum::{extract::Request, middleware::Next, response::Response};

/// State the profile middleware needs to look up `admins`. Mirrors
/// `ThemeLayerState` but with no fallback flag — we always want the DB
/// lookup when an admin is signed in.
#[derive(Clone)]
pub struct AdminProfileLayerState {
    pub meta: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
}

pub async fn admin_profile_layer(
    axum::extract::State(state): axum::extract::State<AdminProfileLayerState>,
    mut req: Request,
    next: Next,
) -> Response {
    let admin_id = req
        .extensions()
        .get::<crate::auth::middleware::AdminId>()
        .map(|a| a.0);
    let profile = match admin_id {
        Some(id) => {
            let conn = state.meta.lock().await;
            match load_admin_profile(&conn, id) {
                Ok(Some(p)) => p,
                _ => AdminProfileExt::placeholder(),
            }
        }
        None => AdminProfileExt::placeholder(),
    };
    req.extensions_mut().insert(profile);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initials_from_two_word_name() {
        let r = AdminProfileExt::compute_initials(Some("Kael Lim"), None);
        assert_eq!(r, "K");
    }

    #[test]
    fn initials_from_multi_word_uses_first_char() {
        let r = AdminProfileExt::compute_initials(Some("Mary Anne Smith"), None);
        assert_eq!(r, "M");
    }

    #[test]
    fn initials_from_single_word() {
        let r = AdminProfileExt::compute_initials(Some("Kael"), None);
        assert_eq!(r, "K");
    }

    #[test]
    fn initials_from_single_char_name() {
        let r = AdminProfileExt::compute_initials(Some("X"), None);
        assert_eq!(r, "X");
    }

    #[test]
    fn initials_from_cjk_name() {
        let r = AdminProfileExt::compute_initials(Some("林宇軒"), None);
        assert_eq!(r, "林");
    }

    #[test]
    fn initials_fall_back_to_email_local_part() {
        let r = AdminProfileExt::compute_initials(None, Some("kael1996@tzuchi-org.tw"));
        assert_eq!(r, "K");
    }

    #[test]
    fn initials_empty_name_falls_through_to_email() {
        let r = AdminProfileExt::compute_initials(Some("   "), Some("alice@example.com"));
        assert_eq!(r, "A");
    }

    #[test]
    fn initials_both_none_returns_placeholder() {
        let r = AdminProfileExt::compute_initials(None, None);
        assert_eq!(r, "?");
    }

    #[test]
    fn initials_email_with_single_char_local() {
        let r = AdminProfileExt::compute_initials(None, Some("z@example.com"));
        assert_eq!(r, "Z");
    }

    #[test]
    fn load_admin_profile_includes_role_field() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE admins (id INTEGER PRIMARY KEY, display_name TEXT, email TEXT, picture_url TEXT, role TEXT NOT NULL DEFAULT 'member');
             INSERT INTO admins (id, display_name, email, role) VALUES (1, 'Kael', 'k@x', 'owner');
             INSERT INTO admins (id, display_name, email, role) VALUES (2, 'Phx', 'p@x', 'member');"
        ).unwrap();
        let p1 = load_admin_profile(&conn, 1).unwrap().unwrap();
        assert_eq!(p1.role, "owner");
        assert!(p1.is_owner);
        let p2 = load_admin_profile(&conn, 2).unwrap().unwrap();
        assert_eq!(p2.role, "member");
        assert!(!p2.is_owner);
    }

    #[test]
    fn placeholder_defaults_to_member_role() {
        let p = AdminProfileExt::placeholder();
        assert_eq!(p.role, "member");
        assert!(!p.is_owner);
    }
}
