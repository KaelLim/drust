//! OAuth intent cookie helpers — used to remember "where the user was going"
//! when /oauth/authorize bounces them through /login.

use axum::http::HeaderMap;

pub const COOKIE_NAME: &str = "drust_oauth_intent";

pub fn read(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{COOKIE_NAME}=")) {
            return urlencoding::decode(v).ok().map(|c| c.into_owned());
        }
    }
    None
}

pub fn build_set(path: &str, secure: bool) -> String {
    let encoded = urlencoding::encode(path);
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{COOKIE_NAME}={encoded}; Path=/drust; HttpOnly{secure_attr}; SameSite=Lax; Max-Age=600")
}

pub fn build_clear(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{COOKIE_NAME}=; Path=/drust; HttpOnly{secure_attr}; SameSite=Lax; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn read_decodes_percent_encoded_path() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            HeaderValue::from_static(
                "drust_oauth_intent=%2Foauth%2Fauthorize%3Fa%3D1",
            ),
        );
        assert_eq!(read(&h).unwrap(), "/oauth/authorize?a=1");
    }

    #[test]
    fn read_returns_none_when_absent() {
        assert!(read(&HeaderMap::new()).is_none());
    }

    #[test]
    fn build_set_uses_path_drust_and_max_age_600() {
        let v = build_set("/oauth/authorize?a=1", true);
        assert!(v.contains("Path=/drust"));
        assert!(v.contains("Max-Age=600"));
        assert!(v.contains("HttpOnly"));
        assert!(v.contains("SameSite=Lax"));
    }

    #[test]
    fn build_clear_uses_max_age_0() {
        let v = build_clear(false);
        assert!(v.contains("Max-Age=0"));
        assert!(v.contains("Path=/drust"));
        assert!(v.contains("SameSite=Lax"));
    }

    #[test]
    fn read_ignores_other_cookies() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            HeaderValue::from_static(
                "drust_session=abc123; drust_oauth_intent=%2Fadmin%2Ffoo",
            ),
        );
        assert_eq!(read(&h).unwrap(), "/admin/foo");
    }
}
