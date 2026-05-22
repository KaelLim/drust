//! Locale resolution + `Extension<Locale>` attachment for admin requests.
//!
//! Resolution order:
//!   1. `drust_locale` cookie (long-lived, set by topbar dropdown)
//!   2. `Accept-Language` header — first supported tag in priority order
//!   3. Default `Locale::En`
//!
//! Mounted as the OUTERMOST layer on the admin router so `/login` and the
//! OAuth callback chain are covered (users must be able to switch language
//! before authenticating).

use axum::{
    extract::Request,
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::CookieJar;

use crate::mgmt::i18n::Locale;

pub async fn locale_layer(
    jar: CookieJar,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Response {
    let locale = resolve_locale(&jar, &headers);
    req.extensions_mut().insert(locale);
    next.run(req).await
}

pub fn resolve_locale(jar: &CookieJar, headers: &HeaderMap) -> Locale {
    // (1) cookie wins
    if let Some(c) = jar.get("drust_locale") {
        if let Some(l) = Locale::from_tag(c.value()) {
            return l;
        }
    }
    // (2) Accept-Language header — process each tag in order, ignore q-weights
    if let Some(al) = headers.get("accept-language").and_then(|v| v.to_str().ok()) {
        for tag in al
            .split(',')
            .map(|s| s.split(';').next().unwrap_or("").trim())
        {
            if let Some(l) = Locale::from_tag(tag) {
                return l;
            }
        }
    }
    // (3) default
    Locale::En
}

// ------------------------------------------------------------------------
// Unit tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use axum_extra::extract::cookie::{Cookie, CookieJar};

    fn jar_with(name: &str, val: &str) -> CookieJar {
        CookieJar::new().add(Cookie::new(name.to_string(), val.to_string()))
    }

    #[test]
    fn cookie_wins_over_header() {
        let mut h = HeaderMap::new();
        h.insert("accept-language", "zh-TW".parse().unwrap());
        let jar = jar_with("drust_locale", "en");
        assert_eq!(resolve_locale(&jar, &h), Locale::En);
    }

    #[test]
    fn header_used_when_no_cookie() {
        let mut h = HeaderMap::new();
        h.insert("accept-language", "zh-TW".parse().unwrap());
        assert_eq!(resolve_locale(&CookieJar::new(), &h), Locale::ZhTw);
    }

    #[test]
    fn permissive_zh_hant_tw_matches() {
        let mut h = HeaderMap::new();
        h.insert("accept-language", "zh-Hant-TW".parse().unwrap());
        assert_eq!(resolve_locale(&CookieJar::new(), &h), Locale::ZhTw);
    }

    #[test]
    fn priority_list_picks_first_supported() {
        let mut h = HeaderMap::new();
        h.insert(
            "accept-language",
            "ja-JP, zh-TW;q=0.8, en;q=0.5".parse().unwrap(),
        );
        assert_eq!(resolve_locale(&CookieJar::new(), &h), Locale::ZhTw);
    }

    #[test]
    fn no_supported_tag_falls_back_to_en() {
        let mut h = HeaderMap::new();
        h.insert("accept-language", "ja-JP, fr-FR".parse().unwrap());
        assert_eq!(resolve_locale(&CookieJar::new(), &h), Locale::En);
    }
}
