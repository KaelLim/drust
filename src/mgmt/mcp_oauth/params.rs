//! Form / query parameter parsing for the OAuth endpoints (MA0-PLAN §3.3).
//!
//! The endpoints parse their own bodies instead of using axum's `Form`, so a
//! repeated key, an empty value and an oversized body each get a controlled
//! answer rather than an extractor rejection.

/// Decoded `(key, value)` pairs in request order. Empty keys and empty values
/// were dropped at parse time.
pub struct Params {
    pairs: Vec<(String, String)>,
}

/// `Duplicate` is never returned today: `parse_pairs` reports repetition
/// through `Params::is_duplicated` and lets the caller pick the error.
#[derive(Debug)]
pub enum ParamError {
    Duplicate(String),
    TooLong,
}

/// `url::form_urlencoded::parse` (`+` = space, lossy UTF-8). Parameters without
/// a value are treated as absent (OAuth 2.1 §3.2: "MUST be treated as if they
/// were omitted"), so they never count toward `is_duplicated`; a pair with an
/// empty key is dropped too. Never fails on a repeated key — the caller decides
/// (RFC 8707 lets `resource` repeat; drust refuses it). Repetition is judged on
/// the DECODED key, so `grant%5Ftype` repeats `grant_type`.
pub fn parse_pairs(raw: &[u8], max_total: usize) -> Result<Params, ParamError> {
    if raw.len() > max_total {
        return Err(ParamError::TooLong);
    }
    let pairs = url::form_urlencoded::parse(raw)
        .filter(|(k, v)| !k.is_empty() && !v.is_empty())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    Ok(Params { pairs })
}

impl Params {
    /// The first value of `k`. Callers check `is_duplicated` first.
    pub fn get(&self, k: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, k: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// More than one (non-empty) occurrence of `k`.
    pub fn is_duplicated(&self, k: &str) -> bool {
        self.pairs.iter().filter(|(key, _)| key == k).count() > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &[u8]) -> Params {
        match parse_pairs(raw, 16 * 1024) {
            Ok(p) => p,
            Err(_) => panic!("parse_pairs refused {raw:?}"),
        }
    }

    #[test]
    fn reads_pairs_and_decodes_form_encoding() {
        let p = parse(b"a=1&b=x+y&c=%41");
        assert_eq!(p.get("a"), Some("1"));
        assert_eq!(p.get("b"), Some("x y"));
        assert_eq!(p.get("c"), Some("A"));
    }

    #[test]
    fn an_empty_value_is_absent() {
        let p = parse(b"a=&b=2");
        assert_eq!(p.get("a"), None);
        assert!(!p.is_duplicated("a"));
        assert!(p.get_all("a").is_empty());
        assert_eq!(p.get("b"), Some("2"));
    }

    #[test]
    fn an_empty_duplicate_is_not_a_duplicate() {
        let p = parse(b"grant_type=&grant_type=refresh_token");
        assert!(!p.is_duplicated("grant_type"));
        assert_eq!(p.get("grant_type"), Some("refresh_token"));
    }

    #[test]
    fn a_repeated_key_is_reported_not_rejected() {
        let p = parse(b"a=1&a=2");
        assert!(p.is_duplicated("a"));
        assert_eq!(p.get_all("a"), vec!["1", "2"]);
        assert_eq!(p.get("a"), Some("1"));
    }

    #[test]
    fn an_empty_key_is_dropped() {
        let p = parse(b"=x&a=1");
        assert_eq!(p.get(""), None);
        assert_eq!(p.get("a"), Some("1"));
    }

    #[test]
    fn over_the_limit_is_too_long() {
        assert!(matches!(
            parse_pairs(&[b'a'; 17], 16),
            Err(ParamError::TooLong)
        ));
    }

    #[test]
    fn exactly_the_limit_parses() {
        assert!(parse_pairs(b"a=12345678901234", 16).is_ok());
    }

    #[test]
    fn invalid_utf8_does_not_panic() {
        let p = parse(b"a=%FF%FE&b=\xff");
        // Lossy decoding: both keys survive with replacement characters.
        assert!(p.get("a").is_some());
        assert!(p.get("b").is_some());
    }
}
