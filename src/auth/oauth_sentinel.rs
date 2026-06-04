//! OAuth-only user marker. v1.12+ inserts this exact string into
//! `_system_users.password_hash` when a user is created via OAuth and
//! has no password. The password-login handler short-circuits BEFORE
//! argon2 verify when this sentinel is seen.

pub const OAUTH_ONLY_SENTINEL: &str = "$oauth-only$";

/// True iff a stored password_hash is the OAuth-only sentinel.
pub fn is_oauth_only(stored_hash: &str) -> bool {
    stored_hash == OAUTH_ONLY_SENTINEL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_round_trip() {
        assert!(is_oauth_only(OAUTH_ONLY_SENTINEL));
        assert!(!is_oauth_only("$argon2id$v=19$m=19456,t=2,p=1$abc$def"));
        assert!(!is_oauth_only(""));
        assert!(!is_oauth_only("$oauth-only")); // missing closing $
        assert!(!is_oauth_only("$oauth-only$x")); // suffix
    }
}
