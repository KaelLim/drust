//! Pinned OAuth clients. drust accepts exactly the clients listed here; there
//! is no dynamic registration and no live CIMD fetch (MA3).

pub struct KnownClient {
    pub client_id: &'static str,
    pub display_name: &'static str,
    pub redirect_uris: &'static [&'static str],
    pub source_url: &'static str,
    pub pinned_on: &'static str,
}

/// Pinned copy of Claude Code's client ID metadata document (no live fetch
/// until MA3). Release checklist: re-fetch `source_url` and compare every
/// release (design §4.3).
pub const KNOWN_CLIENTS: &[KnownClient] = &[KnownClient {
    client_id: "https://claude.ai/oauth/claude-code-client-metadata",
    display_name: "Claude Code",
    redirect_uris: &["http://localhost/callback", "http://127.0.0.1/callback"],
    source_url: "https://claude.ai/oauth/claude-code-client-metadata",
    pinned_on: "2026-11-14",
}];

/// Byte-exact: no trimming, case folding or trailing-slash tolerance.
pub fn find_client(client_id: &str) -> Option<&'static KnownClient> {
    KNOWN_CLIENTS.iter().find(|c| c.client_id == client_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_claude_code_is_pinned() {
        assert_eq!(KNOWN_CLIENTS.len(), 1);
        let c = &KNOWN_CLIENTS[0];
        assert_eq!(
            c.client_id,
            "https://claude.ai/oauth/claude-code-client-metadata"
        );
        assert_eq!(
            c.redirect_uris,
            &["http://localhost/callback", "http://127.0.0.1/callback"]
        );
        assert_eq!(c.pinned_on, "2026-11-14");
    }

    #[test]
    fn find_client_is_exact_match() {
        let id = "https://claude.ai/oauth/claude-code-client-metadata";
        assert!(find_client(id).is_some());
        for miss in [
            "https://claude.ai/oauth/claude-code-client-metadata/",
            "https://CLAUDE.AI/oauth/claude-code-client-metadata",
            " https://claude.ai/oauth/claude-code-client-metadata",
            "https://claude.ai/oauth/claude-code-client-metadata ",
            "",
        ] {
            assert!(find_client(miss).is_none(), "{miss:?}");
        }
    }
}
