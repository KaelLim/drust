//! MCP OAuth token primitives: the four credential families the authorization
//! server mints (access, refresh, authorization code, upload ticket), their
//! domain-separated hashes, and the prefix + length shape check every dispatch
//! between credential families goes through.
//!
//! Only hashes are ever stored (`_mcp_*` tables); the plaintext leaves the
//! process once, in the response that mints it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const ACCESS_PREFIX: &str = "drust_mcpat_";
pub const REFRESH_PREFIX: &str = "drust_mcprt_";
pub const UPLOAD_TICKET_PREFIX: &str = "drust_upl_";
const BODY_LEN: usize = 43; // base64url_nopad(32 bytes)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Access,
    Refresh,
    Code,
    UploadTicket,
}

impl TokenKind {
    const fn prefix(self) -> &'static str {
        match self {
            Self::Access => ACCESS_PREFIX,
            Self::Refresh => REFRESH_PREFIX,
            Self::Code => "",
            Self::UploadTicket => UPLOAD_TICKET_PREFIX,
        }
    }

    /// FROZEN with the DDL: every stored hash depends on these bytes.
    const fn tag(self) -> &'static [u8] {
        match self {
            Self::Access => b"drust-mcp-at-v1\0",
            Self::Refresh => b"drust-mcp-rt-v1\0",
            Self::Code => b"drust-mcp-code-v1\0",
            Self::UploadTicket => b"drust-mcp-upl-v1\0",
        }
    }
}

pub fn new_token(kind: TokenKind) -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{}{}", kind.prefix(), URL_SAFE_NO_PAD.encode(b))
}

/// base64url_nopad(SHA-256(tag || full token incl. prefix)). Callers look rows up BY this
/// value (`WHERE token_hash = ?`); never compare hashes in Rust.
pub fn hash(kind: TokenKind, token: &str) -> String {
    let mut h = Sha256::new();
    h.update(kind.tag());
    h.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(h.finalize())
}

/// Prefix + total byte length only. A false here means: do not touch the DB.
/// Every dispatch between credential families MUST go through this, never a bare
/// `starts_with`: every drust credential starts with `drust_`, a tenant bearer is
/// `drust_` + 43 random chars (49), so its random body can itself begin with `upl_` or
/// `mcpat_`. The families are kept apart by prefix AND length together.
pub fn looks_like(kind: TokenKind, s: &str) -> bool {
    s.len() == kind.prefix().len() + BODY_LEN && s.starts_with(kind.prefix())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{admin_token, bearer, user_session};

    const ALL: [TokenKind; 4] = [
        TokenKind::Access,
        TokenKind::Refresh,
        TokenKind::Code,
        TokenKind::UploadTicket,
    ];

    fn is_b64url(s: &str) -> bool {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    #[test]
    fn prefixes_and_lengths() {
        for (kind, prefix, len) in [
            (TokenKind::Access, "drust_mcpat_", 55),
            (TokenKind::Refresh, "drust_mcprt_", 55),
            (TokenKind::UploadTicket, "drust_upl_", 53),
        ] {
            let t = new_token(kind);
            assert!(t.starts_with(prefix), "{kind:?}: {}", &t[..prefix.len()]);
            assert_eq!(t.len(), len, "{kind:?}");
            assert!(is_b64url(&t[prefix.len()..]), "{kind:?} body not base64url");
        }
        let code = new_token(TokenKind::Code);
        assert_eq!(code.len(), 43);
        assert!(!code.starts_with("drust_"));
        assert!(is_b64url(&code));
    }

    #[test]
    fn new_token_is_random() {
        for kind in ALL {
            assert_ne!(new_token(kind), new_token(kind), "{kind:?}");
        }
    }

    #[test]
    fn golden_vectors() {
        // Computed outside Rust: base64url_nopad(sha256(tag + token)). A change
        // here means every stored hash stops matching — the tags are frozen.
        let a43 = "A".repeat(43);
        assert_eq!(
            hash(TokenKind::Access, &format!("drust_mcpat_{a43}")),
            "Q3MaYxgD1nygzT0qzdbOXIKeyrjhcZ_CVB4x4EREIds"
        );
        assert_eq!(
            hash(TokenKind::Refresh, &format!("drust_mcprt_{a43}")),
            "aDdRoaHVVig3mBh-qPlCYX_qG49_0zWrraYiDiTW4dI"
        );
        assert_eq!(
            hash(TokenKind::Code, &a43),
            "6gR2Gkkdaa383vMcNaMEUnE-0jfiQwcyOUaVYtm87RU"
        );
        assert_eq!(
            hash(TokenKind::UploadTicket, &format!("drust_upl_{a43}")),
            "YCfAAK6bhwTPTyxz-VIxy35dbaEHqIkWTyRoq7y1AVY"
        );
        // Control: the same token WITHOUT a tag is admin_token::hash_token's value.
        assert_eq!(
            admin_token::hash_token(&format!("drust_mcpat_{a43}")),
            "AMS19SGDhwkGwZApEBe-V-dpFrOHmWhTf30h7AZYqU4"
        );
    }

    #[test]
    fn hashes_are_domain_separated() {
        let s = "drust_mcpat_".to_string() + &"x".repeat(43);
        let hashes: Vec<String> = ALL.iter().map(|k| hash(*k, &s)).collect();
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "{:?} vs {:?}", ALL[i], ALL[j]);
            }
            assert_ne!(hashes[i], admin_token::hash_token(&s), "{:?}", ALL[i]);
            assert_ne!(hashes[i], bearer::hash_token(&s), "{:?}", ALL[i]);
        }
    }

    #[test]
    fn hash_shape() {
        for kind in ALL {
            let h = hash(kind, &new_token(kind));
            assert_eq!(h.len(), 43, "{kind:?}");
            assert!(is_b64url(&h), "{kind:?}");
        }
    }

    #[test]
    fn looks_like_prefix_and_length() {
        for kind in ALL {
            let t = new_token(kind);
            assert!(looks_like(kind, &t), "{kind:?}");
            assert!(!looks_like(kind, &t[..t.len() - 1]), "{kind:?} one short");
            assert!(!looks_like(kind, &format!("{t}A")), "{kind:?} one long");
            assert!(!looks_like(kind, ""), "{kind:?} empty");
            assert!(
                !looks_like(kind, &admin_token::generate_token()),
                "{kind:?} PAT"
            );
        }
        // Swap the prefix for another family's.
        let body = "B".repeat(43);
        assert!(!looks_like(
            TokenKind::Access,
            &format!("{REFRESH_PREFIX}{body}")
        ));
        assert!(!looks_like(
            TokenKind::Refresh,
            &format!("{ACCESS_PREFIX}{body}")
        ));
        assert!(!looks_like(
            TokenKind::UploadTicket,
            &format!("drust_pat_{body}")
        ));
        assert!(!looks_like(TokenKind::Code, &new_token(TokenKind::Access)));
    }

    #[test]
    fn namespaces_do_not_collide() {
        // Guard test: reads the constants only, so it is green before the
        // primitives exist. It pins the prefix namespaces, not behaviour.
        assert!(!ACCESS_PREFIX.starts_with(admin_token::TOKEN_PREFIX));
        assert!(!REFRESH_PREFIX.starts_with(admin_token::TOKEN_PREFIX));
        assert!(!"drust_user_".starts_with(UPLOAD_TICKET_PREFIX));
        assert!(!UPLOAD_TICKET_PREFIX.starts_with("drust_user_"));
    }

    #[test]
    fn foreign_credentials_never_look_like_ours() {
        let gens: [(&str, fn() -> String); 4] = [
            ("tenant bearer", bearer::generate_token),
            ("admin PAT", admin_token::generate_token),
            ("CLI PAT", admin_token::generate_cli_token),
            ("user session", user_session::generate_token),
        ];
        for (name, generate) in gens {
            for _ in 0..1_000 {
                let t = generate();
                for kind in ALL {
                    assert!(!looks_like(kind, &t), "{name} looked like {kind:?}");
                }
            }
        }
        // Prefix alone would collide: a tenant bearer is `drust_` + 43 random
        // chars, so its body can begin with `upl_`. Length keeps it out.
        let bearer_shaped = format!("drust_upl_{}", "A".repeat(39));
        assert_eq!(bearer_shaped.len(), 49);
        assert!(!looks_like(TokenKind::UploadTicket, &bearer_shaped));
        // A PAT and an upload ticket are both 53 bytes; the prefixes keep them
        // apart, so neither may be a prefix of the other.
        assert_eq!(admin_token::generate_token().len(), 53);
        assert!(!UPLOAD_TICKET_PREFIX.starts_with(admin_token::TOKEN_PREFIX));
        assert!(!admin_token::TOKEN_PREFIX.starts_with(UPLOAD_TICKET_PREFIX));
    }
}
