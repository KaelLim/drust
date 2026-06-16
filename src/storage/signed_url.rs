//! Drust-minted, drust-served signed URLs for private file downloads.
//!
//! The existing S3-level pre-signed URL points at `127.0.0.1:47830` (Garage's
//! S3 API) which isn't reachable from outside the host. Instead, admin and
//! tenant "sign URL" flows mint an HMAC-SHA256 token bound to
//! `(owner | key | expires | download_mode)` and return a URL that points at
//! drust's own public origin. A public unauth'd handler validates the token,
//! then streams the bytes from Garage through drust.
//!
//! The HMAC secret is generated once at drust startup (32 random bytes) and
//! kept only in memory. Restart invalidates outstanding signed URLs — a
//! deliberate trade-off: keeps the secret out of disk state at the cost of
//! short-lived URLs becoming broken across restarts.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub enum Owner {
    Admin,
    Tenant(String),
}

impl Owner {
    fn label(&self) -> String {
        match self {
            Owner::Admin => "admin".into(),
            Owner::Tenant(id) => format!("t:{id}"),
        }
    }
}

fn compute(secret: &[u8], owner: &Owner, key: &str, expires: i64, download: bool) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any length");
    mac.update(owner.label().as_bytes());
    mac.update(b"|");
    mac.update(key.as_bytes());
    mac.update(b"|");
    mac.update(expires.to_string().as_bytes());
    mac.update(b"|");
    mac.update(if download { b"1" } else { b"0" });
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn mint(secret: &[u8], owner: &Owner, key: &str, expires: i64, download: bool) -> String {
    compute(secret, owner, key, expires, download)
}

pub fn verify(
    secret: &[u8],
    owner: &Owner,
    key: &str,
    expires: i64,
    download: bool,
    token: &str,
) -> bool {
    if expires <= chrono::Utc::now().timestamp() {
        return false;
    }
    let expected = compute(secret, owner, key, expires, download);
    expected.as_bytes().ct_eq(token.as_bytes()).into()
}

/// Build the drust-public URL for a signed download. The URL format is:
///
/// `{base}/drust/s/admin/{key}?e={expires}&t={token}&d={0|1}`
/// `{base}/drust/s/t/{tenant}/{key}?e={expires}&t={token}&d={0|1}`
pub fn build_url(
    base: &str,
    owner: &Owner,
    key: &str,
    expires: i64,
    download: bool,
    token: &str,
) -> String {
    let path = match owner {
        Owner::Admin => crate::base_path::base(&format!("/s/admin/{key}")),
        Owner::Tenant(id) => crate::base_path::base(&format!("/s/t/{id}/{key}")),
    };
    let d = if download { "1" } else { "0" };
    format!(
        "{}{}?e={expires}&t={token}&d={d}",
        base.trim_end_matches('/'),
        path
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_and_verify_roundtrip() {
        let secret = [0x42u8; 32];
        let exp = chrono::Utc::now().timestamp() + 60;
        let tok = mint(&secret, &Owner::Admin, "file.txt", exp, false);
        assert!(verify(&secret, &Owner::Admin, "file.txt", exp, false, &tok));
    }

    #[test]
    fn expired_tokens_fail() {
        let secret = [0x42u8; 32];
        let exp = chrono::Utc::now().timestamp() - 1;
        let tok = mint(&secret, &Owner::Admin, "a", exp, false);
        assert!(!verify(&secret, &Owner::Admin, "a", exp, false, &tok));
    }

    #[test]
    fn tampered_key_fails() {
        let secret = [0x42u8; 32];
        let exp = chrono::Utc::now().timestamp() + 60;
        let tok = mint(&secret, &Owner::Admin, "a", exp, false);
        assert!(!verify(&secret, &Owner::Admin, "b", exp, false, &tok));
    }

    #[test]
    fn owner_distinction() {
        let secret = [0x42u8; 32];
        let exp = chrono::Utc::now().timestamp() + 60;
        let tok_admin = mint(&secret, &Owner::Admin, "a", exp, false);
        assert!(!verify(
            &secret,
            &Owner::Tenant("acme".into()),
            "a",
            exp,
            false,
            &tok_admin
        ));
    }

    #[test]
    fn download_flag_distinction() {
        let secret = [0x42u8; 32];
        let exp = chrono::Utc::now().timestamp() + 60;
        let tok = mint(&secret, &Owner::Admin, "a", exp, false);
        assert!(!verify(&secret, &Owner::Admin, "a", exp, true, &tok));
    }
}
