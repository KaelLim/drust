//! CLI device-flow login (RFC 8628-shaped). v1.44 (CLI Phase 2).
//!
//! Host-plane rendezvous between a headless `drust` CLI and a logged-in admin
//! browser: the CLI `POST`s `/auth/cli/device/start` to mint a `device_code`
//! (returned once, stored only as a hash) + a human `user_code`; the admin
//! opens `/auth/cli/device?user_code=…`, confirms, and `approve` mints a
//! labeled, expiring `drust_pat_cli_*` PAT; the CLI's `poll` then collects it
//! exactly once. Rows live in `meta.sqlite._cli_device_codes` and are reaped
//! hourly by [`sweep_expired_device_codes`].

use base64::Engine;
use rand::{Rng, RngCore};
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

pub const CLI_DEVICE_CODE_TTL_SECS: i64 = 900; // 15 min device-code lifetime
pub const CLI_DEVICE_POLL_INTERVAL_SECS: i64 = 5; // RFC 8628 interval
/// Crockford-ish alphabet: no I L O U / 0 1 (visually confusable).
const USER_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 128-bit device_code, returned in plaintext exactly once by `start`; only
/// its `hash_token` digest is persisted (`device_code_hash`).
pub fn generate_device_code() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Human-typed `"XXXX-XXXX"` code drawn from the confusable-free alphabet.
pub fn generate_user_code() -> String {
    let mut rng = rand::thread_rng();
    let pick = |r: &mut rand::rngs::ThreadRng| {
        USER_CODE_ALPHABET[r.gen_range(0..USER_CODE_ALPHABET.len())] as char
    };
    let a: String = (0..4).map(|_| pick(&mut rng)).collect();
    let b: String = (0..4).map(|_| pick(&mut rng)).collect();
    format!("{a}-{b}")
}

/// Best-effort hourly cleanup: delete every device-code row whose `expires_at`
/// is in the past. `expires_at` is the source of truth (poll/approve reject an
/// expired row regardless), so a missed sweep only leaves rows lingering until
/// the next one. Returns the number of rows deleted.
pub async fn sweep_expired_device_codes(meta: &Arc<Mutex<Connection>>) -> usize {
    let conn = meta.lock().await;
    conn.execute(
        "DELETE FROM _cli_device_codes WHERE datetime(expires_at) < datetime('now')",
        [],
    )
    .unwrap_or(0)
}

#[cfg(test)]
mod gen_tests {
    use super::*;
    #[test]
    fn user_code_excludes_confusables_and_is_grouped() {
        for _ in 0..200 {
            let c = generate_user_code();
            assert_eq!(c.len(), 9); // XXXX-XXXX
            assert_eq!(&c[4..5], "-");
            for ch in c.chars().filter(|c| *c != '-') {
                assert!(!"ILOU01".contains(ch), "confusable {ch} leaked into {c}");
                assert!(USER_CODE_ALPHABET.contains(&(ch as u8)));
            }
        }
    }
    #[test]
    fn device_code_is_high_entropy_and_hashes_stably() {
        let a = generate_device_code();
        let b = generate_device_code();
        assert_ne!(a, b);
        assert!(a.len() >= 20); // 16 bytes base64url
        assert_eq!(
            crate::auth::admin_token::hash_token(&a),
            crate::auth::admin_token::hash_token(&a)
        ); // deterministic
        assert!(!crate::auth::admin_token::hash_token(&a).contains(&a)); // hash != plaintext
    }
}
