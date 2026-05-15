use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::rngs::OsRng;
use std::sync::OnceLock;

pub fn hash_password(plaintext: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let hash = argon
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(hash: &str, plaintext: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("parse hash: {e}"))?;
    match Argon2::default().verify_password(plaintext.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("argon2 verify: {e}")),
    }
}

/// argon2id PHC string for a password the attacker cannot guess. Used by
/// `login_submit` when the submitted username is unknown, so the response
/// timing matches the "username exists, wrong password" path and admin
/// username existence cannot be inferred via wall-clock measurement (S1).
/// Never a valid credential because no admin can register an empty password.
pub fn dummy_hash() -> &'static str {
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    DUMMY_HASH.get_or_init(|| {
        hash_password("__drust_admin_dummy__never_a_real_password__")
            .expect("admin DUMMY_HASH bootstrap")
    })
}
