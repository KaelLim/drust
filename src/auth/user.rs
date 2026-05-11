use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use once_cell::sync::Lazy;

/// argon2id PHC string for a password the attacker cannot guess. Used by login when the
/// email is unknown to make the response timing match the "email exists, wrong password"
/// path. Never a valid credential because no user can register an empty password.
pub static DUMMY_HASH: Lazy<String> = Lazy::new(|| {
    hash_password("__drust_dummy__never_a_real_password__")
        .expect("DUMMY_HASH bootstrap")
});

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let phc = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?
        .to_string();
    Ok(phc)
}

pub fn verify_password(password: &str, phc: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(phc).map_err(|e| anyhow::anyhow!("phc parse: {e}"))?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("argon2 verify: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn hash_then_verify_roundtrips() {
        let h = hash_password("hunter2hunter").unwrap();
        assert!(verify_password("hunter2hunter", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn dummy_hash_is_constant_and_verifies_against_nothing() {
        let d1 = DUMMY_HASH.to_string();
        let d2 = DUMMY_HASH.to_string();
        assert_eq!(d1, d2); // it's a constant, not regenerated
        assert!(!verify_password("anything", &DUMMY_HASH).unwrap());
    }

    /// Spec S1: a verify against DUMMY_HASH must take comparable wall-clock to a real verify.
    /// We tolerate a 4× spread (real verify ~100ms; dummy verify must be > 25ms).
    /// Run with `cargo test --release`; debug-mode Argon2 amplifies jitter.
    #[test]
    fn dummy_hash_is_not_a_short_circuit() {
        let real_hash = hash_password("benchmarkpassword").unwrap();
        let warm = Instant::now();
        verify_password("benchmarkpassword", &real_hash).unwrap();
        let real_dur = warm.elapsed();

        let cold = Instant::now();
        verify_password("benchmarkpassword", &DUMMY_HASH).unwrap();
        let dummy_dur = cold.elapsed();

        let ratio = real_dur.as_nanos() as f64 / dummy_dur.as_nanos().max(1) as f64;
        assert!(
            ratio < 4.0 && ratio > 0.25,
            "dummy ({:?}) and real ({:?}) verify must be in the same order of magnitude (S1)",
            dummy_dur, real_dur
        );
    }
}
