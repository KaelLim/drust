use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::sync::OnceLock;

/// argon2id PHC string for a password the attacker cannot guess. Used by login when the
/// email is unknown to make the response timing match the "email exists, wrong password"
/// path. Never a valid credential because no user can register an empty password.
pub fn dummy_hash() -> &'static str {
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    DUMMY_HASH.get_or_init(|| {
        hash_password("__drust_dummy__never_a_real_password__")
            .expect("DUMMY_HASH bootstrap")
    })
}

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
        let d1 = dummy_hash().to_owned();
        let d2 = dummy_hash().to_owned();
        assert_eq!(d1, d2); // it's a constant, not regenerated
        assert!(!verify_password("anything", dummy_hash()).unwrap());
    }

    /// Spec S1: a verify against DUMMY_HASH must take comparable wall-clock to a real verify.
    /// We tolerate a 4× spread (real verify ~100ms; dummy verify must be > 25ms).
    /// Run with `cargo test -- --ignored --nocapture` (NOT `--release` — LTO + 1 codegen-unit
    /// make `--release` tests take 40+ minutes in this repo; see CLAUDE.md).
    #[test]
    fn dummy_hash_is_not_a_short_circuit() {
        let real_hash = hash_password("benchmarkpassword").unwrap();
        let warm = Instant::now();
        verify_password("benchmarkpassword", &real_hash).unwrap();
        let real_dur = warm.elapsed();

        let cold = Instant::now();
        verify_password("benchmarkpassword", dummy_hash()).unwrap();
        let dummy_dur = cold.elapsed();

        let ratio = real_dur.as_nanos() as f64 / dummy_dur.as_nanos().max(1) as f64;
        assert!(
            ratio < 4.0 && ratio > 0.25,
            "dummy ({:?}) and real ({:?}) verify must be in the same order of magnitude (S1)",
            dummy_dur, real_dur
        );
    }
}
