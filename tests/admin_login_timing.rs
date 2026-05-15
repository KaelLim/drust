//! S1 timing-spread test for admin password login.
//!
//! Mirrors the user-side test in src/auth/user.rs:58. Verifying against
//! `dummy_hash()` must take comparable wall-clock to verifying against a real
//! hash, so an attacker cannot distinguish "unknown username" from "wrong
//! password" by timing alone.
//!
//! Run with `cargo test --test admin_login_timing -- --ignored --nocapture`
//! (NOT `--release` — see CLAUDE.md; LTO + 1 codegen-unit make release tests
//! take 40+ minutes in this repo).

/// Spec S1: a verify against the admin DUMMY_HASH must take comparable
/// wall-clock to a verify against a real admin password hash. We tolerate a
/// 4× spread.
///
/// Note: debug-mode Argon2 amplifies jitter compared to release mode, so
/// the assertion may be flaky on very slow CI. The test is `#[ignore]`-gated
/// so it only runs on explicit request.
#[test]
#[ignore]
fn admin_dummy_hash_is_not_a_short_circuit() {
    use drust::auth::admin::{dummy_hash, hash_password, verify_password};
    use std::time::Instant;

    let real_hash = hash_password("admin-benchmark-pw-123").unwrap();

    let warm = Instant::now();
    verify_password(&real_hash, "admin-benchmark-pw-123").unwrap();
    let real_dur = warm.elapsed();

    let cold = Instant::now();
    verify_password(dummy_hash(), "admin-benchmark-pw-123").unwrap();
    let dummy_dur = cold.elapsed();

    let ratio = real_dur.as_nanos() as f64 / dummy_dur.as_nanos().max(1) as f64;
    assert!(
        ratio < 4.0 && ratio > 0.25,
        "dummy ({dummy_dur:?}) and real ({real_dur:?}) verify must be in the same order of magnitude (S1); ratio={ratio:.2}"
    );
}

/// Sanity: dummy_hash is idempotent and never verifies against any real input.
#[test]
fn admin_dummy_hash_is_constant_and_never_verifies() {
    use drust::auth::admin::{dummy_hash, verify_password};

    let d1 = dummy_hash().to_owned();
    let d2 = dummy_hash().to_owned();
    assert_eq!(d1, d2, "dummy_hash must be a constant, not regenerated");
    assert!(
        !verify_password(dummy_hash(), "anything").unwrap(),
        "dummy_hash must never verify against any password"
    );
}
