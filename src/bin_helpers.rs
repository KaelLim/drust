//! Shared between bin/set_admin_password.rs and tests.

use crate::auth::admin::hash_password;
use crate::storage::meta::open_meta;
use rusqlite::params;
use std::path::Path;

/// Conservative email well-formedness check — does NOT match all of
/// RFC 5322, but catches the obvious junk and is sufficient as a
/// pre-write defense against typos and audit-log injection.
pub fn validate_email(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes.len() > 254 {
        return false;
    }
    let at_count = bytes.iter().filter(|&&b| b == b'@').count();
    if at_count != 1 {
        return false;
    }
    let (local, domain) = s.split_once('@').unwrap();
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if !domain.contains('.') {
        return false;
    }
    let ok_local = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_');
    let ok_domain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-');
    local.bytes().all(ok_local) && domain.bytes().all(ok_domain)
}

pub fn set_admin_password_with_email(
    meta: &Path,
    username: &str,
    new_password: &str,
    email: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(e) = email
        && !validate_email(e)
    {
        anyhow::bail!("invalid email: {e:?}");
    }
    let conn = open_meta(meta)?;
    let hash = hash_password(new_password)?;
    let updated = if let Some(e) = email {
        conn.execute(
            "UPDATE admins SET password_hash = ?1, email = ?2 \
             WHERE username = ?3",
            params![hash, e, username],
        )?
    } else {
        conn.execute(
            "UPDATE admins SET password_hash = ?1 WHERE username = ?2",
            params![hash, username],
        )?
    };
    if updated == 0 {
        anyhow::bail!("no admin row with username = {username:?}");
    }
    Ok(())
}
