//! `drust_set_admin_password --email kael@example.com` populates the
//! `admins.email` column for an existing admin username. Invalid emails
//! are rejected before write.

use rusqlite::Connection;

/// Helper: seed an admin row using the real bootstrap path. `create_admin`
/// doesn't exist in `storage::meta` — the only public seeder is
/// `bootstrap_admin(&mut Connection, username, plaintext) -> Result<bool>`,
/// which inserts only when the `admins` table is empty.
fn seed_admin(meta: &std::path::Path, username: &str, password: &str) {
    let mut conn = drust::storage::meta::open_meta(meta).unwrap();
    let inserted = drust::storage::meta::bootstrap_admin(&mut conn, username, password).unwrap();
    assert!(inserted, "bootstrap_admin should insert on a fresh DB");
}

#[test]
fn cli_sets_email_for_existing_admin() {
    let dir = tempfile::tempdir().unwrap();
    let meta = dir.path().join("meta.sqlite");
    seed_admin(&meta, "kael", "init_password");

    drust::bin_helpers::set_admin_password_with_email(
        &meta,
        "kael",
        "new_password",
        Some("kael@example.com"),
    )
    .unwrap();

    let conn = Connection::open(&meta).unwrap();
    let email: Option<String> = conn
        .query_row(
            "SELECT email FROM admins WHERE username = ?1",
            ["kael"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(email.as_deref(), Some("kael@example.com"));
}

#[test]
fn cli_rejects_malformed_email() {
    let dir = tempfile::tempdir().unwrap();
    let meta = dir.path().join("meta.sqlite");
    seed_admin(&meta, "kael", "init");

    let err =
        drust::bin_helpers::set_admin_password_with_email(&meta, "kael", "x", Some("not-an-email"))
            .unwrap_err();
    assert!(err.to_string().contains("invalid email"), "got: {err}");
}
