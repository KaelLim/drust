//! Break-glass CLI: set an admin's role by email. v1.29.0.
//!
//! Usage:
//!   sudo -u drust DRUST_DATA_DIR=/var/lib/drust \
//!     ./target/release/set_admin_role --email <addr> --role owner|member
//!
//! Mirrors the DRUST_DATA_DIR convention used by set_admin_password.

use rusqlite::params;
use std::path::PathBuf;

fn print_usage() {
    eprintln!("usage: set_admin_role --email <addr> --role owner|member");
    eprintln!("       DRUST_DATA_DIR must be set (default path: /var/lib/drust)");
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut email: Option<String> = None;
    let mut role: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--email" => email = args.next(),
            "--role" => role = args.next(),
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            other => {
                eprintln!("unknown arg: {other}");
                print_usage();
                std::process::exit(2);
            }
        }
    }
    let email = email.ok_or_else(|| anyhow::anyhow!("--email required"))?;
    let role = role.ok_or_else(|| anyhow::anyhow!("--role required"))?;
    if role != "owner" && role != "member" {
        anyhow::bail!("--role must be owner|member, got: {role:?}");
    }

    let data_dir: PathBuf = std::env::var("DRUST_DATA_DIR")
        .map_err(|_| anyhow::anyhow!("DRUST_DATA_DIR env var is required"))?
        .into();
    let meta_path = data_dir.join("meta.sqlite");

    let conn = rusqlite::Connection::open(&meta_path)?;

    let id: i64 = conn
        .query_row(
            "SELECT id FROM admins WHERE email = ?1",
            params![&email],
            |r| r.get(0),
        )
        .map_err(|_| anyhow::anyhow!("no admin found with email {email:?}"))?;

    let before: String = conn.query_row(
        "SELECT role FROM admins WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )?;

    conn.execute(
        "UPDATE admins SET role = ?1 WHERE id = ?2",
        params![&role, id],
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "id": id,
            "email": email,
            "role_before": before,
            "role_after": role,
        }))?
    );
    Ok(())
}
