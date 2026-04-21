// Admin password rotation CLI.
//
// Usage: reads username from argv[1] and password from stdin (one line).
//   sudo -u drust bash -c 'read -s P && DRUST_DATA_DIR=/var/lib/drust \
//     ./target/release/set_admin_password admin <<< "$P"'
//
// Uses drust's own argon2id hasher so the stored hash is indistinguishable
// from a bootstrap-time hash.

use std::io::{self, BufRead, Write};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <username>", args[0]);
        eprintln!("  reads password from stdin (one line)");
        std::process::exit(2);
    }
    let username = &args[1];

    let data_dir: std::path::PathBuf = std::env::var("DRUST_DATA_DIR")
        .map_err(|_| anyhow::anyhow!("DRUST_DATA_DIR env var is required"))?
        .into();
    let meta_path = data_dir.join("meta.sqlite");

    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let password = line.trim_end_matches('\n').trim_end_matches('\r');
    if password.is_empty() {
        anyhow::bail!("empty password from stdin");
    }

    let hash = drust::auth::admin::hash_password(password)?;

    let conn = rusqlite::Connection::open(&meta_path)?;
    let updated = conn.execute(
        "UPDATE admins SET password_hash = ?1 WHERE username = ?2",
        rusqlite::params![hash, username],
    )?;
    if updated == 0 {
        anyhow::bail!("no admin row with username = {username:?}");
    }

    writeln!(io::stderr(), "updated password_hash for admin {username:?}")?;
    Ok(())
}
