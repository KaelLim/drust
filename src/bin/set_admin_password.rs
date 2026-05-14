// Admin password rotation CLI.
//
// Usage:
//   sudo -u drust bash -c 'read -s P && DRUST_DATA_DIR=/var/lib/drust \
//     ./target/release/set_admin_password --username admin <<< "$P"'
//
//   Optional --email <addr> populates admins.email at the same time so
//   the admin row is OAuth-linkable (v1.11+).
//
// Uses drust's own argon2id hasher so the stored hash is indistinguishable
// from a bootstrap-time hash.

use std::io::{self, Read};

fn print_usage() {
    eprintln!("usage: drust_set_admin_password --username <name> [--email <addr>]");
    eprintln!("       password is read from stdin");
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut username: Option<String> = None;
    let mut email: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--username" => username = args.next(),
            "--email" => email = args.next(),
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
    let username = username.ok_or_else(|| anyhow::anyhow!("--username required"))?;

    let data_dir: std::path::PathBuf = std::env::var("DRUST_DATA_DIR")
        .map_err(|_| anyhow::anyhow!("DRUST_DATA_DIR env var is required"))?
        .into();
    let meta_path = data_dir.join("meta.sqlite");

    let mut password = String::new();
    io::stdin().read_to_string(&mut password)?;
    let password = password.trim_end_matches('\n').trim_end_matches('\r');
    if password.is_empty() {
        anyhow::bail!("empty password from stdin");
    }

    drust::bin_helpers::set_admin_password_with_email(
        &meta_path,
        &username,
        password,
        email.as_deref(),
    )?;

    eprintln!("updated password_hash for admin {username:?}");
    Ok(())
}
