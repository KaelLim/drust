//! #925 — merged harness for the admin test group (28 of 30 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `admin_pat_bearer` and `admin_pat_reroll` are NOT here: they keep their own
//! `[[test]]` entries. Three members install a process-global audit writer via
//! `safety::audit_db::init_globals`, whose `WRITER` is a first-write-wins
//! `OnceLock` — these two plus `admin_oauth` (through
//! `common::oauth_helpers::ensure_test_audit_writer`). Only the race winner's
//! SQLite file receives rows, and each of the two pat tests asserts on rows in
//! *its own* file, so at most one could ever pass and which one is scheduling
//! luck. `admin_oauth` only needs *a* writer to exist and asserts nothing about
//! it, so it stays. Backing the losers out is the only permitted fix (鐵律 1).
//!
//! `duplicate_mod` is inherent to the merge, not a defect: every member still
//! carries its own `#[path = "helpers.rs"] mod helpers;`, and once they share a
//! crate clippy sees helpers.rs loaded 28 times. Deduping it would mean editing
//! test bodies (spec 鐵律 1 forbids that) for no gain — rustc compiles the file
//! once per module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

// Declared once for the whole harness; the members that used to declare it
// themselves now `use crate::common;` (spec 鐵律 2).
mod common;

#[path = "admin_api_audit.rs"]
mod admin_api_audit;
#[path = "admin_api_backups.rs"]
mod admin_api_backups;
#[path = "admin_api_tenants.rs"]
mod admin_api_tenants;
#[path = "admin_api_tokens.rs"]
mod admin_api_tokens;
#[path = "admin_broadcast_page.rs"]
mod admin_broadcast_page;
#[path = "admin_cap_switch_toggle.rs"]
mod admin_cap_switch_toggle;
#[path = "admin_description_write.rs"]
mod admin_description_write;
#[path = "admin_email_migration.rs"]
mod admin_email_migration;
#[path = "admin_files_routes.rs"]
mod admin_files_routes;
#[path = "admin_files_upgrade.rs"]
mod admin_files_upgrade;
#[path = "admin_frame_guard.rs"]
mod admin_frame_guard;
#[path = "admin_index_routes.rs"]
mod admin_index_routes;
#[path = "admin_login_rate_limit.rs"]
mod admin_login_rate_limit;
#[path = "admin_login_timing.rs"]
mod admin_login_timing;
#[path = "admin_metrics.rs"]
mod admin_metrics;
#[path = "admin_oauth.rs"]
mod admin_oauth;
#[path = "admin_oauth_provider_handlers.rs"]
mod admin_oauth_provider_handlers;
#[path = "admin_password.rs"]
mod admin_password;
#[path = "admin_pat_admin_plane.rs"]
mod admin_pat_admin_plane;
#[path = "admin_pat_reroll_keeps_cli.rs"]
mod admin_pat_reroll_keeps_cli;
#[path = "admin_policy_routes.rs"]
mod admin_policy_routes;
#[path = "admin_relocated_pages_smoke.rs"]
mod admin_relocated_pages_smoke;
#[path = "admin_session_pat_fallback.rs"]
mod admin_session_pat_fallback;
#[path = "admin_team_batch.rs"]
mod admin_team_batch;
#[path = "admin_team_crud.rs"]
mod admin_team_crud;
#[path = "admin_team_invariants.rs"]
mod admin_team_invariants;
#[path = "admin_users.rs"]
mod admin_users;
#[path = "admin_webhook_handlers.rs"]
mod admin_webhook_handlers;
