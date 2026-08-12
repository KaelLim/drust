//! #925 — merged harness for the tenant test group (16 of 17 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `tenant_quota_requests` is NOT here: it keeps its own `[[test]]` entry. It
//! asserts on rows in an audit DB it installs through
//! `safety::audit_db::init_globals`, whose `WRITER` is a first-write-wins
//! `OnceLock`, and `tenant_oauth` installs one too (through
//! `common::oauth_helpers::ensure_test_audit_writer`). Merged, the loser's rows
//! land in the winner's file; `tenant_oauth` asserts nothing about the writer,
//! so it stays. Backing the file out is the only permitted fix (鐵律 1).
//!
//! `duplicate_mod` is inherent to the merge, not a defect: every member still
//! carries its own `#[path = "helpers.rs"] mod helpers;`, and once they share a
//! crate clippy sees helpers.rs loaded 16 times. Deduping it would mean editing
//! test bodies (spec 鐵律 1 forbids that) for no gain — rustc compiles the file
//! once per module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

// Declared once for the whole harness; the members that used to declare it
// themselves now `use crate::common;` (spec 鐵律 2).
mod common;

#[path = "tenant_auth.rs"]
mod tenant_auth;
#[path = "tenant_cap_request_limits.rs"]
mod tenant_cap_request_limits;
#[path = "tenant_db.rs"]
mod tenant_db;
#[path = "tenant_files_rest.rs"]
mod tenant_files_rest;
#[path = "tenant_id_recycle_keeps_trash.rs"]
mod tenant_id_recycle_keeps_trash;
#[path = "tenant_id_validation.rs"]
mod tenant_id_validation;
#[path = "tenant_oauth.rs"]
mod tenant_oauth;
#[path = "tenant_ownership_create.rs"]
mod tenant_ownership_create;
#[path = "tenant_ownership_guard.rs"]
mod tenant_ownership_guard;
#[path = "tenant_ownership_hostwide.rs"]
mod tenant_ownership_hostwide;
#[path = "tenant_ownership_pat.rs"]
mod tenant_ownership_pat;
#[path = "tenant_ownership_transfer.rs"]
mod tenant_ownership_transfer;
#[path = "tenant_ownership_visibility.rs"]
mod tenant_ownership_visibility;
#[path = "tenant_quota_db.rs"]
mod tenant_quota_db;
#[path = "tenant_quota_files.rs"]
mod tenant_quota_files;
#[path = "tenant_settings.rs"]
mod tenant_settings;
