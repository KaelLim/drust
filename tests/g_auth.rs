//! #925 — merged harness for the auth test group (28 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `duplicate_mod` is inherent to the merge, not a defect: every member still
//! carries its own `#[path = "helpers.rs"] mod helpers;`, and once they share a
//! crate clippy sees helpers.rs loaded 28 times. Deduping it would mean editing
//! test bodies (spec 鐵律 1 forbids that) for no gain — rustc compiles the file
//! once per module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

#[path = "auth_admin_ui.rs"]
mod auth_admin_ui;
#[path = "auth_audit.rs"]
mod auth_audit;
#[path = "auth_bearer_resolution.rs"]
mod auth_bearer_resolution;
#[path = "auth_cache_change_password.rs"]
mod auth_cache_change_password;
#[path = "auth_cache_delete_user.rs"]
mod auth_cache_delete_user;
#[path = "auth_cache_hit.rs"]
mod auth_cache_hit;
#[path = "auth_cache_logout.rs"]
mod auth_cache_logout;
#[path = "auth_cache_mcp_publish_policy.rs"]
mod auth_cache_mcp_publish_policy;
#[path = "auth_cache_mcp_user.rs"]
mod auth_cache_mcp_user;
#[path = "auth_cache_missed_hook_ttl.rs"]
mod auth_cache_missed_hook_ttl;
#[path = "auth_cache_negative.rs"]
mod auth_cache_negative;
#[path = "auth_cache_pat_reroll.rs"]
mod auth_cache_pat_reroll;
#[path = "auth_cache_publish_policy.rs"]
mod auth_cache_publish_policy;
#[path = "auth_cache_revoke_all.rs"]
mod auth_cache_revoke_all;
#[path = "auth_cache_revoke_reroll.rs"]
mod auth_cache_revoke_reroll;
#[path = "auth_cache_set_file_caps.rs"]
mod auth_cache_set_file_caps;
#[path = "auth_cache_state.rs"]
mod auth_cache_state;
#[path = "auth_cache_tenant_lifecycle.rs"]
mod auth_cache_tenant_lifecycle;
#[path = "auth_cache_user_expiry.rs"]
mod auth_cache_user_expiry;
#[path = "auth_login.rs"]
mod auth_login;
#[path = "auth_mcp_blocked.rs"]
mod auth_mcp_blocked;
#[path = "auth_me.rs"]
mod auth_me;
#[path = "auth_migration.rs"]
mod auth_migration;
#[path = "auth_query_blocked.rs"]
mod auth_query_blocked;
#[path = "auth_register.rs"]
mod auth_register;
#[path = "auth_rpc.rs"]
mod auth_rpc;
#[path = "auth_session.rs"]
mod auth_session;
#[path = "auth_xff.rs"]
mod auth_xff;
