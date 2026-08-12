//! #925 — merged harness for the misc test group (55 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! "misc" is the plan's tail bucket, not a subject: it collects every test file
//! whose name prefix had fewer than three siblings, so membership here means
//! "no group of its own", never "related to its neighbours".
//!
//! `duplicate_mod` is inherent to the merge, not a defect: 21 of the members
//! load tests/helpers.rs (20 as `mod helpers;`, sse_realtime_gating as
//! `mod tests_helpers;`), so once they share a crate clippy sees that one file
//! loaded 21 times. Deduping it would mean editing test bodies (spec 鐵律 1
//! forbids that) for no gain — rustc compiles the file once per module path
//! either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

#[path = "aggregate.rs"]
mod aggregate;
#[path = "authorizer.rs"]
mod authorizer;
#[path = "authorizer_writable.rs"]
mod authorizer_writable;
#[path = "backup_roundtrip.rs"]
mod backup_roundtrip;
#[path = "bearer_token.rs"]
mod bearer_token;
#[path = "bench_ws_publish.rs"]
mod bench_ws_publish;
#[path = "check_constraints_meta.rs"]
mod check_constraints_meta;
#[path = "check_constraints_writepath.rs"]
mod check_constraints_writepath;
#[path = "codegen_golden.rs"]
mod codegen_golden;
#[path = "codegen_routes.rs"]
mod codegen_routes;
#[path = "collections_endpoints.rs"]
mod collections_endpoints;
#[path = "connection_pool.rs"]
mod connection_pool;
#[path = "dataplane_files_service_guard.rs"]
mod dataplane_files_service_guard;
#[path = "defensive_writer.rs"]
mod defensive_writer;
#[path = "disk_check_root.rs"]
mod disk_check_root;
#[path = "end_to_end.rs"]
mod end_to_end;
#[path = "error_suggested_fix.rs"]
mod error_suggested_fix;
#[path = "explain_endpoint.rs"]
mod explain_endpoint;
#[path = "filter_composition.rs"]
mod filter_composition;
#[path = "host_files_owner_only.rs"]
mod host_files_owner_only;
#[path = "index_tools.rs"]
mod index_tools;
#[path = "large_upload_tus.rs"]
mod large_upload_tus;
#[path = "meta_lock_contention.rs"]
mod meta_lock_contention;
#[path = "meta_sqlite.rs"]
mod meta_sqlite;
#[path = "mgmt_login.rs"]
mod mgmt_login;
#[path = "owner_field.rs"]
mod owner_field;
#[path = "owner_field_records.rs"]
mod owner_field_records;
#[path = "pragma_optimize_smoke.rs"]
mod pragma_optimize_smoke;
#[path = "prepare_cached_parity.rs"]
mod prepare_cached_parity;
#[path = "prepare_cached_staleness.rs"]
mod prepare_cached_staleness;
#[path = "query_endpoint.rs"]
mod query_endpoint;
#[path = "quota_update_growth.rs"]
mod quota_update_growth;
#[path = "rate_limit.rs"]
mod rate_limit;
#[path = "rate_limit_middleware.rs"]
mod rate_limit_middleware;
#[path = "reconcile_pending.rs"]
mod reconcile_pending;
#[path = "returning_mcp_parity.rs"]
mod returning_mcp_parity;
#[path = "returning_rest_policy.rs"]
mod returning_rest_policy;
#[path = "session.rs"]
mod session;
#[path = "session_middleware.rs"]
mod session_middleware;
#[path = "set_admin_password_email.rs"]
mod set_admin_password_email;
#[path = "set_admin_role_cli.rs"]
mod set_admin_role_cli;
#[path = "soft_delete_no_resurrect.rs"]
mod soft_delete_no_resurrect;
#[path = "sqlite_internal_write_denied.rs"]
mod sqlite_internal_write_denied;
#[path = "sse.rs"]
mod sse;
#[path = "sse_realtime_gating.rs"]
mod sse_realtime_gating;
#[path = "strict_new_collection.rs"]
mod strict_new_collection;
#[path = "strict_rebuild.rs"]
mod strict_rebuild;
#[path = "tenants_api.rs"]
mod tenants_api;
#[path = "three_tier_roles.rs"]
mod three_tier_roles;
#[path = "token_roles.rs"]
mod token_roles;
#[path = "tokens_api.rs"]
mod tokens_api;
#[path = "upload_content_type_safety.rs"]
mod upload_content_type_safety;
#[path = "upsert.rs"]
mod upsert;
#[path = "upsert_rest.rs"]
mod upsert_rest;
#[path = "x_drust_version_header.rs"]
mod x_drust_version_header;
