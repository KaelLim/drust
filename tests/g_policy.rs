//! #925 — merged harness for the policy test group (8 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `duplicate_mod` is inherent to the merge, not a defect: 6 of the members
//! declare their own `mod helpers;`, so once they share a crate clippy sees
//! tests/helpers.rs loaded 6 times. Deduping it would mean editing test bodies
//! (spec 鐵律 1 forbids that) for no gain — rustc compiles the file once per
//! module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

#[path = "policy_backward_compat.rs"]
mod policy_backward_compat;
#[path = "policy_config_rest.rs"]
mod policy_config_rest;
#[path = "policy_deny_surfaces.rs"]
mod policy_deny_surfaces;
#[path = "policy_expression.rs"]
mod policy_expression;
#[path = "policy_mcp.rs"]
mod policy_mcp;
#[path = "policy_read_enforcement.rs"]
mod policy_read_enforcement;
#[path = "policy_sse.rs"]
mod policy_sse;
#[path = "policy_write_enforcement.rs"]
mod policy_write_enforcement;
