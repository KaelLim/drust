//! #925 — merged harness for the functions test group (10 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `duplicate_mod` is inherent to the merge, not a defect: 8 of the members
//! declare their own `mod helpers;`, so once they share a crate clippy sees
//! tests/helpers.rs loaded 8 times. Deduping it would mean editing test bodies
//! (spec 鐵律 1 forbids that) for no gain — rustc compiles the file once per
//! module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

#[path = "functions_caller_enforcement.rs"]
mod functions_caller_enforcement;
#[path = "functions_caller_escalation.rs"]
mod functions_caller_escalation;
#[path = "functions_dispatch.rs"]
mod functions_dispatch;
#[path = "functions_invoke_acl_config.rs"]
mod functions_invoke_acl_config;
#[path = "functions_invoke_gate.rs"]
mod functions_invoke_gate;
#[path = "functions_isolation.rs"]
mod functions_isolation;
#[path = "functions_mcp.rs"]
mod functions_mcp;
#[path = "functions_rest.rs"]
mod functions_rest;
#[path = "functions_schema.rs"]
mod functions_schema;
#[path = "functions_wasm_real.rs"]
mod functions_wasm_real;
