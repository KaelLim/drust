//! #925 — merged harness for the rpc test group (4 of 5 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `rpc_v2_mutation` is NOT here: it keeps its own `[[test]]` entry. It and
//! `rpc_query_kind` both install a process-global audit writer through
//! `safety::audit_db::init_globals`, whose `WRITER` is a first-write-wins
//! `OnceLock`, and both then assert on rows in the SQLite file *they*
//! installed. Merged, only the race winner's file ever receives rows, so which
//! of the two passes is scheduling luck. Backing one out is the only permitted
//! fix (鐵律 1) and leaves `rpc_query_kind` the group's sole installer, which
//! makes the survivor deterministic rather than lucky.
//!
//! `duplicate_mod` is inherent to the merge, not a defect: 4 of the members
//! declare their own `mod helpers;`, so once they share a crate clippy sees
//! tests/helpers.rs loaded 4 times. Deduping it would mean editing test bodies
//! (spec 鐵律 1 forbids that) for no gain — rustc compiles the file once per
//! module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

#[path = "rpc_prepare_cached_staleness.rs"]
mod rpc_prepare_cached_staleness;
#[path = "rpc_query_kind.rs"]
mod rpc_query_kind;
#[path = "rpc_user_id_spoof.rs"]
mod rpc_user_id_spoof;
#[path = "rpc_v2_create_validation.rs"]
mod rpc_v2_create_validation;
