//! #925 — merged harness for the audit test group (5 of 6 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `audit_retention_no_drop` is NOT here: it keeps its own `[[test]]` entry,
//! and unlike the other #925 backouts it would need one even if it won every
//! race. It installs the process-global audit writer via the first-write-wins
//! `safety::audit_db::init_globals` `OnceLock` (`audit_middleware` races it and
//! won here, leaving retention's reader on an empty file: 0 rows instead of
//! 12250), but the deeper problem is what it measures — that a retention pass
//! drops **no** inbound row. That is a count over the whole process's audit
//! traffic, so any other test emitting into the same bounded channel perturbs
//! it. Its own header already says "exactly ONE test in this binary may call
//! `init_globals` — keep this file to a single test". Sole ownership of the
//! process is the test's premise, not an accident of merge order.
//!
//! `duplicate_mod` is inherent to the merge, not a defect: 2 of the members
//! declare their own `mod helpers;`, so once they share a crate clippy sees
//! tests/helpers.rs loaded 2 times. Deduping it would mean editing test bodies
//! (spec 鐵律 1 forbids that) for no gain — rustc compiles the file once per
//! module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

#[path = "audit3_readscope_all_caps.rs"]
mod audit3_readscope_all_caps;
#[path = "audit3_sse_evict.rs"]
mod audit3_sse_evict;
#[path = "audit_middleware.rs"]
mod audit_middleware;
#[path = "audit_sqlite.rs"]
mod audit_sqlite;
#[path = "audit_ui_routes.rs"]
mod audit_ui_routes;
