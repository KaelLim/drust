//! #925 — merged harness for the fts test group (4 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `duplicate_mod` is inherent to the merge, not a defect: 2 of the members
//! declare their own `mod helpers;`, so once they share a crate clippy sees
//! tests/helpers.rs loaded 2 times. Deduping it would mean editing test bodies
//! (spec 鐵律 1 forbids that) for no gain — rustc compiles the file once per
//! module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

#[path = "fts_index_lifecycle.rs"]
mod fts_index_lifecycle;
#[path = "fts_query.rs"]
mod fts_query;
#[path = "fts_surface.rs"]
mod fts_surface;
#[path = "fts_write_rpc.rs"]
mod fts_write_rpc;
