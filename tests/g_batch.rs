//! #925 — merged harness for the batch test group (3 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `duplicate_mod` is inherent to the merge, not a defect: 2 of the members
//! declare their own `mod helpers;`, so once they share a crate clippy sees
//! tests/helpers.rs loaded 2 times. Deduping it would mean editing test bodies
//! (spec 鐵律 1 forbids that) for no gain — rustc compiles the file once per
//! module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

// Declared once for the whole harness; `batch_webhook_fanout` used to declare
// it itself and now says `use crate::webhooks_common;` (spec 鐵律 2).
mod webhooks_common;

#[path = "batch_insert.rs"]
mod batch_insert;
#[path = "batch_insert_rest.rs"]
mod batch_insert_rest;
#[path = "batch_webhook_fanout.rs"]
mod batch_webhook_fanout;
