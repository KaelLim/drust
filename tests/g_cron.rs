//! #925 — merged harness for the cron test group (3 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `duplicate_mod` is inherent to the merge, not a defect: 2 of the members
//! declare their own `mod helpers;`, so once they share a crate clippy sees
//! tests/helpers.rs loaded 2 times. Deduping it would mean editing test bodies
//! (spec 鐵律 1 forbids that) for no gain — rustc compiles the file once per
//! module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

#[path = "cron_admin_ui.rs"]
mod cron_admin_ui;
#[path = "cron_dispatch.rs"]
mod cron_dispatch;
#[path = "cron_rest.rs"]
mod cron_rest;
