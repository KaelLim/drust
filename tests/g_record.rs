//! #925 — merged harness for the record test group (9 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! `duplicate_mod` is inherent to the merge, not a defect: 8 of the members
//! declare their own `mod helpers;`, so once they share a crate clippy sees
//! tests/helpers.rs loaded 8 times. Deduping it would mean editing test bodies
//! (spec 鐵律 1 forbids that) for no gain — rustc compiles the file once per
//! module path either way. Without this allow, CI's
//! `cargo clippy --all-targets -- -D warnings` fails on every harness.
#![allow(clippy::duplicate_mod)]

#[path = "record_history_capture.rs"]
mod record_history_capture;
#[path = "record_history_read.rs"]
mod record_history_read;
#[path = "record_history_retention.rs"]
mod record_history_retention;
#[path = "record_history_rpc.rs"]
mod record_history_rpc;
#[path = "records_body_limit.rs"]
mod records_body_limit;
#[path = "records_crud.rs"]
mod records_crud;
#[path = "records_list_structured.rs"]
mod records_list_structured;
#[path = "records_list_user_caps.rs"]
mod records_list_user_caps;
#[path = "records_user_filter_denied.rs"]
mod records_user_filter_denied;
