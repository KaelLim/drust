//! #925 — merged harness for the file test group (7 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! No member of this group loads a shared module file twice, so
//! `duplicate_mod` has nothing to fire on here today. The allow is still
//! present because the plan puts it on every #925 harness: a member added later
//! that declares `mod helpers;` alongside an existing one would otherwise turn
//! CI's `cargo clippy --all-targets -- -D warnings` red for a duplication that
//! is inherent to the merge rather than a defect.
#![allow(clippy::duplicate_mod)]

#[path = "file_policy_expression.rs"]
mod file_policy_expression;
#[path = "file_visibility.rs"]
mod file_visibility;
#[path = "files_rls_admin_ui.rs"]
mod files_rls_admin_ui;
#[path = "files_rls_policy.rs"]
mod files_rls_policy;
#[path = "files_rls_read.rs"]
mod files_rls_read;
#[path = "files_rls_schema.rs"]
mod files_rls_schema;
#[path = "files_rls_upload.rs"]
mod files_rls_upload;
