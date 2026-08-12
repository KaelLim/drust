//! #925 — merged harness for the collection test group (4 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! No member of this group loads a shared module file twice, so
//! `duplicate_mod` has nothing to fire on here today. The allow is still
//! present because the plan puts it on every #925 harness: a member added later
//! that declares `mod helpers;` alongside an existing one would otherwise turn
//! CI's `cargo clippy --all-targets -- -D warnings` red for a duplication that
//! is inherent to the merge rather than a defect.
#![allow(clippy::duplicate_mod)]

#[path = "collection_list_admin_errors.rs"]
mod collection_list_admin_errors;
#[path = "collection_list_admin_filter_ast.rs"]
mod collection_list_admin_filter_ast;
#[path = "collection_list_admin_protected.rs"]
mod collection_list_admin_protected;
#[path = "collection_page_back_compat.rs"]
mod collection_page_back_compat;
