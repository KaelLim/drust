//! #925 — merged harness for the member test group (4 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! No member of this group loads a shared module file twice, so
//! `duplicate_mod` has nothing to fire on here today. The allow is still
//! present because the plan puts it on every #925 harness: a member added later
//! that declares `mod helpers;` alongside an existing one would otherwise turn
//! CI's `cargo clippy --all-targets -- -D warnings` red for a duplication that
//! is inherent to the merge rather than a defect.
#![allow(clippy::duplicate_mod)]

#[path = "member_tenant_cap.rs"]
mod member_tenant_cap;
#[path = "member_tenant_cap_http.rs"]
mod member_tenant_cap_http;
#[path = "member_tenant_cap_requests.rs"]
mod member_tenant_cap_requests;
#[path = "member_tenant_cap_ui.rs"]
mod member_tenant_cap_ui;
