//! #925 — merged harness for the storage test group (6 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! No member of this group loads a shared module file twice, so
//! `duplicate_mod` has nothing to fire on here today. The allow is still
//! present because the plan puts it on every #925 harness: a member added later
//! that declares `mod helpers;` alongside an existing one would otherwise turn
//! CI's `cargo clippy --all-targets -- -D warnings` red for a duplication that
//! is inherent to the merge rather than a defect.
#![allow(clippy::duplicate_mod)]

// Declared once for the whole harness; `storage_garage_admin` used to declare
// it itself and now says `use crate::common;` (spec 鐵律 2).
mod common;

#[path = "storage_disk.rs"]
mod storage_disk;
#[path = "storage_files_helpers.rs"]
mod storage_files_helpers;
#[path = "storage_garage_admin.rs"]
mod storage_garage_admin;
#[path = "storage_garage_signing.rs"]
mod storage_garage_signing;
#[path = "storage_meta_migration.rs"]
mod storage_meta_migration;
#[path = "storage_tenant_db.rs"]
mod storage_tenant_db;
