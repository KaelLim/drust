//! #925 — merged harness for the webhook test group (5 members).
//! Each module is one former standalone integration-test binary, unchanged.
//!
//! No member of this group loads a shared module file twice, so
//! `duplicate_mod` has nothing to fire on here today. The allow is still
//! present because the plan puts it on every #925 harness: a member added later
//! that declares `mod helpers;` alongside an existing one would otherwise turn
//! CI's `cargo clippy --all-targets -- -D warnings` red for a duplication that
//! is inherent to the merge rather than a defect.
#![allow(clippy::duplicate_mod)]

// Declared once for the whole harness; `webhook_dns_rebind`,
// `webhook_egress_per_attempt` and `webhooks` used to declare it themselves and
// now say `use crate::webhooks_common;` (spec 鐵律 2).
mod webhooks_common;

#[path = "webhook_dns_rebind.rs"]
mod webhook_dns_rebind;
#[path = "webhook_egress_per_attempt.rs"]
mod webhook_egress_per_attempt;
#[path = "webhook_url_validation.rs"]
mod webhook_url_validation;
#[path = "webhooks.rs"]
mod webhooks;
#[path = "webhooks_migration.rs"]
mod webhooks_migration;
