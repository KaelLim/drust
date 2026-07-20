// Accepted clippy lints — project-wide design/style choices. Prefer fixing or a
// local `#[allow]` over growing this list.
//   result_large_err   — several handler Results carry a large typed error enum
//                        by design; boxing every Err is churn for little gain.
//   too_many_arguments — a few request handlers take 8-9 params; threading a
//                        params struct would obscure more than it helps.
//   type_complexity    — some channel / router types are inherently complex.
//   large_enum_variant — one event enum has a large variant (boxing queued).
//   doc_lazy_continuation / doc_overindented_list_items — pedantic markdown-in-doc
//                        formatting; the docs read fine as written.
#![allow(
    clippy::result_large_err,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::large_enum_variant,
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items
)]

pub mod auth;
pub mod base_path;
pub mod bin_helpers;
pub mod codegen;
pub mod config;
pub mod cron;
pub mod db;
pub mod error;
pub mod functions;
pub mod mcp;
pub mod mgmt;
pub mod oauth;
pub mod query;
pub mod rpc;
pub mod safety;
pub mod storage;
pub mod tenant;

/// Compile-time UI consistency gates. The logic lives in `build_support/` so
/// `build.rs` can `include!` it; mirrored here under `cfg(test)` so the suite
/// exercises the pure scanners — `build.rs` is never covered by `cargo test`.
#[cfg(test)]
#[path = "../build_support/ui_gates.rs"]
mod ui_gates;
