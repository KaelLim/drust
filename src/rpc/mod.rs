//! RPC subsystem: stored Supabase-style named SQL functions.
//!
//! - `exec_write` — v1.30 mutation executor (split_statements + execute_one).
//! - `handler` — REST handler `POST /drust/t/<tenant>/rpc/<name>`.
//! - `params` — param schema declaration + JSON validation.
//! - `prepare` — prepare-time SQL safety check (read-only authorizer).
//! - `registry` — persistence + counter increments over `_system_rpc`.

pub mod exec_write;
pub mod handler;
pub mod params;
pub mod prepare;
pub mod registry;

// Ergonomics re-export so call sites can spell `crate::rpc::RpcMode`
// instead of `crate::rpc::registry::RpcMode`.
pub use registry::RpcMode;
