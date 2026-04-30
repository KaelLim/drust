//! RPC subsystem: stored Supabase-style named SQL functions.
//!
//! - `params` — param schema declaration + JSON validation.
//! - `registry` — persistence + counter increments over `_system_rpc`.
//! - `prepare` — prepare-time SQL safety check (read-only authorizer).
//! - `handler` — REST handler `POST /drust/t/<tenant>/rpc/<name>`.

pub mod handler;
pub mod params;
pub mod prepare;
pub mod registry;
