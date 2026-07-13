//! v1.48 — Cron / scheduled jobs: tenants schedule their own edge functions
//! or stored RPCs with 5-field cron expressions (UTC), executed at
//! `Privileged` identity by an in-process minute-tick scheduler.
//! Spec: docs/superpowers/specs/2026-07-13-drust-cron-design.md.

pub mod schedule;

/// Env-driven cron knobs. Parsed once in `main.rs`; cloned everywhere.
#[derive(Clone, Debug)]
pub struct CronConfig {
    /// DRUST_CRON_MAX_JOBS_PER_TENANT — `_system_cron_jobs` row cap (default 10).
    pub max_jobs_per_tenant: i64,
    /// DRUST_CRON_DISABLED — `1` means the scheduler is not spawned.
    pub disabled: bool,
}

impl CronConfig {
    pub fn from_env() -> Self {
        fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        Self {
            max_jobs_per_tenant: env_or("DRUST_CRON_MAX_JOBS_PER_TENANT", 10),
            disabled: std::env::var("DRUST_CRON_DISABLED").as_deref() == Ok("1"),
        }
    }

    /// Test defaults — small, deterministic.
    #[cfg(any(test, debug_assertions))]
    pub fn test_default() -> Self {
        Self {
            max_jobs_per_tenant: 10,
            disabled: false,
        }
    }
}
