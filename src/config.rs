use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing env var: {0}")]
    Missing(&'static str),
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub public_base_url: String,
    pub data_dir: PathBuf,
    pub log_dir: PathBuf,
    pub init_admin: Option<(String, String)>,
    pub rate_limit_per_token: u32,
    pub rate_limit_window_secs: u64,
    /// Hard upper bound on the rate-limiter's bucket map size. Prevents
    /// memory DoS from a flood of distinct random bearer tokens.
    pub rate_limit_map_cap: usize,
    /// How often the rate-limiter's background cleanup task runs.
    pub rate_limit_cleanup_interval_secs: u64,
    pub tenant_read_pool_size: usize,
    pub session_ttl_days: u64,
    pub storage: Option<StorageConfig>,
    /// Comma-separated allow-list parsed from `DRUST_CORS_ORIGINS`.
    /// Empty Vec disables CORS entirely (browsers will keep blocking
    /// cross-origin fetch — same as before this feature existed).
    /// Each entry must be a full origin like `https://app.example.com`
    /// — no trailing slash, no path.
    pub cors_origins: Vec<String>,
    /// Row count above which index creation is considered "large table" and
    /// may be guarded (e.g. background-threaded, warned, or refused in
    /// certain contexts). Parsed from `DRUST_INDEX_LARGE_TABLE_ROWS`;
    /// defaults to 1 000 000. The guard logic that consumes this lands
    /// in a later task — this field is plumbing only for now.
    pub index_large_table_rows: u64,
    /// `DRUST_TRUSTED_PROXIES`: how many reverse proxies in front of drust
    /// each append one entry to `X-Forwarded-For`. The per-IP rate limiters
    /// key on `parts[len - N]`; `0` ignores the header and keys on the TCP
    /// peer. Default 2 (the bare-metal nginx → Caddy chain), range `0..=8`.
    /// Out of range or non-numeric refuses to boot rather than clamping: this
    /// value picks which header position becomes a rate-limit key, and a
    /// silently substituted one is wrong in a direction nobody sees.
    pub trusted_proxies: u8,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub endpoint: String,
    /// `GARAGE_ADMIN_ENDPOINT`. Empty = the Garage admin API is not
    /// configured (see `admin_api_pair`); only the reconcile page's cleanup
    /// of retired per-tenant buckets uses it.
    pub admin_endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    /// `GARAGE_ADMIN_TOKEN`. Empty exactly when `admin_endpoint` is empty.
    pub admin_token: String,
    pub public_bucket: String,
    pub max_upload_bytes: usize,
    pub disk_min_free_pct: u8,
    /// Mode B (resumable) per-file ceiling → tus `Tus-Max-Size`. Default 2 GiB.
    pub large_upload_max_bytes: usize,
    /// Mode B per-PATCH chunk body limit. Must stay < the Caddy `max_size`
    /// (200 MB today). Default 64 MiB.
    pub large_upload_chunk_max_bytes: usize,
    /// Max concurrent in-flight Mode B sessions per tenant. Default 5.
    pub large_upload_max_sessions_per_tenant: u32,
    /// Abandoned-session lifetime (seconds) → `expires_at` + janitor sweep.
    /// Default 86 400 (24 h).
    pub large_upload_session_ttl_secs: u64,
}

impl StorageConfig {
    /// Returns None when GARAGE_S3_ENDPOINT is unset (storage module disabled).
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let Some(endpoint) = opt("GARAGE_S3_ENDPOINT") else {
            return Ok(None);
        };
        let disk_min_free_pct: u8 = parse_num("DRUST_DISK_MIN_FREE_PCT", 20)?;
        if !(1..=99).contains(&disk_min_free_pct) {
            return Err(ConfigError::Invalid(
                "DRUST_DISK_MIN_FREE_PCT",
                "must be between 1 and 99".into(),
            ));
        }
        let access_key = req("GARAGE_S3_ACCESS_KEY")?;
        let secret_key = req("GARAGE_S3_SECRET_KEY")?;
        let max_upload_bytes = parse_num("GARAGE_MAX_UPLOAD_SIZE", 52_428_800)?;
        let large_upload_max_bytes = parse_num("DRUST_LARGE_UPLOAD_MAX_BYTES", 2_147_483_648)?;
        let large_upload_chunk_max_bytes =
            parse_num("DRUST_LARGE_UPLOAD_CHUNK_MAX_BYTES", 67_108_864)?;
        let large_upload_max_sessions_per_tenant =
            parse_num("DRUST_LARGE_UPLOAD_MAX_SESSIONS_PER_TENANT", 5)?;
        let large_upload_session_ttl_secs =
            parse_num("DRUST_LARGE_UPLOAD_SESSION_TTL_SECS", 86_400)?;
        // After every fallible read above, so a missing S3 key or a bad number
        // is still the reported error and the half-pair warning is never
        // emitted on a config that fails anyway.
        let (admin_endpoint, admin_token) = admin_api_pair();
        Ok(Some(Self {
            endpoint,
            admin_endpoint,
            access_key,
            secret_key,
            admin_token,
            public_bucket: opt("GARAGE_PUBLIC_BUCKET").unwrap_or_else(|| "public".to_string()),
            max_upload_bytes,
            disk_min_free_pct,
            large_upload_max_bytes,
            large_upload_chunk_max_bytes,
            large_upload_max_sessions_per_tenant,
            large_upload_session_ttl_secs,
        }))
    }
}

fn opt(name: &'static str) -> Option<String> {
    std::env::var(name).ok()
}

/// Unset, empty, OR whitespace-only → `None` (a blank-looking token must not
/// be sent as a bearer). A non-blank value is returned as given.
fn opt_nonempty(name: &'static str) -> Option<String> {
    opt(name).filter(|v| !v.trim().is_empty())
}

/// The Garage admin API is configured only when BOTH `GARAGE_ADMIN_ENDPOINT`
/// and `GARAGE_ADMIN_TOKEN` are non-blank. Anything else — both absent or
/// blank, or a half pair — reads as "not configured" (both fields empty).
/// A half pair is warned about, never refused: it booted before these became
/// optional (`req` accepted an empty string), and nothing on the data path
/// uses the admin API. The warning names the missing variable, never a value.
fn admin_api_pair() -> (String, String) {
    match (
        opt_nonempty("GARAGE_ADMIN_ENDPOINT"),
        opt_nonempty("GARAGE_ADMIN_TOKEN"),
    ) {
        (Some(endpoint), Some(token)) => (endpoint, token),
        (None, None) => (String::new(), String::new()),
        (Some(_), None) => {
            tracing::warn!(
                missing = "GARAGE_ADMIN_TOKEN",
                "GARAGE_ADMIN_ENDPOINT is set but GARAGE_ADMIN_TOKEN is not; treating the Garage admin API as not configured"
            );
            (String::new(), String::new())
        }
        (None, Some(_)) => {
            tracing::warn!(
                missing = "GARAGE_ADMIN_ENDPOINT",
                "GARAGE_ADMIN_TOKEN is set but GARAGE_ADMIN_ENDPOINT is not; treating the Garage admin API as not configured"
            );
            (String::new(), String::new())
        }
    }
}

fn req(name: &'static str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::Missing(name))
}

fn parse_num<T: std::str::FromStr>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T::Err: std::fmt::Display,
{
    match opt(name) {
        None => Ok(default),
        Some(s) => s
            .parse::<T>()
            .map_err(|e| ConfigError::Invalid(name, e.to_string())),
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind: SocketAddr = opt("DRUST_BIND")
            .unwrap_or_else(|| "127.0.0.1:47826".to_string())
            .parse()
            .map_err(|e: std::net::AddrParseError| {
                ConfigError::Invalid("DRUST_BIND", e.to_string())
            })?;

        let public_base_url =
            opt("DRUST_PUBLIC_BASE_URL").unwrap_or_else(|| "http://localhost:8793".to_string());
        let data_dir: PathBuf = req("DRUST_DATA_DIR")?.into();
        let log_dir: PathBuf = req("DRUST_LOG_DIR")?.into();

        let init_admin = match (
            opt("DRUST_INIT_ADMIN_USERNAME"),
            opt("DRUST_INIT_ADMIN_PASSWORD"),
        ) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Some((u, p)),
            _ => None,
        };

        let storage = StorageConfig::from_env()?;

        let trusted_proxies: u8 = parse_num(
            "DRUST_TRUSTED_PROXIES",
            crate::safety::ip::DEFAULT_TRUSTED_PROXIES,
        )?;
        if trusted_proxies > crate::safety::ip::MAX_TRUSTED_PROXIES {
            return Err(ConfigError::Invalid(
                "DRUST_TRUSTED_PROXIES",
                format!(
                    "must be between 0 and {}",
                    crate::safety::ip::MAX_TRUSTED_PROXIES
                ),
            ));
        }

        Ok(Self {
            bind,
            public_base_url,
            data_dir,
            log_dir,
            init_admin,
            rate_limit_per_token: parse_num("DRUST_RATE_LIMIT_PER_TOKEN", 60)?,
            rate_limit_window_secs: parse_num("DRUST_RATE_LIMIT_WINDOW_SECS", 10)?,
            rate_limit_map_cap: parse_num("DRUST_RATE_LIMIT_MAP_CAP", 10_000)?,
            rate_limit_cleanup_interval_secs: parse_num(
                "DRUST_RATE_LIMIT_CLEANUP_INTERVAL_SECS",
                60,
            )?,
            tenant_read_pool_size: parse_num("DRUST_TENANT_READ_POOL_SIZE", 4)?,
            session_ttl_days: parse_num("DRUST_SESSION_TTL_DAYS", 7)?,
            storage,
            cors_origins: opt("DRUST_CORS_ORIGINS")
                .map(|s| {
                    s.split(',')
                        .map(|p| p.trim().to_string())
                        .filter(|p| !p.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            index_large_table_rows: parse_num("DRUST_INDEX_LARGE_TABLE_ROWS", 1_000_000)?,
            trusted_proxies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env mutation is serialised with `#[serial_test::serial]` (default key),
    // NOT a module-private Mutex. `cargo test --lib` is ONE binary running
    // every test in parallel and it holds three env-mutating domains — this
    // one, `crate::oauth::config::tests` and
    // `crate::tenant::rooms::state::tests`. Three independent locks are no
    // mutual exclusion at all, and `set_var` is unsound against ANY
    // concurrent `getenv`, not just a second writer of the same variable.
    // The default serial key is the only mechanism here that spans modules.

    fn clear_storage_env() {
        for k in [
            "GARAGE_S3_ENDPOINT",
            "GARAGE_ADMIN_ENDPOINT",
            "GARAGE_S3_ACCESS_KEY",
            "GARAGE_S3_SECRET_KEY",
            "GARAGE_ADMIN_TOKEN",
            "GARAGE_PUBLIC_BUCKET",
            "GARAGE_MAX_UPLOAD_SIZE",
        ] {
            unsafe { std::env::remove_var(k) };
        }
    }

    #[test]
    #[serial_test::serial] // mutates process-global GARAGE_* / DRUST_LARGE_UPLOAD_* env vars
    fn storage_config_disabled_when_endpoint_unset() {
        clear_storage_env();
        assert!(StorageConfig::from_env().unwrap().is_none());
    }

    #[test]
    #[serial_test::serial] // mutates process-global GARAGE_* / DRUST_LARGE_UPLOAD_* env vars
    fn storage_config_requires_full_set_when_endpoint_set() {
        clear_storage_env();
        unsafe { std::env::set_var("GARAGE_S3_ENDPOINT", "http://127.0.0.1:47830") };
        let err = StorageConfig::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::Missing(_)));
        clear_storage_env();
    }

    /// The S3 trio every S3-compatible store needs, and nothing else.
    fn set_s3_trio() {
        unsafe {
            std::env::set_var("GARAGE_S3_ENDPOINT", "http://127.0.0.1:47830");
            std::env::set_var("GARAGE_S3_ACCESS_KEY", "GK123");
            std::env::set_var("GARAGE_S3_SECRET_KEY", "secret");
        }
    }

    #[test]
    #[serial_test::serial] // mutates process-global GARAGE_* / DRUST_LARGE_UPLOAD_* env vars
    fn storage_config_admin_api_is_optional() {
        clear_storage_env();
        set_s3_trio();
        let cfg = StorageConfig::from_env()
            .expect("the S3 trio alone must load")
            .expect("GARAGE_S3_ENDPOINT set => storage enabled");
        assert_eq!(cfg.admin_endpoint, "");
        assert_eq!(cfg.admin_token, "");
        clear_storage_env();
    }

    #[test]
    #[serial_test::serial] // mutates process-global GARAGE_* / DRUST_LARGE_UPLOAD_* env vars
    fn storage_config_empty_admin_pair_reads_as_unset() {
        clear_storage_env();
        set_s3_trio();
        unsafe {
            std::env::set_var("GARAGE_ADMIN_ENDPOINT", "");
            std::env::set_var("GARAGE_ADMIN_TOKEN", "");
        }
        let cfg = StorageConfig::from_env().unwrap().unwrap();
        assert_eq!(cfg.admin_endpoint, "");
        assert_eq!(cfg.admin_token, "");
        clear_storage_env();
    }

    #[test]
    #[serial_test::serial] // mutates process-global GARAGE_* / DRUST_LARGE_UPLOAD_* env vars
    fn storage_config_half_configured_admin_api_reads_as_unconfigured() {
        // (endpoint, token): None = unset, Some("") = present but empty.
        // Whitespace-only reads as empty: a blank-looking token is never sent.
        let cases: [(Option<&str>, Option<&str>); 6] = [
            (Some("http://127.0.0.1:47832"), None),
            (Some("http://127.0.0.1:47832"), Some("")),
            (Some("http://127.0.0.1:47832"), Some("  \t")),
            (None, Some("token")),
            (Some(""), Some("token")),
            (Some(" "), Some("token")),
        ];
        for (endpoint, token) in cases {
            clear_storage_env();
            set_s3_trio();
            unsafe {
                if let Some(e) = endpoint {
                    std::env::set_var("GARAGE_ADMIN_ENDPOINT", e);
                }
                if let Some(t) = token {
                    std::env::set_var("GARAGE_ADMIN_TOKEN", t);
                }
            }
            let cfg = match StorageConfig::from_env() {
                Ok(Some(cfg)) => cfg,
                Ok(None) => panic!("storage disabled for {endpoint:?}/{token:?}"),
                Err(e) => {
                    panic!("a half admin pair must never refuse boot ({endpoint:?}/{token:?}): {e}")
                }
            };
            assert_eq!(
                (cfg.admin_endpoint.as_str(), cfg.admin_token.as_str()),
                ("", ""),
                "half pair {endpoint:?}/{token:?} must read as not configured"
            );
        }
        clear_storage_env();
    }

    #[test]
    #[serial_test::serial] // mutates process-global GARAGE_* / DRUST_LARGE_UPLOAD_* env vars
    fn storage_config_full_admin_pair_is_kept() {
        clear_storage_env();
        set_s3_trio();
        unsafe {
            std::env::set_var("GARAGE_ADMIN_ENDPOINT", "http://127.0.0.1:47832");
            std::env::set_var("GARAGE_ADMIN_TOKEN", "token");
        }
        let cfg = StorageConfig::from_env().unwrap().unwrap();
        assert_eq!(cfg.admin_endpoint, "http://127.0.0.1:47832");
        assert_eq!(cfg.admin_token, "token");
        clear_storage_env();
    }

    #[test]
    #[serial_test::serial] // mutates process-global GARAGE_* / DRUST_LARGE_UPLOAD_* env vars
    fn storage_config_defaults_bucket_and_size() {
        clear_storage_env();
        unsafe {
            std::env::set_var("GARAGE_S3_ENDPOINT", "http://127.0.0.1:47830");
            std::env::set_var("GARAGE_ADMIN_ENDPOINT", "http://127.0.0.1:47832");
            std::env::set_var("GARAGE_S3_ACCESS_KEY", "GK123");
            std::env::set_var("GARAGE_S3_SECRET_KEY", "secret");
            std::env::set_var("GARAGE_ADMIN_TOKEN", "token");
        }
        let cfg = StorageConfig::from_env().unwrap().unwrap();
        assert_eq!(cfg.public_bucket, "public");
        assert_eq!(cfg.max_upload_bytes, 52_428_800);
        assert_eq!(cfg.disk_min_free_pct, 20);
        clear_storage_env();
    }

    #[test]
    #[serial_test::serial] // mutates process-global GARAGE_* / DRUST_LARGE_UPLOAD_* env vars
    fn storage_config_large_upload_defaults() {
        clear_storage_env();
        for k in [
            "DRUST_LARGE_UPLOAD_MAX_BYTES",
            "DRUST_LARGE_UPLOAD_CHUNK_MAX_BYTES",
            "DRUST_LARGE_UPLOAD_MAX_SESSIONS_PER_TENANT",
            "DRUST_LARGE_UPLOAD_SESSION_TTL_SECS",
        ] {
            unsafe { std::env::remove_var(k) };
        }
        unsafe {
            std::env::set_var("GARAGE_S3_ENDPOINT", "http://127.0.0.1:47830");
            std::env::set_var("GARAGE_ADMIN_ENDPOINT", "http://127.0.0.1:47832");
            std::env::set_var("GARAGE_S3_ACCESS_KEY", "GK123");
            std::env::set_var("GARAGE_S3_SECRET_KEY", "secret");
            std::env::set_var("GARAGE_ADMIN_TOKEN", "token");
        }
        let cfg = StorageConfig::from_env().unwrap().unwrap();
        assert_eq!(cfg.large_upload_max_bytes, 2_147_483_648);
        assert_eq!(cfg.large_upload_chunk_max_bytes, 67_108_864);
        assert_eq!(cfg.large_upload_max_sessions_per_tenant, 5);
        assert_eq!(cfg.large_upload_session_ttl_secs, 86_400);
        clear_storage_env();
    }
}
