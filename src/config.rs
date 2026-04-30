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
    pub url_prefix: String,
    pub public_base_url: String,
    pub data_dir: PathBuf,
    pub log_dir: PathBuf,
    pub init_admin: Option<(String, String)>,
    pub query_timeout_secs: u64,
    pub query_row_cap: usize,
    pub query_max_sql_bytes: usize,
    pub rate_limit_per_token: u32,
    pub rate_limit_window_secs: u64,
    pub rate_limit_anon_per_ip: u32,
    pub rate_limit_anon_window_secs: u64,
    pub tenant_read_pool_size: usize,
    pub session_ttl_days: u64,
    pub storage: Option<StorageConfig>,
    /// Comma-separated allow-list parsed from `DRUST_CORS_ORIGINS`.
    /// Empty Vec disables CORS entirely (browsers will keep blocking
    /// cross-origin fetch — same as before this feature existed).
    /// Each entry must be a full origin like `https://app.example.com`
    /// — no trailing slash, no path.
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub endpoint: String,
    pub admin_endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub admin_token: String,
    pub public_bucket: String,
    pub max_upload_bytes: usize,
    pub disk_min_free_pct: u8,
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
        Ok(Some(Self {
            endpoint,
            admin_endpoint: req("GARAGE_ADMIN_ENDPOINT")?,
            access_key: req("GARAGE_S3_ACCESS_KEY")?,
            secret_key: req("GARAGE_S3_SECRET_KEY")?,
            admin_token: req("GARAGE_ADMIN_TOKEN")?,
            public_bucket: opt("GARAGE_PUBLIC_BUCKET").unwrap_or_else(|| "public".to_string()),
            max_upload_bytes: parse_num("GARAGE_MAX_UPLOAD_SIZE", 52_428_800)?,
            disk_min_free_pct,
        }))
    }
}

fn opt(name: &'static str) -> Option<String> {
    std::env::var(name).ok()
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

        let url_prefix = opt("DRUST_URL_PREFIX").unwrap_or_else(|| "/drust".to_string());
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

        Ok(Self {
            bind,
            url_prefix,
            public_base_url,
            data_dir,
            log_dir,
            init_admin,
            query_timeout_secs: parse_num("DRUST_QUERY_TIMEOUT_SECS", 5)?,
            query_row_cap: parse_num("DRUST_QUERY_ROW_CAP", 10_000)?,
            query_max_sql_bytes: parse_num("DRUST_QUERY_MAX_SQL_BYTES", 16_384)?,
            rate_limit_per_token: parse_num("DRUST_RATE_LIMIT_PER_TOKEN", 60)?,
            rate_limit_window_secs: parse_num("DRUST_RATE_LIMIT_WINDOW_SECS", 10)?,
            rate_limit_anon_per_ip: parse_num("DRUST_RATE_LIMIT_ANON_PER_IP", 30)?,
            rate_limit_anon_window_secs: parse_num("DRUST_RATE_LIMIT_ANON_WINDOW_SECS", 60)?,
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
    fn storage_config_disabled_when_endpoint_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_storage_env();
        assert!(StorageConfig::from_env().unwrap().is_none());
    }

    #[test]
    fn storage_config_requires_full_set_when_endpoint_set() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_storage_env();
        unsafe { std::env::set_var("GARAGE_S3_ENDPOINT", "http://127.0.0.1:47830") };
        let err = StorageConfig::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::Missing(_)));
        clear_storage_env();
    }

    #[test]
    fn storage_config_defaults_bucket_and_size() {
        let _g = ENV_LOCK.lock().unwrap();
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
}
