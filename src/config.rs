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
        let data_dir: PathBuf = req("DRUST_DATA_DIR")?.into();
        let log_dir: PathBuf = req("DRUST_LOG_DIR")?.into();

        let init_admin = match (
            opt("DRUST_INIT_ADMIN_USERNAME"),
            opt("DRUST_INIT_ADMIN_PASSWORD"),
        ) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Some((u, p)),
            _ => None,
        };

        Ok(Self {
            bind,
            url_prefix,
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
        })
    }
}
