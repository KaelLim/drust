use drust::config::Config;
use std::path::PathBuf;

fn clear_env() {
    unsafe {
        for key in [
            "DRUST_BIND",
            "DRUST_URL_PREFIX",
            "DRUST_DATA_DIR",
            "DRUST_LOG_DIR",
            "DRUST_INIT_ADMIN_USERNAME",
            "DRUST_INIT_ADMIN_PASSWORD",
            "DRUST_QUERY_TIMEOUT_SECS",
            "DRUST_QUERY_ROW_CAP",
            "DRUST_QUERY_MAX_SQL_BYTES",
            "DRUST_RATE_LIMIT_PER_TOKEN",
            "DRUST_RATE_LIMIT_WINDOW_SECS",
            "DRUST_RATE_LIMIT_ANON_PER_IP",
            "DRUST_RATE_LIMIT_ANON_WINDOW_SECS",
            "DRUST_TENANT_READ_POOL_SIZE",
            "DRUST_SESSION_TTL_DAYS",
        ] {
            std::env::remove_var(key);
        }
    }
}

#[test]
fn loads_with_all_defaults() {
    clear_env();
    unsafe {
        std::env::set_var("DRUST_DATA_DIR", "/tmp/drust-data");
        std::env::set_var("DRUST_LOG_DIR", "/tmp/drust-log");
    }
    let cfg = Config::from_env().expect("config parses");
    assert_eq!(cfg.bind.to_string(), "127.0.0.1:47826");
    assert_eq!(cfg.url_prefix, "/drust");
    assert_eq!(cfg.data_dir, PathBuf::from("/tmp/drust-data"));
    assert_eq!(cfg.log_dir, PathBuf::from("/tmp/drust-log"));
    assert_eq!(cfg.query_timeout_secs, 5);
    assert_eq!(cfg.query_row_cap, 10_000);
    assert_eq!(cfg.query_max_sql_bytes, 16_384);
    assert_eq!(cfg.rate_limit_per_token, 60);
    assert_eq!(cfg.rate_limit_window_secs, 10);
    assert_eq!(cfg.rate_limit_anon_per_ip, 30);
    assert_eq!(cfg.rate_limit_anon_window_secs, 60);
    assert_eq!(cfg.tenant_read_pool_size, 4);
    assert_eq!(cfg.session_ttl_days, 7);
    assert!(cfg.init_admin.is_none());
}

#[test]
fn picks_up_init_admin_pair() {
    clear_env();
    unsafe {
        std::env::set_var("DRUST_DATA_DIR", "/tmp/drust-data");
        std::env::set_var("DRUST_LOG_DIR", "/tmp/drust-log");
        std::env::set_var("DRUST_INIT_ADMIN_USERNAME", "admin");
        std::env::set_var("DRUST_INIT_ADMIN_PASSWORD", "p@ssw0rd");
    }
    let cfg = Config::from_env().unwrap();
    let init = cfg.init_admin.expect("admin present");
    assert_eq!(init.0, "admin");
    assert_eq!(init.1, "p@ssw0rd");
}

#[test]
fn rejects_missing_data_dir() {
    clear_env();
    unsafe {
        std::env::set_var("DRUST_LOG_DIR", "/tmp/drust-log");
    }
    assert!(Config::from_env().is_err());
}
