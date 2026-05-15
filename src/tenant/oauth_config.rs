// src/tenant/oauth_config.rs
//! CRUD for the per-tenant `_system_oauth_providers` table + input
//! validation for the admin REST/MCP surface. The provider trait shape
//! and adapter wiring stay in `src/oauth/`; this module is the drust-side
//! glue that turns DB rows into config and validates admin-supplied
//! upserts.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthProviderConfig {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub allowed_redirect_uris: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OauthConfigError {
    #[error("provider must be 'google' or 'github'")]
    InvalidProvider,
    #[error("client_id must be non-empty and at most 256 chars")]
    InvalidClientId,
    #[error("client_secret must be non-empty and at most 256 chars")]
    InvalidClientSecret,
    #[error("allowed_redirect_uris must be a non-empty array")]
    EmptyRedirectUris,
    #[error("invalid redirect URI: {0}")]
    InvalidRedirectUri(String),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}

impl OauthConfigError {
    /// Stable machine-readable code for REST + MCP responses. Lets clients
    /// branch on the specific failure mode without parsing `.to_string()`.
    /// `Db` keeps the umbrella `"DB"` (still 500) because it isn't a
    /// validation outcome callers can correct on retry.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidProvider => "INVALID_PROVIDER",
            Self::InvalidClientId => "INVALID_CLIENT_ID",
            Self::InvalidClientSecret => "INVALID_CLIENT_SECRET",
            Self::EmptyRedirectUris => "EMPTY_REDIRECT_URIS",
            Self::InvalidRedirectUri(_) => "INVALID_REDIRECT_URI",
            Self::Db(_) => "DB",
        }
    }
}

const ALLOWED_PROVIDERS: &[&str] = &["google", "github"];

pub fn validate_provider(p: &str) -> Result<(), OauthConfigError> {
    if ALLOWED_PROVIDERS.contains(&p) {
        Ok(())
    } else {
        Err(OauthConfigError::InvalidProvider)
    }
}

pub fn validate_redirect_uri(uri: &str) -> Result<(), OauthConfigError> {
    if uri.is_empty()
        || uri.len() >= 1024
        || uri.chars().any(|c| c.is_whitespace() || c == ',')
    {
        return Err(OauthConfigError::InvalidRedirectUri(uri.to_string()));
    }
    let ok = uri.starts_with("https://")
        || uri.starts_with("http://localhost")
        || uri.starts_with("http://127.0.0.1");
    if !ok {
        return Err(OauthConfigError::InvalidRedirectUri(uri.to_string()));
    }
    Ok(())
}

pub fn validate_upsert(
    provider: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uris: &[String],
) -> Result<(), OauthConfigError> {
    validate_provider(provider)?;
    if client_id.is_empty() || client_id.len() > 256 {
        return Err(OauthConfigError::InvalidClientId);
    }
    if client_secret.is_empty() || client_secret.len() > 256 {
        return Err(OauthConfigError::InvalidClientSecret);
    }
    if redirect_uris.is_empty() {
        return Err(OauthConfigError::EmptyRedirectUris);
    }
    for u in redirect_uris {
        validate_redirect_uri(u)?;
    }
    Ok(())
}

fn parse_uris(joined: &str) -> Vec<String> {
    // Stored as comma-separated; split, trim, drop empties.
    joined
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn list(conn: &Connection) -> Result<Vec<OauthProviderConfig>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT provider, client_id, client_secret, allowed_redirect_uris, created_at, updated_at \
         FROM _system_oauth_providers ORDER BY provider",
    )?;
    let rows = stmt.query_map([], |r| {
        let uris: String = r.get(3)?;
        Ok(OauthProviderConfig {
            provider: r.get(0)?,
            client_id: r.get(1)?,
            client_secret: r.get(2)?,
            allowed_redirect_uris: parse_uris(&uris),
            created_at: r.get(4)?,
            updated_at: r.get(5)?,
        })
    })?;
    rows.collect()
}

pub fn get(
    conn: &Connection,
    provider: &str,
) -> Result<Option<OauthProviderConfig>, rusqlite::Error> {
    conn.query_row(
        "SELECT provider, client_id, client_secret, allowed_redirect_uris, created_at, updated_at \
         FROM _system_oauth_providers WHERE provider = ?1",
        [provider],
        |r| {
            let uris: String = r.get(3)?;
            Ok(OauthProviderConfig {
                provider: r.get(0)?,
                client_id: r.get(1)?,
                client_secret: r.get(2)?,
                allowed_redirect_uris: parse_uris(&uris),
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
            })
        },
    )
    .optional()
}

pub fn upsert(
    conn: &Connection,
    provider: &str,
    client_id: &str,
    client_secret: &str,
    allowed_redirect_uris: &[String],
) -> Result<(), OauthConfigError> {
    validate_upsert(provider, client_id, client_secret, allowed_redirect_uris)?;
    let uris_joined = allowed_redirect_uris.join(",");
    conn.execute(
        "INSERT INTO _system_oauth_providers \
           (provider, client_id, client_secret, allowed_redirect_uris) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(provider) DO UPDATE SET \
           client_id = excluded.client_id, \
           client_secret = excluded.client_secret, \
           allowed_redirect_uris = excluded.allowed_redirect_uris, \
           updated_at = datetime('now')",
        params![provider, client_id, client_secret, uris_joined],
    )?;
    Ok(())
}

pub fn delete(conn: &Connection, provider: &str) -> Result<bool, rusqlite::Error> {
    let n = conn.execute(
        "DELETE FROM _system_oauth_providers WHERE provider = ?1",
        [provider],
    )?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_with_table() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::migrations::SQL_CREATE_SYSTEM_OAUTH_PROVIDERS_IF_NOT_EXISTS)
            .unwrap();
        c
    }

    #[test]
    fn validate_provider_accepts_known() {
        assert!(validate_provider("google").is_ok());
        assert!(validate_provider("github").is_ok());
        assert!(matches!(
            validate_provider("microsoft"),
            Err(OauthConfigError::InvalidProvider)
        ));
        assert!(matches!(
            validate_provider(""),
            Err(OauthConfigError::InvalidProvider)
        ));
    }

    #[test]
    fn validate_redirect_uri_accepts_https_and_localhost() {
        assert!(validate_redirect_uri("https://app.example.com/cb").is_ok());
        assert!(validate_redirect_uri("https://app.example.com").is_ok());
        assert!(validate_redirect_uri("http://localhost:5173/cb").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1:8080/cb").is_ok());
    }

    #[test]
    fn validate_redirect_uri_rejects_plain_http_and_garbage() {
        assert!(validate_redirect_uri("http://attacker.com/cb").is_err());
        assert!(validate_redirect_uri("ftp://x").is_err());
        assert!(validate_redirect_uri("").is_err());
        assert!(validate_redirect_uri("https://has space").is_err());
        assert!(validate_redirect_uri("https://comma,inside").is_err());
        let long = format!("https://{}", "a".repeat(1100));
        assert!(validate_redirect_uri(&long).is_err());
    }

    #[test]
    fn upsert_then_list_round_trip() {
        let c = db_with_table();
        upsert(
            &c,
            "google",
            "cid-1",
            "csec-1",
            &["https://app.example.com/cb".into()],
        )
        .unwrap();
        let got = list(&c).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].provider, "google");
        assert_eq!(got[0].client_id, "cid-1");
        assert_eq!(got[0].client_secret, "csec-1");
        assert_eq!(
            got[0].allowed_redirect_uris,
            vec!["https://app.example.com/cb".to_string()]
        );
    }

    #[test]
    fn upsert_updates_on_conflict() {
        let c = db_with_table();
        upsert(&c, "google", "cid-1", "csec-1", &["https://a/cb".into()]).unwrap();
        upsert(&c, "google", "cid-2", "csec-2", &["https://b/cb".into()]).unwrap();
        let got = list(&c).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].client_id, "cid-2");
    }

    #[test]
    fn delete_returns_existed_flag() {
        let c = db_with_table();
        upsert(&c, "google", "x", "y", &["https://z/cb".into()]).unwrap();
        assert!(delete(&c, "google").unwrap());
        assert!(!delete(&c, "google").unwrap());
    }

    #[test]
    fn error_code_maps_each_variant() {
        assert_eq!(OauthConfigError::InvalidProvider.error_code(), "INVALID_PROVIDER");
        assert_eq!(OauthConfigError::InvalidClientId.error_code(), "INVALID_CLIENT_ID");
        assert_eq!(
            OauthConfigError::InvalidClientSecret.error_code(),
            "INVALID_CLIENT_SECRET"
        );
        assert_eq!(
            OauthConfigError::EmptyRedirectUris.error_code(),
            "EMPTY_REDIRECT_URIS"
        );
        assert_eq!(
            OauthConfigError::InvalidRedirectUri("http://bad".into()).error_code(),
            "INVALID_REDIRECT_URI"
        );
        // Db is the umbrella for the 500-class — error_code is `DB`.
        let db_err =
            OauthConfigError::Db(rusqlite::Error::InvalidParameterName("x".into()));
        assert_eq!(db_err.error_code(), "DB");
    }
}
