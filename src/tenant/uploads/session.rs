//! _system_upload_sessions row CRUD + tus metadata/derivation helpers +
//! the abandoned-session janitor sweep. All writes go through the
//! per-tenant writer mutex (`pool.with_writer`).

use crate::storage::pool::SharedTenantPool;
use base64::Engine;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct NewSession {
    pub upload_token: String,
    pub tenant_id: String,
    pub key: String,
    pub visibility: String,
    pub original_name: String,
    pub content_type: Option<String>,
    pub total_length: i64,
    pub expires_at: String,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub upload_token: String,
    pub tenant_id: String,
    pub key: String,
    pub visibility: String,
    pub original_name: String,
    pub content_type: Option<String>,
    pub total_length: i64,
    pub expires_at: String,
}

/// Parse a tus `Upload-Metadata` header: comma-separated `key b64value`
/// pairs; a valueless key maps to "". Undecodable values are skipped.
pub fn parse_upload_metadata(raw: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let mut parts = item.splitn(2, ' ');
        let key = parts.next().unwrap_or("").trim();
        if key.is_empty() {
            continue;
        }
        match parts.next() {
            Some(b64) => {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim())
                    && let Ok(s) = String::from_utf8(bytes)
                {
                    out.insert(key.to_string(), s);
                }
            }
            None => {
                out.insert(key.to_string(), String::new());
            }
        }
    }
    out
}

/// tus token = server-minted uuid-v4. Validate shape before any fs/DB use so
/// a malicious path component (`../`, `/`) can never reach the spool path.
pub fn is_valid_token(tok: &str) -> bool {
    tok.len() == 36
        && tok.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        && tok.as_bytes().iter().enumerate().all(|(i, &b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b != b'-'
            }
        })
}

/// Server-derived bare `_system_files` key: `<uuid>.<ext>` (ext from the
/// client filename, defaulting to `bin`). Never embeds the client name.
pub fn derive_key(original_name: &str) -> String {
    let ext = std::path::Path::new(original_name)
        .extension()
        .and_then(|s| s.to_str())
        .filter(|s| s.chars().all(|c| c.is_ascii_alphanumeric()) && s.len() <= 12)
        .unwrap_or("bin");
    format!("{}.{}", uuid::Uuid::new_v4(), ext)
}

pub async fn insert_session(pool: &SharedTenantPool, s: NewSession) -> rusqlite::Result<()> {
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_upload_sessions
               (upload_token, tenant_id, key, visibility, original_name,
                content_type, total_length, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                s.upload_token,
                s.tenant_id,
                s.key,
                s.visibility,
                s.original_name,
                s.content_type,
                s.total_length,
                s.expires_at,
            ],
        )
        .map(|_| ())
    })
    .await
}

pub async fn get_session(
    pool: &SharedTenantPool,
    token: &str,
) -> rusqlite::Result<Option<Session>> {
    let token = token.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT upload_token, tenant_id, key, visibility, original_name,
                    content_type, total_length, expires_at
             FROM _system_upload_sessions WHERE upload_token = ?1",
            rusqlite::params![token],
            |r| {
                Ok(Session {
                    upload_token: r.get(0)?,
                    tenant_id: r.get(1)?,
                    key: r.get(2)?,
                    visibility: r.get(3)?,
                    original_name: r.get(4)?,
                    content_type: r.get(5)?,
                    total_length: r.get(6)?,
                    expires_at: r.get(7)?,
                })
            },
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
    })
    .await
}

pub async fn delete_session(pool: &SharedTenantPool, token: &str) -> rusqlite::Result<()> {
    let token = token.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "DELETE FROM _system_upload_sessions WHERE upload_token = ?1",
            rusqlite::params![token],
        )
        .map(|_| ())
    })
    .await
}

pub async fn count_in_flight(pool: &SharedTenantPool) -> rusqlite::Result<i64> {
    pool.with_reader(move |c| {
        c.query_row("SELECT COUNT(*) FROM _system_upload_sessions", [], |r| {
            r.get(0)
        })
    })
    .await
}

/// List in-flight sessions (newest first) — backs `GET /t/<id>/uploads`.
pub async fn list_sessions(pool: &SharedTenantPool) -> rusqlite::Result<Vec<Session>> {
    pool.with_reader(move |c| {
        let mut stmt = c.prepare(
            "SELECT upload_token, tenant_id, key, visibility, original_name,
                    content_type, total_length, expires_at
             FROM _system_upload_sessions ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Session {
                upload_token: r.get(0)?,
                tenant_id: r.get(1)?,
                key: r.get(2)?,
                visibility: r.get(3)?,
                original_name: r.get(4)?,
                content_type: r.get(5)?,
                total_length: r.get(6)?,
                expires_at: r.get(7)?,
            })
        })?;
        rows.collect()
    })
    .await
}

/// Sweep one tenant's expired sessions: delete the spool file + session row,
/// and prune the per-token append lock. Returns the number reclaimed.
///
/// Deliberately does NOT touch `_system_files` or Garage. A session row can
/// still exist for a SUCCESSFULLY finalized upload (e.g. a crash in the small
/// window between the Garage push and the session-row delete), so deleting the
/// object / row here could destroy a live file. A half-finalized orphan row
/// (Garage push failed, then upload abandoned) is left for the existing
/// reconcile page to surface — never silently deleted.
pub async fn sweep_tenant(
    pool: &SharedTenantPool,
    tenant_id: &str,
    data_root: &std::path::Path,
    now_rfc3339: &str,
) -> usize {
    let expired = match expired_tokens(pool, now_rfc3339.to_string()).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(tenant = %tenant_id, error = %e, "upload janitor: list expired failed");
            return 0;
        }
    };
    let mut n = 0;
    for s in expired {
        let spool = crate::storage::tenant_db::tenant_dir(data_root, tenant_id)
            .join("_uploads")
            .join(format!("{}.part", s.upload_token));
        let _ = tokio::fs::remove_file(&spool).await;
        let _ = delete_session(pool, &s.upload_token).await;
        // Prune the per-token append lock (T7's token_locks map) so abandoned
        // uploads don't leak DashMap entries. `session` is a child module of
        // `uploads`, so it can reach the parent's private `token_locks()`.
        super::token_locks().remove(&s.upload_token);
        n += 1;
    }
    n
}

/// Tokens of sessions whose `expires_at` is in the past — the janitor's work
/// list. Returned with their `key` + `visibility` so the caller can also
/// clean any half-finalized `_system_files` row / Garage object.
pub async fn expired_tokens(
    pool: &SharedTenantPool,
    now_rfc3339: String,
) -> rusqlite::Result<Vec<Session>> {
    pool.with_reader(move |c| {
        let mut stmt = c.prepare(
            "SELECT upload_token, tenant_id, key, visibility, original_name,
                    content_type, total_length, expires_at
             FROM _system_upload_sessions WHERE expires_at < ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![now_rfc3339], |r| {
            Ok(Session {
                upload_token: r.get(0)?,
                tenant_id: r.get(1)?,
                key: r.get(2)?,
                visibility: r.get(3)?,
                original_name: r.get(4)?,
                content_type: r.get(5)?,
                total_length: r.get(6)?,
                expires_at: r.get(7)?,
            })
        })?;
        rows.collect()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_upload_metadata_decodes_pairs() {
        // filename=test.txt, filetype=text/plain, visibility=public
        let raw = "filename dGVzdC50eHQ=,filetype dGV4dC9wbGFpbg==,visibility cHVibGlj";
        let m = parse_upload_metadata(raw);
        assert_eq!(m.get("filename").unwrap(), "test.txt");
        assert_eq!(m.get("filetype").unwrap(), "text/plain");
        assert_eq!(m.get("visibility").unwrap(), "public");
    }

    #[test]
    fn parse_upload_metadata_handles_valueless_and_blank() {
        let m = parse_upload_metadata("is_confidential,filename dGVzdC50eHQ=");
        assert_eq!(m.get("is_confidential").unwrap(), "");
        assert_eq!(m.get("filename").unwrap(), "test.txt");
        assert!(parse_upload_metadata("").is_empty());
    }

    #[test]
    fn valid_token_accepts_uuid_rejects_traversal() {
        assert!(is_valid_token("8f14e45f-ceea-467f-9a36-dcc8f1d0a5b2"));
        assert!(!is_valid_token("../../etc/passwd"));
        assert!(!is_valid_token("8f14e45f/ceea"));
        assert!(!is_valid_token("short"));
        assert!(!is_valid_token(&"x".repeat(40)));
    }

    #[test]
    fn derive_key_uses_extension() {
        assert!(derive_key("invoice.pdf").ends_with(".pdf"));
        assert!(derive_key("noext").ends_with(".bin"));
        // server-minted uuid prefix, not the client name
        assert!(!derive_key("secret.pdf").contains("secret"));
    }

    #[tokio::test]
    async fn create_get_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tid = "t-sess";
        drust_open(&dir, tid);
        let pool = registry(&dir).get_or_open(tid).unwrap();
        let row = NewSession {
            upload_token: "tok-rt".into(),
            tenant_id: tid.into(),
            key: "k1.bin".into(),
            visibility: "private".into(),
            original_name: "f.bin".into(),
            content_type: Some("application/octet-stream".into()),
            total_length: 1234,
            expires_at: "2999-01-01T00:00:00Z".into(),
        };
        insert_session(&pool, row.clone()).await.unwrap();
        let got = get_session(&pool, "tok-rt").await.unwrap().unwrap();
        assert_eq!(got.key, "k1.bin");
        assert_eq!(got.total_length, 1234);
        assert_eq!(count_in_flight(&pool).await.unwrap(), 1);
        delete_session(&pool, "tok-rt").await.unwrap();
        assert!(get_session(&pool, "tok-rt").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sweep_removes_expired_and_keeps_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let tid = "t-sweep";
        crate::storage::tenant_db::open_write(dir.path(), tid).unwrap();
        let pool = registry(&dir).get_or_open(tid).unwrap();
        // expired
        insert_session(
            &pool,
            NewSession {
                upload_token: "exp".into(),
                tenant_id: tid.into(),
                key: "e.bin".into(),
                visibility: "private".into(),
                original_name: "e".into(),
                content_type: None,
                total_length: 10,
                expires_at: "2000-01-01T00:00:00+00:00".into(),
            },
        )
        .await
        .unwrap();
        // fresh
        insert_session(
            &pool,
            NewSession {
                upload_token: "fresh".into(),
                tenant_id: tid.into(),
                key: "f.bin".into(),
                visibility: "private".into(),
                original_name: "f".into(),
                content_type: None,
                total_length: 10,
                expires_at: "2999-01-01T00:00:00+00:00".into(),
            },
        )
        .await
        .unwrap();
        // spool file for the expired one
        let updir = crate::storage::tenant_db::tenant_dir(dir.path(), tid).join("_uploads");
        std::fs::create_dir_all(&updir).unwrap();
        let spool = updir.join("exp.part");
        std::fs::write(&spool, b"partial").unwrap();

        let removed = sweep_tenant(&pool, tid, dir.path(), "2026-06-03T00:00:00+00:00").await;
        assert_eq!(removed, 1);
        assert!(!spool.exists(), "expired spool file should be deleted");
        assert!(get_session(&pool, "exp").await.unwrap().is_none());
        assert!(get_session(&pool, "fresh").await.unwrap().is_some());
    }

    // --- test helpers ---
    fn drust_open(dir: &tempfile::TempDir, tid: &str) {
        crate::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    }
    fn registry(dir: &tempfile::TempDir) -> std::sync::Arc<crate::storage::pool::TenantRegistry> {
        std::sync::Arc::new(crate::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        ))
    }
}
