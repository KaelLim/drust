//! Pure async helpers for Task 7 — webhook subscription MCP tools.
//!
//! Mirrors the SQL bodies of the REST handlers in
//! `src/tenant/webhook_routes.rs`, but returns `anyhow::Result<Value>` so
//! it can be wired uniformly from `#[tool]` methods in `handler.rs`.
//!
//! MCP is service-key-only — the dispatch layer blocks anon bearers before
//! these helpers run, so the role is not re-checked here (mirrors the
//! oauth/user tool modules).

use crate::storage::pool::SharedTenantPool;
use crate::tenant::webhook_routes::{check_events, check_url, generate_secret};
use serde_json::json;

// ─── create ──────────────────────────────────────────────────────────────────

pub async fn create_webhook(
    pool: &SharedTenantPool,
    collection: String,
    events: Vec<String>,
    url: String,
) -> anyhow::Result<serde_json::Value> {
    if let Err((code, msg)) = check_url(&url) {
        return Err(anyhow::anyhow!("{code}: {msg}"));
    }
    if let Err((code, msg)) = check_events(&events) {
        return Err(anyhow::anyhow!("{code}: {msg}"));
    }
    let events_json =
        serde_json::to_string(&events).map_err(|e| anyhow::anyhow!("ENCODE_FAILED: {e}"))?;
    let secret = generate_secret();
    let secret_for_db = secret.clone();
    let now = chrono::Utc::now().to_rfc3339();
    let now2 = now.clone();
    let collection_db = collection.clone();
    let url_db = url.clone();

    let id = pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_webhooks \
                 (collection, events, url, secret, active, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                rusqlite::params![collection_db, events_json, url_db, secret_for_db, now2],
            )?;
            Ok::<_, rusqlite::Error>(c.last_insert_rowid())
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB_ERROR: {e}"))?;

    Ok(json!({
        "id": id,
        "secret": secret,
        "collection": collection,
        "events": events,
        "url": url,
        "active": true,
        "created_at": now,
    }))
}

// ─── list ────────────────────────────────────────────────────────────────────

pub async fn list_webhooks(pool: &SharedTenantPool) -> anyhow::Result<serde_json::Value> {
    let rows: Vec<serde_json::Value> = pool
        .with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT id, collection, events, url, active, \
                        last_failure_at, last_failure_reason, created_at \
                 FROM _system_webhooks \
                 ORDER BY id DESC",
            )?;
            stmt.query_map([], |r| {
                let events_raw: String = r.get(2)?;
                let events: Vec<String> = serde_json::from_str(&events_raw).unwrap_or_default();
                Ok(json!({
                    "id":                  r.get::<_, i64>(0)?,
                    "collection":          r.get::<_, String>(1)?,
                    "events":              events,
                    "url":                 r.get::<_, String>(3)?,
                    "secret":              "●●●●",
                    "active":              r.get::<_, i64>(4)? != 0,
                    "last_failure_at":     r.get::<_, Option<String>>(5)?,
                    "last_failure_reason": r.get::<_, Option<String>>(6)?,
                    "created_at":          r.get::<_, String>(7)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    Ok(json!({ "webhooks": rows }))
}

// ─── update ──────────────────────────────────────────────────────────────────

pub async fn update_webhook(
    pool: &SharedTenantPool,
    id: i64,
    active: Option<bool>,
    events: Option<Vec<String>>,
    url: Option<String>,
) -> anyhow::Result<serde_json::Value> {
    if let Some(ref u) = url {
        if let Err((code, msg)) = check_url(u) {
            return Err(anyhow::anyhow!("{code}: {msg}"));
        }
    }
    if let Some(ref evs) = events {
        if let Err((code, msg)) = check_events(evs) {
            return Err(anyhow::anyhow!("{code}: {msg}"));
        }
    }
    let new_active = active.map(|b| if b { 1i64 } else { 0i64 });
    let new_events_json = events
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| anyhow::anyhow!("ENCODE_FAILED: {e}"))?;
    let new_url = url;

    let count = pool
        .with_writer(move |c| -> rusqlite::Result<i64> {
            let tx = c.transaction()?;
            if let Some(v) = new_active {
                tx.execute(
                    "UPDATE _system_webhooks SET active = ?1 WHERE id = ?2",
                    rusqlite::params![v, id],
                )?;
            }
            if let Some(ref e) = new_events_json {
                tx.execute(
                    "UPDATE _system_webhooks SET events = ?1 WHERE id = ?2",
                    rusqlite::params![e, id],
                )?;
            }
            if let Some(ref u) = new_url {
                tx.execute(
                    "UPDATE _system_webhooks SET url = ?1 WHERE id = ?2",
                    rusqlite::params![u, id],
                )?;
            }
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM _system_webhooks WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )?;
            tx.commit()?;
            Ok(count)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;

    if count == 0 {
        return Err(anyhow::anyhow!("NOT_FOUND: no such webhook"));
    }
    Ok(json!({"updated": true, "id": id}))
}

// ─── delete ──────────────────────────────────────────────────────────────────

pub async fn delete_webhook(pool: &SharedTenantPool, id: i64) -> anyhow::Result<serde_json::Value> {
    let n = pool
        .with_writer(move |c| {
            c.execute(
                "DELETE FROM _system_webhooks WHERE id = ?1",
                rusqlite::params![id],
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;

    if n == 0 {
        return Err(anyhow::anyhow!("NOT_FOUND: no such webhook"));
    }
    Ok(json!({"deleted": true, "id": id}))
}
