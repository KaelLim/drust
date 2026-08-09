//! Wave 2 M3 — service-only FTS5 index lifecycle tools (create/drop/list).
//!
//! An FTS index is an external-content FTS5 vtable named
//! `fts_head_name(coll, name)` plus three sync triggers on the parent
//! collection, all built in ONE `with_writer_tx`. The mandatory `('rebuild')`
//! backfill runs in that same tx so pre-index rows stay deletable — without it,
//! deleting or updating a row inserted BEFORE the index raises SQLITE_CORRUPT
//! (reproduced in the Phase 0 spike). The registry of `{name, fields, tokenizer}`
//! lives in `_system_collection_meta.fts_indexes_json` and is the operator-facing
//! identity `describe_collection` / the `$fts` operand resolve against.
//!
//! These three tools are reachable only over `/t/<id>/mcp`, which is
//! service-only by route dispatch (anon → `WRITE_DENIED`, user →
//! `MCP_USER_DENIED`); there is no per-tool role check, matching `create_index`.

use crate::mcp::server::DrustMcp;
use crate::mcp::tools::schema::{SYSTEM_COLUMNS, identifier};
use crate::storage::schema::{
    FtsIndex, collection_exists, describe_collection, is_protected_collection, read_fts_indexes,
    write_fts_indexes,
};
use crate::storage::search_names::{fts_head_name, fts_trigger_names, validate_fts_index_name};
use serde_json::{Value, json};

const ALLOWED_TOKENIZERS: [&str; 2] = ["trigram", "unicode61"];

/// Double-quote an identifier for interpolation into DDL. Every id passed here
/// is drust-controlled — a collection name (`identifier()`), an index name
/// (`validate_fts_index_name`), a field name (already on the schema), or a
/// derived head/trigger name — so this only guards the pathological embedded
/// quote. `mcp/tools/schema.rs` has no shared `q()` helper.
fn qid(id: &str) -> String {
    format!("\"{}\"", id.replace('"', "\"\""))
}

/// Create an external-content FTS5 index over one or more TEXT fields of a
/// collection. ALL validation runs BEFORE any DDL.
///
/// Builds the head vtable + three content-sync triggers and runs the mandatory
/// `('rebuild')` backfill in ONE writer transaction. NOTE: that rebuild holds
/// the tenant writer mutex for the whole corpus and is unbounded growth with
/// **no `check_tenant_quota`** — the documented DDL trusted-caller quota
/// carve-out (`.claude/rules/write-path.md`): a service/admin key can
/// transiently exceed the cap by building one index; the next record/upload
/// write then blocks. Untrusted anon/user cannot reach this tool.
pub async fn create_fts_index(
    s: &DrustMcp,
    coll: &str,
    name: &str,
    fields: &[String],
    tokenizer: Option<&str>,
) -> anyhow::Result<Value> {
    // ---- validation (all BEFORE any DDL) ----
    identifier(coll)?;
    if is_protected_collection(coll) {
        anyhow::bail!("no such collection: {coll}");
    }
    validate_fts_index_name(name)?;
    if fields.is_empty() {
        anyhow::bail!("FTS_FIELD_INVALID: fields must be non-empty");
    }
    let tok = tokenizer.unwrap_or("trigram");
    if !ALLOWED_TOKENIZERS.contains(&tok) {
        anyhow::bail!(
            "FTS_TOKENIZER_INVALID: tokenizer must be one of [{}] (got {tok:?})",
            ALLOWED_TOKENIZERS.join(", ")
        );
    }

    let pool = s.inner().pool.clone();
    let coll_for_schema = coll.to_string();
    let schema = pool
        .with_reader(move |c| describe_collection(c, &coll_for_schema))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no such collection: {coll}"))?;

    // Duplicate — the schema carries the current registry (read_fts_indexes).
    if schema.fts_indexes.iter().any(|i| i.name == name) {
        anyhow::bail!("FTS_INDEX_EXISTS: an fts index named {name:?} already exists on {coll}");
    }

    // Every field: exists, TEXT, not a vector field, not a system column.
    let vector_names: std::collections::BTreeSet<&str> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.as_str())
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    for f in fields {
        if !seen.insert(f.as_str()) {
            anyhow::bail!("FTS_FIELD_INVALID: duplicate field {f:?} in index spec");
        }
        // Banned first: created_at/updated_at ARE TEXT and would pass the type
        // check. updated_at in particular is banned because the `_updated_at`
        // trigger fires the sync triggers twice and convergence is proven only
        // for non-indexed columns (spike fact #4).
        if SYSTEM_COLUMNS.contains(&f.as_str()) {
            anyhow::bail!(
                "FTS_FIELD_INVALID: {f:?} is a system column (id/created_at/updated_at) and \
                 cannot be fts-indexed"
            );
        }
        let field = schema
            .fields
            .iter()
            .find(|sf| &sf.name == f)
            .ok_or_else(|| {
                anyhow::anyhow!("FTS_FIELD_INVALID: field {f:?} does not exist on {coll}")
            })?;
        if vector_names.contains(f.as_str()) {
            anyhow::bail!("FTS_FIELD_INVALID: field {f:?} is a vector field, not TEXT");
        }
        if !field.sql_type.eq_ignore_ascii_case("TEXT") {
            anyhow::bail!(
                "FTS_FIELD_INVALID: field {f:?} has type {:?}; only TEXT fields can be fts-indexed",
                field.sql_type
            );
        }
    }

    // ---- DDL: head + 3 triggers + mandatory backfill, all in ONE tx ----
    let head = fts_head_name(coll, name);
    let [ai, ad, au] = fts_trigger_names(coll, name);
    let head_q = qid(&head);
    let coll_q = qid(coll);
    let cols_csv = fields.iter().map(|f| qid(f)).collect::<Vec<_>>().join(", ");
    let new_vals = fields
        .iter()
        .map(|f| format!("new.{}", qid(f)))
        .collect::<Vec<_>>()
        .join(", ");
    let old_vals = fields
        .iter()
        .map(|f| format!("old.{}", qid(f)))
        .collect::<Vec<_>>()
        .join(", ");
    // `content='{coll}'` / `tokenize='{tok}'` are safe string literals: coll
    // passed `identifier()` ([a-z0-9_], no quote) and tok is a fixed allowlist.
    // The `'delete'` command column in the _ad/_au triggers is the
    // double-quoted head IDENTIFIER (the fts5 hidden column), per the spike.
    let ddl = format!(
        "CREATE VIRTUAL TABLE {head_q} USING fts5({cols_csv}, content='{coll}', \
             content_rowid='id', tokenize='{tok}');\n\
         CREATE TRIGGER {ai_q} AFTER INSERT ON {coll_q} BEGIN\n\
           INSERT INTO {head_q}(rowid, {cols_csv}) VALUES (new.id, {new_vals});\n\
         END;\n\
         CREATE TRIGGER {ad_q} AFTER DELETE ON {coll_q} BEGIN\n\
           INSERT INTO {head_q}({head_q}, rowid, {cols_csv}) VALUES ('delete', old.id, {old_vals});\n\
         END;\n\
         CREATE TRIGGER {au_q} AFTER UPDATE ON {coll_q} BEGIN\n\
           INSERT INTO {head_q}({head_q}, rowid, {cols_csv}) VALUES ('delete', old.id, {old_vals});\n\
           INSERT INTO {head_q}(rowid, {cols_csv}) VALUES (new.id, {new_vals});\n\
         END;",
        ai_q = qid(&ai),
        ad_q = qid(&ad),
        au_q = qid(&au),
    );
    // Mandatory: without this a pre-index row raises SQLITE_CORRUPT on
    // delete/update because the shadow has no matching entry to remove.
    let backfill = format!("INSERT INTO {head_q}({head_q}) VALUES('rebuild');");

    let new_entry = FtsIndex {
        name: name.to_string(),
        fields: fields.to_vec(),
        tokenizer: tok.to_string(),
    };
    let coll_for_tx = coll.to_string();
    pool.with_writer_tx(move |tx| {
        tx.execute_batch(&ddl)?;
        tx.execute_batch(&backfill)?;
        // Re-read under the writer mutex, then append + persist (authoritative).
        let mut list = read_fts_indexes(tx, &coll_for_tx)?;
        list.push(new_entry);
        write_fts_indexes(tx, &coll_for_tx, &list)?;
        Ok(())
    })
    .await?;

    // A cached describe_collection would omit the new index.
    pool.schema_cache.invalidate(coll);

    let coll_for_read = coll.to_string();
    let indexes = pool
        .with_reader(move |c| read_fts_indexes(c, &coll_for_read))
        .await?;
    Ok(json!({
        "ok": true,
        "collection": coll,
        "name": name,
        "fields": fields,
        "tokenizer": tok,
        "fts_indexes": indexes,
    }))
}

/// Drop an FTS index: its three sync triggers + head vtable (the fts5 module
/// cascades the head's shadow tables; DEFENSIVE permits the head drop), then
/// remove it from the registry — all in ONE tx. `FTS_INDEX_NOT_FOUND` if the
/// index is not registered on `coll`.
pub async fn drop_fts_index(s: &DrustMcp, coll: &str, name: &str) -> anyhow::Result<Value> {
    identifier(coll)?;
    if is_protected_collection(coll) {
        anyhow::bail!("no such collection: {coll}");
    }
    validate_fts_index_name(name)?;
    let pool = s.inner().pool.clone();

    let coll_check = coll.to_string();
    let name_check = name.to_string();
    let exists = pool
        .with_reader(move |c| {
            Ok::<bool, rusqlite::Error>(
                read_fts_indexes(c, &coll_check)?
                    .iter()
                    .any(|i| i.name == name_check),
            )
        })
        .await?;
    if !exists {
        anyhow::bail!("FTS_INDEX_NOT_FOUND: no fts index named {name:?} on {coll}");
    }

    let head = fts_head_name(coll, name);
    let [ai, ad, au] = fts_trigger_names(coll, name);
    let drop_ddl = format!(
        "DROP TRIGGER IF EXISTS {};\n\
         DROP TRIGGER IF EXISTS {};\n\
         DROP TRIGGER IF EXISTS {};\n\
         DROP TABLE IF EXISTS {};",
        qid(&ai),
        qid(&ad),
        qid(&au),
        qid(&head),
    );
    let coll_for_tx = coll.to_string();
    let name_for_tx = name.to_string();
    pool.with_writer_tx(move |tx| {
        tx.execute_batch(&drop_ddl)?;
        let mut list = read_fts_indexes(tx, &coll_for_tx)?;
        list.retain(|i| i.name != name_for_tx);
        write_fts_indexes(tx, &coll_for_tx, &list)?;
        Ok(())
    })
    .await?;

    pool.schema_cache.invalidate(coll);

    let coll_for_read = coll.to_string();
    let indexes = pool
        .with_reader(move |c| read_fts_indexes(c, &coll_for_read))
        .await?;
    Ok(json!({
        "ok": true,
        "collection": coll,
        "dropped_index": name,
        "fts_indexes": indexes,
    }))
}

/// List the FTS indexes registered on a collection.
pub async fn list_fts_indexes(s: &DrustMcp, coll: &str) -> anyhow::Result<Value> {
    identifier(coll)?;
    if is_protected_collection(coll) {
        anyhow::bail!("no such collection: {coll}");
    }
    let pool = s.inner().pool.clone();
    let coll_check = coll.to_string();
    let exists = pool
        .with_reader(move |c| collection_exists(c, &coll_check))
        .await?;
    if !exists {
        anyhow::bail!("no such collection: {coll}");
    }
    let coll_read = coll.to_string();
    let indexes = pool
        .with_reader(move |c| read_fts_indexes(c, &coll_read))
        .await?;
    Ok(json!({ "collection": coll, "fts_indexes": indexes }))
}
