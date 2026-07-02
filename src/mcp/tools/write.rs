use crate::mcp::server::DrustMcp;
use crate::storage::schema::{VectorField, describe_collection, is_protected_collection};
use crate::tenant::events::Event;
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use serde_json::json;
use std::collections::HashSet;

/// Build a `rusqlite::Error` whose Display renders the given human-readable
/// message. Using `rusqlite::Error::InvalidQuery` (the obvious-looking variant)
/// is wrong — its Display is hard-coded to `"Query is not read-only"`, which
/// bubbles up as a confusing error from the writer path.
fn invalid_input(msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(msg))
}

/// Backstop for the MCP write path: rewrite a raw native CHECK-constraint
/// failure into the typed `CHECK_CONSTRAINT_FAILED: ...` message so the MCP
/// error surfaces the SAME code the REST handlers do (`bail_mcp` parses the
/// code off the prefix). The app-layer `check_constraints` is the fast path;
/// this catches any constraint shape it does not model (defense in depth).
/// Non-CHECK errors (UNIQUE / FK / NOT NULL / no-rows) pass through unchanged.
fn map_check_violation(e: rusqlite::Error) -> rusqlite::Error {
    if crate::error::is_check_violation(&e) {
        invalid_input(format!("CHECK_CONSTRAINT_FAILED: {e}"))
    } else {
        e
    }
}

/// v1.43 — validate provided values against each field's structured
/// constraints (min/max/enum/max_length) and return a typed
/// `CHECK_CONSTRAINT_FAILED: <detail>` on the first violation, so callers
/// get a friendly message instead of a raw SQLite CHECK string. The native
/// inline CHECK remains the authority (it also catches admin REST / stored
/// RPC / edge-function writes that bypass this pre-check); this is the
/// friendly fast-path for MCP/REST structured writes.
///
/// Note: `length("col")` in SQL and `s.chars().count()` here BOTH count
/// Unicode code points (verified: `length('😀😀') = 2`), so the `max_length`
/// pre-check and the native CHECK agree on every input.
///
/// Enum and min/max are TYPE-AWARE so the pre-check agrees with
/// `compile_check`: on an integer/real/boolean field the enum compiles to a
/// numeric `IN (...)` and a JSON number/bool is compared numerically (a JSON
/// number would otherwise slip past a string-only check and hit the raw native
/// CHECK). A value whose JSON shape does not match the column type is left for
/// the native CHECK / STRICT typing to reject.
fn check_constraints(
    schema: &crate::storage::schema::CollectionSchema,
    data: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), rusqlite::Error> {
    // Numeric view of a JSON value: a number, or a bool (true→1, false→0,
    // matching `json_to_sql_value`'s bool→Integer lowering).
    fn as_num(v: &serde_json::Value) -> Option<f64> {
        v.as_f64()
            .or_else(|| v.as_bool().map(|b| if b { 1.0 } else { 0.0 }))
    }
    for f in &schema.fields {
        let Some(c) = &f.constraints else { continue };
        let Some(v) = data.get(&f.name) else { continue };
        if v.is_null() {
            continue;
        }
        let numeric = matches!(f.sql_type.as_str(), "integer" | "real" | "boolean");
        if let Some(n) = as_num(v) {
            if let Some(min) = c.min
                && n < min
            {
                return Err(invalid_input(format!(
                    "CHECK_CONSTRAINT_FAILED: {} must be >= {min}",
                    f.name
                )));
            }
            if let Some(max) = c.max
                && n > max
            {
                return Err(invalid_input(format!(
                    "CHECK_CONSTRAINT_FAILED: {} must be <= {max}",
                    f.name
                )));
            }
        }
        if let Some(en) = &c.enum_values {
            // Mirror compile_check: numeric column → numeric membership;
            // text column → string membership. Skip when the value's JSON
            // shape doesn't match the column type (native CHECK/STRICT handles).
            let in_enum = if numeric {
                match as_num(v) {
                    Some(n) => en
                        .iter()
                        .any(|e| e.parse::<f64>().map(|ev| ev == n).unwrap_or(false)),
                    None => true,
                }
            } else {
                match v.as_str() {
                    Some(s) => en.iter().any(|e| e == s),
                    None => true,
                }
            };
            if !in_enum {
                return Err(invalid_input(format!(
                    "CHECK_CONSTRAINT_FAILED: {} not in enum",
                    f.name
                )));
            }
        }
        if let (Some(s), Some(len)) = (v.as_str(), c.max_length)
            && s.chars().count() as u32 > len
        {
            return Err(invalid_input(format!(
                "CHECK_CONSTRAINT_FAILED: {} exceeds max_length {len}",
                f.name
            )));
        }
    }
    Ok(())
}

fn json_to_sql_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Integer(if *b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Value::Real(f)
            } else {
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        other => Value::Text(other.to_string()),
    }
}

/// Materialize one already-fetched `rusqlite::Row` (column names `col_names`)
/// into a JSON object, hiding declared vector columns entirely and rendering
/// any BLOB as `{"__blob_bytes": n}`. Shared by the `RETURNING *` insert and
/// update read-back paths so both render byte-identical rows — same per-column
/// shape the REST records.rs path produces. `pub`: also the row projector for
/// the shared record-history pre-image helper (`storage::record_history`).
pub fn materialize_row(
    r: &rusqlite::Row<'_>,
    col_names: &[String],
    vector_names: &HashSet<String>,
) -> rusqlite::Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    for (i, n) in col_names.iter().enumerate() {
        // Vector columns are hidden by default — same shape as the REST
        // records.rs path. Keep them out of the response entirely;
        // retrieval is via search_collection.
        if vector_names.contains(n) {
            continue;
        }
        let v = r.get_ref(i)?;
        let jv = match v {
            rusqlite::types::ValueRef::Null => serde_json::Value::Null,
            rusqlite::types::ValueRef::Integer(i) => serde_json::json!(i),
            rusqlite::types::ValueRef::Real(f) => serde_json::json!(f),
            rusqlite::types::ValueRef::Text(t) => {
                serde_json::Value::String(String::from_utf8_lossy(t).into_owned())
            }
            rusqlite::types::ValueRef::Blob(b) => json!({ "__blob_bytes": b.len() }),
        };
        obj.insert(n.clone(), jv);
    }
    Ok(serde_json::Value::Object(obj))
}

/// Encode every vector field present in `data_map` to a packed-f32
/// BLOB, returning the bytes keyed by field name. Errors map to typed
/// strings so callers can render them as the expected error codes
/// (`VECTOR_DIM_MISMATCH` / `VECTOR_NON_FINITE` / `VECTOR_TYPE_ERROR`).
fn pre_encode_vectors(
    vector_fields: &[VectorField],
    data_map: &serde_json::Map<String, serde_json::Value>,
) -> Result<std::collections::HashMap<String, Vec<u8>>, anyhow::Error> {
    let mut out = std::collections::HashMap::new();
    for vf in vector_fields {
        if let Some(v) = data_map.get(&vf.name) {
            match crate::query::vector_codec::pack(&vf.name, vf.dim, v) {
                Ok(bytes) => {
                    out.insert(vf.name.clone(), bytes);
                }
                Err(crate::query::vector_codec::VectorCodecError::DimMismatch { .. }) => {
                    anyhow::bail!(
                        "VECTOR_DIM_MISMATCH: vector field {:?} has wrong dim",
                        vf.name
                    );
                }
                Err(crate::query::vector_codec::VectorCodecError::NonFinite { .. }) => {
                    anyhow::bail!(
                        "VECTOR_NON_FINITE: vector field {:?} contains NaN or Inf",
                        vf.name
                    );
                }
                Err(e) => {
                    anyhow::bail!("VECTOR_TYPE_ERROR: {e}");
                }
            }
        }
    }
    Ok(out)
}

/// An explicit-policy CHECK to evaluate on the persisted (read-back) row
/// INSIDE the writer transaction. Threaded by the enforcement core
/// (`src/functions/enforce.rs`) so a failing predicate rolls the write back —
/// byte-identical to the REST handler's in-tx CHECK. `None` (the default for
/// the service-key MCP / Privileged-function callers) means "no CHECK", so the
/// existing call sites are unchanged.
#[derive(Clone)]
pub struct PolicyCheck {
    pub ast: crate::query::vector_filter::FilterAst,
    pub auth_id: Option<String>,
}

impl PolicyCheck {
    /// Evaluate `ast` against the read-back `rec`; returns the rollback
    /// sentinel error when the predicate rejects the row.
    fn enforce(&self, rec: &serde_json::Value) -> Result<(), rusqlite::Error> {
        let row_map = rec.as_object().cloned().unwrap_or_default();
        let pc = crate::query::policy::PolicyCtx {
            auth_id: self.auth_id.clone(),
            data: Some(row_map.clone()),
        };
        if crate::query::policy::eval_policy(&self.ast, &row_map, &pc) {
            Ok(())
        } else {
            Err(crate::query::policy::policy_check_sentinel())
        }
    }
}

pub async fn insert_record(
    s: &DrustMcp,
    collection: &str,
    data: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    insert_record_checked(s, collection, data, None).await
}

/// `insert_record` with an optional in-tx policy CHECK (enforcement-core entry).
pub async fn insert_record_checked(
    s: &DrustMcp,
    collection: &str,
    data: serde_json::Value,
    policy_check: Option<PolicyCheck>,
) -> anyhow::Result<serde_json::Value> {
    if is_protected_collection(collection) {
        anyhow::bail!(
            "PROTECTED_COLLECTION: _system_* tables are read-only via MCP records tools. Use the dedicated admin tools."
        );
    }
    let coll = collection.to_string();
    let data_map = data
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("data must be object"))?
        .clone();
    let pool = s.inner().pool.clone();
    let tenant = s.inner().tenant_id.clone();
    let bus = s.inner().bus.clone();

    // Read schema OUTSIDE the writer closure so vector_codec errors
    // can surface as typed anyhow!() before we take the writer lock —
    // matches records.rs (REST) shape.
    let coll_for_schema = coll.clone();
    let schema = pool
        .with_reader(move |c| describe_collection(c, &coll_for_schema))
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown collection: '{}'", coll))?;

    let vector_bytes = pre_encode_vectors(&schema.vector_fields, &data_map)?;
    let vector_names: HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    let webhooks = s.inner().webhooks.clone();
    let (id, record) = pool
        .with_writer_tx(move |tx| -> rusqlite::Result<(i64, serde_json::Value)> {
            let schema = describe_collection(tx, &coll)?
                .ok_or_else(|| invalid_input(format!("unknown collection: '{}'", coll)))?;
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data_map.keys() {
                if !allowed.contains(k.as_str()) {
                    let mut names: Vec<&str> = allowed.iter().copied().collect();
                    names.sort();
                    return Err(invalid_input(format!(
                        "unknown field '{}' for collection '{}' (allowed: {})",
                        k,
                        coll,
                        names.join(", ")
                    )));
                }
            }
            // v1.43 — structured CHECK pre-validation (typed 4xx before the
            // native CHECK would raise a raw SQLite string).
            check_constraints(&schema, &data_map)?;
            let cols: Vec<&str> = data_map.keys().map(|k| k.as_str()).collect();
            let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
            // `RETURNING *` collapses the post-insert read-back: SQLite returns
            // the persisted row in one round-trip, so there is no second SELECT.
            let sql = if cols.is_empty() {
                format!(
                    "INSERT INTO \"{}\" DEFAULT VALUES RETURNING *",
                    coll.replace('"', "\"\"")
                )
            } else {
                format!(
                    "INSERT INTO \"{}\" ({}) VALUES ({}) RETURNING *",
                    coll.replace('"', "\"\""),
                    cols.iter()
                        .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                        .collect::<Vec<_>>()
                        .join(","),
                    placeholders.join(","),
                )
            };
            // Vector fields bind as BLOB from the pre-encoded bytes; the
            // rest go through json_to_sql_value.
            let params: Vec<Value> = data_map
                .iter()
                .map(|(k, v)| match vector_bytes.get(k) {
                    Some(bytes) => Value::Blob(bytes.clone()),
                    None => json_to_sql_value(v),
                })
                .collect();
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let mut stmt = tx.prepare(&sql)?;
            let col_names: Vec<String> =
                stmt.column_names().iter().map(|s| s.to_string()).collect();
            let rec = stmt
                .query_row(&refs[..], |r| materialize_row(r, &col_names, &vector_names))
                .map_err(map_check_violation)?;
            // Pull id from the RETURNING row; fall back to last_insert_rowid for
            // the (theoretical) collection without an `id` column.
            let id = rec
                .get("id")
                .and_then(|v| v.as_i64())
                .unwrap_or_else(|| tx.last_insert_rowid());
            // Explicit-policy CHECK on the persisted row (enforcement core).
            // A failing predicate returns the sentinel → rolls back the INSERT,
            // mirroring records.rs (REST). `None` for service/Privileged.
            if let Some(check) = &policy_check {
                check.enforce(&rec)?;
            }
            Ok((id, rec))
        })
        .await?;
    // Build response first; dispatch only after payload exists.
    let response_payload = json!({ "id": id, "record": record.clone() });
    let ev = Event::Created { record };
    bus.publish(&tenant, collection, ev.clone());
    if let Some(f) = s.inner().functions.as_ref() {
        f.dispatch(&tenant, collection, &ev);
    }
    webhooks.dispatch(&tenant, collection, ev);
    Ok(response_payload)
}

pub async fn update_record(
    s: &DrustMcp,
    collection: &str,
    id: i64,
    data: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    update_record_checked(s, collection, id, data, None, None, None).await
}

/// `update_record` with optional owner/USING filtering + an in-tx policy CHECK
/// (enforcement-core entry). `owner`/`using` are `None` for service/Privileged
/// (id-only UPDATE, unchanged); the caller-identity path passes them so the
/// ownership clause + policy USING pre-flight are AND-ed atomically INSIDE the
/// same write tx as the UPDATE — full parity with `delete_record_filtered`, no
/// read-lane TOCTOU window.
pub async fn update_record_checked(
    s: &DrustMcp,
    collection: &str,
    id: i64,
    data: serde_json::Value,
    owner: Option<(String, String)>,
    using: Option<(String, Vec<Value>)>,
    policy_check: Option<PolicyCheck>,
) -> anyhow::Result<serde_json::Value> {
    if is_protected_collection(collection) {
        anyhow::bail!(
            "PROTECTED_COLLECTION: _system_* tables are read-only via MCP records tools. Use the dedicated admin tools."
        );
    }
    let coll = collection.to_string();
    let data_map = data
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("data must be object"))?
        .clone();
    if data_map.is_empty() {
        anyhow::bail!("data must have at least one field");
    }
    let pool = s.inner().pool.clone();
    let tenant = s.inner().tenant_id.clone();
    let bus = s.inner().bus.clone();
    let webhooks = s.inner().webhooks.clone();

    let coll_for_schema = coll.clone();
    let schema = pool
        .with_reader(move |c| describe_collection(c, &coll_for_schema))
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown collection: '{}'", coll))?;
    let vector_bytes = pre_encode_vectors(&schema.vector_fields, &data_map)?;
    let vector_names: HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    let record = pool
        .with_writer_tx(move |tx| -> rusqlite::Result<serde_json::Value> {
            let schema = describe_collection(tx, &coll)?
                .ok_or_else(|| invalid_input(format!("unknown collection: '{}'", coll)))?;
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data_map.keys() {
                if !allowed.contains(k.as_str()) {
                    let mut names: Vec<&str> = allowed.iter().copied().collect();
                    names.sort();
                    return Err(invalid_input(format!(
                        "unknown field '{}' for collection '{}' (allowed: {})",
                        k,
                        coll,
                        names.join(", ")
                    )));
                }
            }
            // v1.43 — structured CHECK pre-validation (typed 4xx before the
            // native CHECK would raise a raw SQLite string).
            check_constraints(&schema, &data_map)?;
            // Policy-USING pre-flight, AND-ed INSIDE this write tx (mirror
            // delete_record_filtered): a row the caller cannot see per the
            // update USING is not an updatable target → not-found, with NO
            // read-lane TOCTOU window. `None` (service / Privileged) skips it.
            if let Some((frag, pbinds)) = &using {
                let q = format!(
                    "SELECT 1 FROM \"{}\" WHERE id = ?1 AND ({frag})",
                    coll.replace('"', "\"\"")
                );
                let mut pp: Vec<Value> = vec![Value::Integer(id)];
                pp.extend(pbinds.iter().cloned());
                let refs: Vec<&dyn rusqlite::ToSql> =
                    pp.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                if tx
                    .query_row(&q, &refs[..], |r| r.get::<_, i64>(0))
                    .optional()?
                    .is_none()
                {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
            }
            // Owner clause AND-ed onto the UPDATE itself — user_id is UUID-shaped,
            // safe to inline after escaping (same as delete_record_filtered).
            let owner_clause = if let Some((field, user_id)) = &owner {
                format!(
                    " AND \"{}\" = '{}'",
                    field.replace('"', "\"\""),
                    user_id.replace('\'', "''")
                )
            } else {
                String::new()
            };
            let set_exprs: Vec<String> = data_map
                .keys()
                .enumerate()
                .map(|(i, k)| format!("\"{}\" = ?{}", k.replace('"', "\"\""), i + 1))
                .collect();
            // `RETURNING *` collapses the post-update read-back: a zero-row
            // UPDATE (id absent OR the owner clause filtered it out) returns no
            // row, which `.optional()` maps to `None` → `QueryReturnedNoRows` —
            // the single not-found signal both callers rely on.
            let sql = format!(
                "UPDATE \"{}\" SET {}, updated_at = datetime('now') WHERE id = ?{}{} RETURNING *",
                coll.replace('"', "\"\""),
                set_exprs.join(","),
                data_map.len() + 1,
                owner_clause
            );
            let mut params: Vec<Value> = data_map
                .iter()
                .map(|(k, v)| match vector_bytes.get(k) {
                    Some(bytes) => Value::Blob(bytes.clone()),
                    None => json_to_sql_value(v),
                })
                .collect();
            params.push(Value::Integer(id));
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let mut stmt = tx.prepare(&sql)?;
            let col_names: Vec<String> =
                stmt.column_names().iter().map(|s| s.to_string()).collect();
            match stmt
                .query_row(&refs[..], |r| materialize_row(r, &col_names, &vector_names))
                .map_err(map_check_violation)
                .optional()?
            {
                Some(rec) => {
                    // Explicit-policy CHECK on the post-image row (enforcement
                    // core): a failing predicate rolls the UPDATE back, mirroring
                    // records.rs (REST). `None` for service/Privileged.
                    if let Some(check) = &policy_check {
                        check.enforce(&rec)?;
                    }
                    Ok(rec)
                }
                None => Err(rusqlite::Error::QueryReturnedNoRows),
            }
        })
        .await?;
    // Build response first; dispatch only after payload exists.
    let response_payload = json!({ "record": record.clone() });
    let ev = Event::Updated { record };
    bus.publish(&tenant, collection, ev.clone());
    if let Some(f) = s.inner().functions.as_ref() {
        f.dispatch(&tenant, collection, &ev);
    }
    webhooks.dispatch(&tenant, collection, ev);
    Ok(response_payload)
}

/// v1.26 — Validation half of `delete_record`, used by dry_run mode.
/// Runs the existence + protection checks but returns Ok before the
/// DELETE would execute. Errors mirror the real path 1:1 so dry_run
/// surfaces the same problems a real call would.
pub async fn delete_record_validate(s: &DrustMcp, collection: &str, id: i64) -> anyhow::Result<()> {
    if is_protected_collection(collection) {
        anyhow::bail!("PROTECTED_COLLECTION: cannot delete from {collection}");
    }
    let coll_owned = collection.to_string();
    let exists: i64 = s
        .inner()
        .pool
        .with_reader(move |c| {
            let count_sql = format!(
                "SELECT COUNT(*) FROM \"{}\" WHERE id = ?1",
                coll_owned.replace('"', "\"\"")
            );
            c.query_row(&count_sql, rusqlite::params![id], |r| r.get(0))
        })
        .await
        .map_err(|e| anyhow::anyhow!("COLLECTION_NOT_FOUND: {e}"))?;
    if exists == 0 {
        anyhow::bail!("RECORD_NOT_FOUND: id {id} not in {collection}");
    }
    Ok(())
}

pub async fn delete_record(
    s: &DrustMcp,
    collection: &str,
    id: i64,
) -> anyhow::Result<serde_json::Value> {
    delete_record_filtered(s, collection, id, None, None).await
}

/// `delete_record` with an optional owner clause + explicit-policy USING
/// pre-flight (enforcement-core entry). Both are applied INSIDE the writer
/// transaction, byte-mirroring the REST `delete_handler`:
///   - `owner` = `(field, user_id)` AND-ed onto the DELETE's `WHERE` (a User may
///     only delete their own row → a foreign row is a no-op → 404).
///   - `using` = `(sql_fragment, binds)` pre-flight SELECT: a row failing the
///     compiled USING is "not a deletable target" → 404 (same `Ok(0)` arm).
/// `None`/`None` (service / Privileged) → today's id-only DELETE, unchanged.
pub async fn delete_record_filtered(
    s: &DrustMcp,
    collection: &str,
    id: i64,
    owner: Option<(String, String)>,
    using: Option<(String, Vec<Value>)>,
) -> anyhow::Result<serde_json::Value> {
    if is_protected_collection(collection) {
        anyhow::bail!(
            "PROTECTED_COLLECTION: _system_* tables are read-only via MCP records tools. Use the dedicated admin tools."
        );
    }
    let pool = s.inner().pool.clone();
    let tenant = s.inner().tenant_id.clone();
    let bus = s.inner().bus.clone();
    let webhooks = s.inner().webhooks.clone();
    let coll_w = collection.to_string();
    let n = pool
        .with_writer_tx(move |tx| -> rusqlite::Result<usize> {
            // Explicit-policy USING pre-flight (mirror REST delete_handler):
            // a row failing the compiled fragment is not a deletable target.
            if let Some((frag, pbinds)) = &using {
                use rusqlite::OptionalExtension;
                let q = format!(
                    "SELECT 1 FROM \"{}\" WHERE id = ?1 AND ({frag})",
                    coll_w.replace('"', "\"\"")
                );
                let mut pp: Vec<Value> = vec![Value::Integer(id)];
                pp.extend(pbinds.iter().cloned());
                let refs: Vec<&dyn rusqlite::ToSql> =
                    pp.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                if tx
                    .query_row(&q, &refs[..], |r| r.get::<_, i64>(0))
                    .optional()?
                    .is_none()
                {
                    return Ok(0usize);
                }
            }
            // Owner clause AND-ed onto the DELETE — user_id is UUID-shaped,
            // safe to inline after escaping (same as REST delete_handler).
            let owner_clause = if let Some((field, user_id)) = &owner {
                format!(
                    " AND \"{}\" = '{}'",
                    field.replace('"', "\"\""),
                    user_id.replace('\'', "''")
                )
            } else {
                String::new()
            };
            let sql = format!(
                "DELETE FROM \"{}\" WHERE id = ?1{}",
                coll_w.replace('"', "\"\""),
                owner_clause,
            );
            tx.execute(&sql, rusqlite::params![id])
        })
        .await?;
    if n == 0 {
        return Ok(
            json!({ "ok": false, "error_code": "RECORD_NOT_FOUND", "message": format!("record with id {} not found in collection {:?}", id, collection) }),
        );
    }
    // Build response first; dispatch only after payload exists.
    let response_payload = json!({ "ok": true });
    let ev = Event::Deleted { id };
    bus.publish(&tenant, collection, ev.clone());
    if let Some(f) = s.inner().functions.as_ref() {
        f.dispatch(&tenant, collection, &ev);
    }
    webhooks.dispatch(&tenant, collection, ev);
    Ok(response_payload)
}
