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
pub(crate) fn invalid_input(msg: String) -> rusqlite::Error {
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
pub(crate) fn pre_encode_vectors(
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
    let mut out = insert_record_checked(
        s,
        collection,
        data,
        None,
        crate::storage::record_history::AuditActor::service(),
    )
    .await?;
    // v1.56 M4 resource_link: a CONCRETE, top-level link to the new row (the
    // response already carries its `id`). Injected in the single-insert wrapper
    // only, so the shared `insert_record_checked` core (also used by the batch
    // and edge paths) is byte-unchanged. Top-level, so it can never collide
    // with a user column named `resource_link` inside `record`.
    if let Some(o) = out.as_object_mut()
        && let Some(id) = o.get("id").cloned()
    {
        o.insert(
            "resource_link".into(),
            serde_json::Value::String(format!(
                "drust://{}/collections/{}/records/{}",
                s.tenant_id(),
                collection,
                id
            )),
        );
    }
    Ok(out)
}

/// `insert_record` with an optional in-tx policy CHECK (enforcement-core entry).
/// The per-row INSERT body, run INSIDE a caller-supplied writer transaction.
/// Shared by single-row `insert_record_checked` (called once) and batch insert
/// (M2 — called once per row inside ONE tx). In order: per-row quota check,
/// field allowlist, structured CHECK pre-validation, `INSERT ... RETURNING *`
/// projected via `materialize_row`, id extraction, optional policy CHECK, and
/// in-tx record-history capture. `schema` is the AUTHORITATIVE in-tx describe
/// the caller performed once; `quota_tier`/`vector_names`/`actor` are shared
/// across a batch while `data_map`/`vector_bytes` are per row. Returns
/// `(id, post-image row)`. A rolled-back tx discards the data AND history rows.
#[allow(clippy::too_many_arguments)]
pub(crate) fn insert_row_in_tx(
    tx: &rusqlite::Connection,
    schema: &crate::storage::schema::CollectionSchema,
    data_map: &serde_json::Map<String, serde_json::Value>,
    vector_bytes: &std::collections::HashMap<String, Vec<u8>>,
    vector_names: &HashSet<String>,
    quota_tier: i64,
    policy_check: Option<&PolicyCheck>,
    actor: &crate::storage::record_history::AuditActor,
) -> rusqlite::Result<(i64, serde_json::Value)> {
    // Per-tenant hard quota, measured on THIS writer conn inside the tx
    // (single-writer invariant, no TOCTOU). usage_on_conn reflects in-tx page
    // growth, so in a batch the row that would cross the tier fails here → the
    // whole tx rolls back. incoming=0: "reject the next growth once at cap".
    crate::storage::quota::check_tenant_quota(
        crate::storage::quota::usage_on_conn(tx)?,
        0,
        quota_tier,
    )
    .map_err(crate::error::quota_exceeded_error)?;
    // v1.58 P1-3 — an owner-scoped collection may not take a row with no owner.
    //
    // Placed in the shared per-row body rather than as a fourth parallel check
    // beside REST / edge / batch, so MCP single insert, MCP batch insert, upsert
    // and the edge host op are covered by one guard. Predicate is byte-identical
    // to the batch pre-tx check so the two cannot drift.
    //
    // This is row VALIDATION, not an authorization gate, so it deliberately
    // binds `CallerCtx::Privileged` as well. Do not assume every caller has
    // already settled the field: the service REST path supplies it and
    // `functions::enforce` stamps it for a User, but the Privileged arm of the
    // wasm `insert-record` host import (`functions/runtime.rs`) calls
    // `write::insert_record` DIRECTLY and does neither — it arrives here with
    // whatever the guest sent. Cron fires, record/file event dispatch and
    // service manual invoke all run as Privileged, so before this guard they
    // could mint owner-less rows. Refusing them matches REST-service (409
    // OWNER_FIELD_REQUIRED) and the `AuthCtx::Service` arm of `enforce.rs`, and
    // it is the same family as the quota, unknown-field and CHECK validations
    // that already bind Privileged in this body. God-mode covers authorization
    // — caps, owner filtering, RLS, file caps — not row validation.
    // `.claude/rules/background-jobs.md` records the carve-out;
    // `tests/mcp_owner_field_required.rs` pins the Privileged branch.
    if let Some(of) = schema.owner_field.as_deref() {
        let supplied = data_map
            .get(of)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty());
        if !supplied {
            return Err(invalid_input(format!(
                "OWNER_FIELD_REQUIRED: must supply a non-empty '{of}' on owner-scoped collection '{}'",
                schema.name
            )));
        }
    }
    let allowed: std::collections::HashSet<&str> =
        schema.fields.iter().map(|f| f.name.as_str()).collect();
    for k in data_map.keys() {
        if !allowed.contains(k.as_str()) {
            let mut names: Vec<&str> = allowed.iter().copied().collect();
            names.sort();
            return Err(invalid_input(format!(
                "unknown field '{}' for collection '{}' (allowed: {})",
                k,
                schema.name,
                names.join(", ")
            )));
        }
    }
    // v1.43 — structured CHECK pre-validation (typed 4xx before the native
    // CHECK would raise a raw SQLite string).
    check_constraints(schema, data_map)?;
    let cols: Vec<&str> = data_map.keys().map(|k| k.as_str()).collect();
    let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
    // `RETURNING *` collapses the post-insert read-back into one round-trip.
    let sql = if cols.is_empty() {
        format!(
            "INSERT INTO \"{}\" DEFAULT VALUES RETURNING *",
            schema.name.replace('"', "\"\"")
        )
    } else {
        format!(
            "INSERT INTO \"{}\" ({}) VALUES ({}) RETURNING *",
            schema.name.replace('"', "\"\""),
            cols.iter()
                .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(","),
            placeholders.join(","),
        )
    };
    // Vector fields bind as BLOB from the pre-encoded bytes; the rest through
    // json_to_sql_value.
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
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rec = stmt
        .query_row(&refs[..], |r| materialize_row(r, &col_names, vector_names))
        .map_err(map_check_violation)?;
    // Pull id from the RETURNING row; fall back to last_insert_rowid for the
    // (theoretical) collection without an `id` column.
    let id = rec
        .get("id")
        .and_then(|v| v.as_i64())
        .unwrap_or_else(|| tx.last_insert_rowid());
    // Explicit-policy CHECK on the persisted row. A failing predicate returns
    // the sentinel → rolls back the INSERT. `None` for service/Privileged.
    if let Some(check) = policy_check {
        check.enforce(&rec)?;
    }
    // v1.46 — history capture (in-tx, atomic; after the policy CHECK so a
    // rejected insert leaves no history row). new = the persisted row.
    crate::storage::record_history::capture(
        tx,
        &schema.name,
        crate::storage::record_history::HistoryOp::Insert,
        id,
        None,
        Some(&rec),
        actor,
        schema.audit_enabled,
    )?;
    Ok((id, rec))
}

/// Validate that `on_conflict` (as a column SET) matches a real conflict target
/// on `table`: any UNIQUE index — INCLUDING the implicit `sqlite_autoindex_*` a
/// `UNIQUE` COLUMN / non-integer PK / composite PK creates — or the bare
/// single-column INTEGER PRIMARY KEY (rowid). We query `PRAGMA index_xinfo`/
/// `table_info` DIRECTLY rather than reuse `describe_collection().indices`,
/// which deliberately FILTERS OUT autoindexes (schema.rs) — a `sku TEXT UNIQUE`
/// or a PK target would be invisible there and wrongly rejected. Order-
/// insensitive set match.
///
/// Returns the matched target's **per-column collation** (`column → collation
/// name`, e.g. `NOCASE`), so the caller's pre-image probe can match SQLite's
/// actual ON CONFLICT semantics (a `NOCASE` unique index must probe with
/// `COLLATE NOCASE`, else `'a'` vs stored `'A'` is misclassified as an insert).
/// UNIQUE indexes are checked BEFORE the bare-PK branch so a non-integer/
/// composite PK's autoindex supplies its real collation; the rowid-PK branch
/// (no autoindex) defaults to `BINARY`. `UPSERT_NO_UNIQUE` / `_NO_CONFLICT_COLS`
/// / `_DUPLICATE_COLUMN` otherwise.
pub(crate) fn validate_conflict_target(
    tx: &rusqlite::Connection,
    table: &str,
    on_conflict: &[String],
) -> rusqlite::Result<std::collections::HashMap<String, String>> {
    if on_conflict.is_empty() {
        return Err(invalid_input(
            "UPSERT_NO_CONFLICT_COLS: on_conflict must list at least one column".to_string(),
        ));
    }
    // Reject duplicate columns — `["sku","sku"]` would dedup to a matching set
    // below but generate a malformed `ON CONFLICT("sku","sku")`.
    let mut distinct = std::collections::HashSet::new();
    for c in on_conflict {
        if !distinct.insert(c.as_str()) {
            return Err(invalid_input(format!(
                "UPSERT_DUPLICATE_COLUMN: on_conflict lists column '{c}' more than once"
            )));
        }
    }
    let esc = |s: &str| s.replace('"', "\"\"");
    let want: std::collections::BTreeSet<String> = on_conflict.iter().cloned().collect();

    // Candidate 1 (checked first): any UNIQUE index (incl. `sqlite_autoindex_*`)
    // whose KEY-column set equals `on_conflict`. `index_xinfo` yields the per-
    // column collation (col 4) for key columns (col 5 == 1); auxiliary/rowid
    // entries (key == 0, or a NULL expression name) are skipped.
    let idx_names: Vec<String> = tx
        .prepare(&format!("PRAGMA index_list(\"{}\")", esc(table)))?
        // index_list cols: (0 seq, 1 name, 2 unique, 3 origin, 4 partial).
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        // UNIQUE and NOT partial. A partial unique index (`... WHERE <pred>`)
        // requires a matching `ON CONFLICT(cols) WHERE <pred>` — drust generates
        // no WHERE, so SQLite would reject the target at runtime; refuse it here
        // with a clean UPSERT_NO_UNIQUE instead.
        .filter(|(_, uniq, partial)| *uniq == 1 && *partial == 0)
        .map(|(n, _, _)| n)
        .collect();
    for iname in idx_names {
        let key_cols: Vec<(Option<String>, String)> = tx
            .prepare(&format!("PRAGMA index_xinfo(\"{}\")", esc(&iname)))?
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(5)?,            // key (1 = a key column)
                    r.get::<_, Option<String>>(2)?, // column name (NULL = expression)
                    r.get::<_, Option<String>>(4)?, // collation
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|(key, _, _)| *key == 1)
            .map(|(_, name, coll)| (name, coll.unwrap_or_else(|| "BINARY".to_string())))
            .collect();
        // An expression key column (NULL name) means this is not a plain-column
        // unique index — it cannot be an `ON CONFLICT(col, ...)` target. Skip the
        // WHOLE index so a caller can't falsely match on the remaining named
        // subset (e.g. `(a, lower(b))` must NOT satisfy on_conflict=["a"]).
        if key_cols.iter().any(|(name, _)| name.is_none()) {
            continue;
        }
        let cols: Vec<(String, String)> = key_cols
            .into_iter()
            .map(|(name, coll)| (name.unwrap(), coll))
            .collect();
        let colset: std::collections::BTreeSet<String> =
            cols.iter().map(|(n, _)| n.clone()).collect();
        if !colset.is_empty() && colset == want {
            return Ok(cols.into_iter().collect());
        }
    }

    // Candidate 2: the bare single/composite PRIMARY KEY (`table_info.pk` > 0).
    // A non-integer or composite PK already matched above via its autoindex; the
    // only case reaching here is the rowid INTEGER PRIMARY KEY, which compares
    // as an integer — collation BINARY.
    let pk: std::collections::BTreeSet<String> = tx
        .prepare(&format!("PRAGMA table_info(\"{}\")", esc(table)))?
        .query_map([], |r| Ok((r.get::<_, i64>(5)?, r.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|(pk, _)| *pk > 0)
        .map(|(_, n)| n)
        .collect();
    if !pk.is_empty() && pk == want {
        return Ok(pk.into_iter().map(|n| (n, "BINARY".to_string())).collect());
    }

    Err(invalid_input(format!(
        "UPSERT_NO_UNIQUE: on_conflict {on_conflict:?} does not match any UNIQUE index or the \
         primary key of '{table}'"
    )))
}

/// The per-row UPSERT body, run INSIDE a caller-supplied writer tx (M2). Mirrors
/// [`insert_row_in_tx`] but resolves an existing row by the `on_conflict` key
/// first: a hit is an UPDATE (history `op=update`, old=pre-image), a miss is an
/// INSERT (`op=insert`). Order: field allowlist → conflict-key presence →
/// structured CHECK → pre-image probe → **quota gate ONLY on the insert branch**
/// (a conflict UPDATE mirrors `update_record_checked`: not quota-gated, so a
/// shrink/recovery is never blocked) → `INSERT ... ON CONFLICT(<cols>) DO UPDATE
/// SET <non-key col>=excluded.<col>, updated_at=datetime('now') RETURNING *` →
/// in-tx history capture. Returns `(op, post-image)`; a rolled-back tx discards
/// data AND history. Upsert is service-only (no policy CHECK; service bypasses).
#[allow(clippy::too_many_arguments)]
pub(crate) fn upsert_row_in_tx(
    tx: &rusqlite::Connection,
    schema: &crate::storage::schema::CollectionSchema,
    data_map: &serde_json::Map<String, serde_json::Value>,
    vector_bytes: &std::collections::HashMap<String, Vec<u8>>,
    vector_names: &HashSet<String>,
    on_conflict: &[String],
    collations: &std::collections::HashMap<String, String>,
    quota_tier: i64,
    actor: &crate::storage::record_history::AuditActor,
) -> rusqlite::Result<(crate::storage::record_history::HistoryOp, serde_json::Value)> {
    use crate::storage::record_history::HistoryOp;
    let allowed: std::collections::HashSet<&str> =
        schema.fields.iter().map(|f| f.name.as_str()).collect();
    for k in data_map.keys() {
        if !allowed.contains(k.as_str()) {
            let mut names: Vec<&str> = allowed.iter().copied().collect();
            names.sort();
            return Err(invalid_input(format!(
                "unknown field '{}' for collection '{}' (allowed: {})",
                k,
                schema.name,
                names.join(", ")
            )));
        }
    }
    // Every conflict key must be present in the row — otherwise we cannot probe
    // the pre-image (nor would the caller's intent be well-defined).
    for c in on_conflict {
        if !data_map.contains_key(c) {
            return Err(invalid_input(format!(
                "UPSERT_MISSING_KEY: row is missing on_conflict column '{c}'"
            )));
        }
    }
    check_constraints(schema, data_map)?;
    let esc = |s: &str| s.replace('"', "\"\"");

    // Pre-image by the conflict key → decides op + supplies history `old`. The
    // probe MUST use the conflict index's collation (from validate_conflict_
    // target), else a `NOCASE` unique index makes SQLite take the DO UPDATE
    // branch while a BINARY `=` here misses the row and misclassifies it as an
    // insert (wrong history op / lost old image / a pure update wrongly quota-
    // gated). `collation_clause` is empty for BINARY (the common case).
    let key_where: Vec<String> = on_conflict
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let coll = collations.get(c).map(|s| s.as_str()).unwrap_or("BINARY");
            // Collation names come from `PRAGMA index_xinfo` (SQLite metadata,
            // not user input): BINARY / NOCASE / RTRIM. Safe to interpolate.
            let collation_clause = if coll.eq_ignore_ascii_case("BINARY") {
                String::new()
            } else {
                format!(" COLLATE {coll}")
            };
            format!("\"{}\" = ?{}{}", esc(c), i + 1, collation_clause)
        })
        .collect();
    let sel = format!(
        "SELECT * FROM \"{}\" WHERE {}",
        esc(&schema.name),
        key_where.join(" AND ")
    );
    let key_params: Vec<Value> = on_conflict
        .iter()
        .map(|c| match vector_bytes.get(c) {
            Some(bytes) => Value::Blob(bytes.clone()),
            None => json_to_sql_value(&data_map[c]),
        })
        .collect();
    let krefs: Vec<&dyn rusqlite::ToSql> = key_params
        .iter()
        .map(|v| v as &dyn rusqlite::ToSql)
        .collect();
    let pre = {
        let mut st = tx.prepare(&sel)?;
        let cn: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
        st.query_row(&krefs[..], |r| materialize_row(r, &cn, vector_names))
            .optional()?
    };
    let op = if pre.is_some() {
        HistoryOp::Update
    } else {
        HistoryOp::Insert
    };
    // Quota gates the growth (INSERT) branch only — a conflict UPDATE is in
    // lockstep with `update_record_checked` (v1.50 F3: never block a shrink).
    if matches!(op, HistoryOp::Insert) {
        crate::storage::quota::check_tenant_quota(
            crate::storage::quota::usage_on_conn(tx)?,
            0,
            quota_tier,
        )
        .map_err(crate::error::quota_exceeded_error)?;
    }

    let cols: Vec<&str> = data_map.keys().map(|k| k.as_str()).collect();
    let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
    let key_set: std::collections::HashSet<&str> = on_conflict.iter().map(|s| s.as_str()).collect();
    // DO UPDATE assigns every NON-key, NON-server-managed provided column from
    // `excluded`, plus a convergent `updated_at` so `RETURNING *` matches the
    // committed (post AFTER-trigger) row (v1.43 reader-cache/RETURNING invariant).
    // `id` / `created_at` are drust-maintained (`SYSTEM_COLUMNS`): the INSERT
    // branch still honors an explicitly-supplied value (they ride the VALUES
    // list), but the UPDATE branch must NOT overwrite an existing row's PK or
    // creation time even when the payload carries them (external-sync payloads
    // routinely include their own id) — that would move the PK / reset the
    // timestamp and diverge the history record_id from the pre-image.
    let mut set_exprs: Vec<String> = cols
        .iter()
        .filter(|c| {
            !key_set.contains(**c) && !crate::mcp::tools::schema::SYSTEM_COLUMNS.contains(&**c)
        })
        .map(|c| {
            let e = esc(c);
            format!("\"{e}\" = excluded.\"{e}\"")
        })
        .collect();
    if schema.fields.iter().any(|f| f.name == "updated_at") {
        set_exprs.push("updated_at = datetime('now')".to_string());
    }
    if set_exprs.is_empty() {
        // Degenerate: only key columns and no `updated_at` — a harmless
        // self-assignment keeps DO UPDATE (and thus RETURNING) well-formed.
        let e = esc(&on_conflict[0]);
        set_exprs.push(format!("\"{e}\" = excluded.\"{e}\""));
    }
    let conflict_sql = on_conflict
        .iter()
        .map(|c| format!("\"{}\"", esc(c)))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "INSERT INTO \"{}\" ({}) VALUES ({}) ON CONFLICT({}) DO UPDATE SET {} RETURNING *",
        esc(&schema.name),
        cols.iter()
            .map(|c| format!("\"{}\"", esc(c)))
            .collect::<Vec<_>>()
            .join(","),
        placeholders.join(","),
        conflict_sql,
        set_exprs.join(","),
    );
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
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rec = stmt
        .query_row(&refs[..], |r| materialize_row(r, &col_names, vector_names))
        .map_err(map_check_violation)?;
    let id = rec
        .get("id")
        .and_then(|v| v.as_i64())
        .unwrap_or_else(|| tx.last_insert_rowid());
    crate::storage::record_history::capture(
        tx,
        &schema.name,
        op,
        id,
        pre.as_ref(),
        Some(&rec),
        actor,
        schema.audit_enabled,
    )?;
    Ok((op, rec))
}

pub async fn insert_record_checked(
    s: &DrustMcp,
    collection: &str,
    data: serde_json::Value,
    policy_check: Option<PolicyCheck>,
    actor: crate::storage::record_history::AuditActor,
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
    // v1.50 (Spec B §5.1) — per-tenant quota tier. `meta` is Some on the prod
    // MCP + edge host state; test-only ctors pass None → fail-safe tier 1 (the
    // check never fires on the tiny test DBs). Read once before the writer tx.
    let inner = s.inner();
    let quota_tier = match inner.meta.as_ref() {
        Some(m) => crate::storage::quota::read_tier(m, &inner.tenant_id).await,
        None => 1,
    };
    let (id, record) = pool
        .with_writer_tx(move |tx| -> rusqlite::Result<(i64, serde_json::Value)> {
            // Authoritative in-tx describe (once), then the shared per-row body.
            let schema = describe_collection(tx, &coll)?
                .ok_or_else(|| invalid_input(format!("unknown collection: '{}'", coll)))?;
            insert_row_in_tx(
                tx,
                &schema,
                &data_map,
                &vector_bytes,
                &vector_names,
                quota_tier,
                policy_check.as_ref(),
                &actor,
            )
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
    update_record_checked(
        s,
        collection,
        id,
        data,
        None,
        None,
        None,
        crate::storage::record_history::AuditActor::service(),
    )
    .await
}

/// `update_record` with optional owner/USING filtering + an in-tx policy CHECK
/// (enforcement-core entry). `owner`/`using` are `None` for service/Privileged
/// (id-only UPDATE, unchanged); the caller-identity path passes them so the
/// ownership clause + policy USING pre-flight are AND-ed atomically INSIDE the
/// same write tx as the UPDATE — full parity with `delete_record_filtered`, no
/// read-lane TOCTOU window.
#[allow(clippy::too_many_arguments)]
pub async fn update_record_checked(
    s: &DrustMcp,
    collection: &str,
    id: i64,
    data: serde_json::Value,
    owner: Option<(String, String)>,
    using: Option<(String, Vec<Value>)>,
    policy_check: Option<PolicyCheck>,
    actor: crate::storage::record_history::AuditActor,
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

    // v1.50 (Spec B, adversarial F3): UPDATE is NOT quota-gated. A shrink or
    // in-place update must never be blocked — a tenant already over cap (e.g.
    // after an owner tier downgrade) has to be able to shrink to recover
    // (spec §7). Growth is gated at INSERT / upload / write-RPC instead.
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
            // v1.46 — pre-image for history, gated + owner-scoped (only a row
            // this caller may update is recorded). Shared projector = plain
            // prepare + vectors hidden (v1.43 reader-cache rule).
            let old_json = if schema.audit_enabled {
                crate::storage::record_history::select_row_json_owner(
                    tx,
                    &coll,
                    id,
                    &owner,
                    &vector_names,
                )?
            } else {
                None
            };
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
                    // v1.46 — history capture (in-tx; after the CHECK so a
                    // rejected update leaves no history row even before rollback).
                    crate::storage::record_history::capture(
                        tx,
                        &coll,
                        crate::storage::record_history::HistoryOp::Update,
                        id,
                        old_json.as_ref(),
                        Some(&rec),
                        &actor,
                        schema.audit_enabled,
                    )?;
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
    delete_record_filtered(
        s,
        collection,
        id,
        None,
        None,
        crate::storage::record_history::AuditActor::service(),
    )
    .await
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
    actor: crate::storage::record_history::AuditActor,
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
            // v1.46 — one describe covers both the audit gate and the vector
            // names for the pre-image projector. A missing collection maps to
            // (gate off, no vectors) so the DELETE below surfaces the same
            // "no such table" error as before.
            let (audit_on, vnames) = match describe_collection(tx, &coll_w)? {
                Some(schema) => (
                    schema.audit_enabled,
                    schema
                        .vector_fields
                        .iter()
                        .map(|v| v.name.clone())
                        .collect::<HashSet<String>>(),
                ),
                None => (false, HashSet::new()),
            };
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
            // v1.46 — pre-image before the DELETE, owner-scoped (shared
            // projector; only a row this caller may delete is recorded).
            let old_json = if audit_on {
                crate::storage::record_history::select_row_json_owner(
                    tx, &coll_w, id, &owner, &vnames,
                )?
            } else {
                None
            };
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
            let n = tx.execute(&sql, rusqlite::params![id])?;
            if n > 0 {
                crate::storage::record_history::capture(
                    tx,
                    &coll_w,
                    crate::storage::record_history::HistoryOp::Delete,
                    id,
                    old_json.as_ref(),
                    None,
                    &actor,
                    audit_on,
                )?;
            }
            Ok(n)
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

#[cfg(test)]
mod validate_conflict_target_tests {
    use super::validate_conflict_target;
    use rusqlite::Connection;

    fn conn_with(ddl: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(ddl).unwrap();
        c
    }

    #[test]
    fn accepts_unique_column_returns_binary_collation() {
        let c = conn_with("CREATE TABLE t(sku TEXT UNIQUE, name TEXT);");
        let m = validate_conflict_target(&c, "t", &["sku".to_string()]).unwrap();
        assert_eq!(m.get("sku").map(|s| s.as_str()), Some("BINARY"));
    }

    #[test]
    fn accepts_integer_pk_target() {
        // Bare INTEGER PRIMARY KEY (rowid, no autoindex) still resolves via the
        // PK fallback after the unique-index scan.
        let c = conn_with("CREATE TABLE t(id INTEGER PRIMARY KEY, sku TEXT);");
        let m = validate_conflict_target(&c, "t", &["id".to_string()]).unwrap();
        assert_eq!(m.get("id").map(|s| s.as_str()), Some("BINARY"));
    }

    #[test]
    fn reports_index_collation() {
        let c = conn_with(
            "CREATE TABLE t(sku TEXT, name TEXT); \
             CREATE UNIQUE INDEX ux ON t(sku COLLATE NOCASE);",
        );
        let m = validate_conflict_target(&c, "t", &["sku".to_string()]).unwrap();
        assert_eq!(m.get("sku").map(|s| s.as_str()), Some("NOCASE"));
    }

    #[test]
    fn rejects_partial_unique_index() {
        let c = conn_with(
            "CREATE TABLE t(sku TEXT, name TEXT); \
             CREATE UNIQUE INDEX ux ON t(sku) WHERE name IS NOT NULL;",
        );
        let e = validate_conflict_target(&c, "t", &["sku".to_string()]).unwrap_err();
        assert!(e.to_string().contains("UPSERT_NO_UNIQUE"), "got {e}");
    }

    #[test]
    fn rejects_expression_index_on_named_subset() {
        // `(sku, lower(name))` must NOT satisfy on_conflict=["sku"].
        let c = conn_with(
            "CREATE TABLE t(sku TEXT, name TEXT); \
             CREATE UNIQUE INDEX ux ON t(sku, lower(name));",
        );
        let e = validate_conflict_target(&c, "t", &["sku".to_string()]).unwrap_err();
        assert!(e.to_string().contains("UPSERT_NO_UNIQUE"), "got {e}");
    }

    #[test]
    fn rejects_duplicate_columns() {
        let c = conn_with("CREATE TABLE t(a TEXT, b TEXT, UNIQUE(a, b));");
        let e = validate_conflict_target(&c, "t", &["a".to_string(), "a".to_string()]).unwrap_err();
        assert!(e.to_string().contains("UPSERT_DUPLICATE_COLUMN"), "got {e}");
    }

    #[test]
    fn rejects_non_unique_target() {
        let c = conn_with("CREATE TABLE t(sku TEXT UNIQUE, name TEXT);");
        let e = validate_conflict_target(&c, "t", &["name".to_string()]).unwrap_err();
        assert!(e.to_string().contains("UPSERT_NO_UNIQUE"), "got {e}");
    }
}
