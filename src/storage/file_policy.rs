//! Files-RLS prefix policy registry (#950-B, v1.63) — the `_system_file_policy`
//! table, the synthetic schema the policy engine evaluates against, and the
//! marker-guarded root seed.
//!
//! A "folder" in drust is a **prefix of `_system_files.path`**, never an object.
//! One registry row attaches an access rule to one prefix, and the LONGEST
//! matching prefix wins — that is inheritance and override with no tree, no
//! folder rows, and no rename problem. `''` is the tenant root and matches every
//! file including the unfiled ones (`path IS NULL`).
//!
//! Three things here are load-bearing:
//!
//! * **`public_read` is a stored column, not a derived property.** A row with
//!   `owner_scoped=0`, no select clause and `public_read=0` is "restricted but
//!   unspecified" and DENIES all reads on both evaluators (T4/T5). The write
//!   face refuses to create that shape ([`FILE_POLICY_OPEN_REQUIRES_FLAG`]), and
//!   the read face denies it anyway — a legacy or hand-INSERTed row must fail
//!   CLOSED. Keeping the open decision in the schema is what makes the
//!   fail-open shape structurally impossible instead of merely validated once
//!   (CLAUDE.md invariant 12's `select_read_access` is the same lesson).
//! * **The policy engine is reused verbatim.** [`file_policy_schema`] is a
//!   synthetic [`CollectionSchema`] describing a file row, so `validate_policy`,
//!   `compile_policy_using` and `eval_policy` all work on file policies with no
//!   engine change and no second grammar to drift.
//! * **Config is service-only** on every face. An end user able to write its own
//!   policy is a privilege escalation, not a feature.

use crate::query::policy::{CollectionPolicies, Policy, validate_policy};
use crate::query::vector_filter::FilterAst;
use crate::storage::file_path::validate_file_prefix;
use crate::storage::schema::{CollectionSchema, DmlVerb, Field};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A prefix that is neither `''` nor a valid path with a trailing `/`.
pub const FILE_POLICY_PREFIX_INVALID: &str = "FILE_POLICY_PREFIX_INVALID";
/// `owner_scoped=0` + no select clause + no `public_read` — the deny-all shape.
pub const FILE_POLICY_OPEN_REQUIRES_FLAG: &str = "FILE_POLICY_OPEN_REQUIRES_FLAG";
/// A policy clause referencing an unsupported column, or comparing across
/// storage classes (#954) — the two cases where the SQL and in-memory
/// evaluators would order operands differently.
pub const FILE_POLICY_OPERAND_UNSUPPORTED: &str = "FILE_POLICY_OPERAND_UNSUPPORTED";
/// `clear_file_policy` naming a prefix with no registry row.
pub const FILE_POLICY_NOT_FOUND: &str = "FILE_POLICY_NOT_FOUND";

/// One registered prefix rule. Serialized shape is the REST/MCP wire shape:
/// the two AST columns are named `select` / `delete` there (the SQL columns
/// carry the `_policy_json` suffix).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePolicyRow {
    /// `''` = the tenant root; anything else ends with `/`.
    pub prefix: String,
    /// AND-composes `uploader == $auth` onto every decision for this prefix.
    #[serde(default)]
    pub owner_scoped: bool,
    /// The EXPLICIT open flag. See the module docs — its absence on an
    /// otherwise clause-less row means deny, never "no restriction".
    #[serde(default)]
    pub public_read: bool,
    #[serde(rename = "select", default)]
    pub select_policy: Option<FilterAst>,
    /// `None` inherits the select semantics (readable ⇒ possibly deletable;
    /// the `Delete` file cap is still required on top).
    #[serde(rename = "delete", default)]
    pub delete_policy: Option<FilterAst>,
}

/// A rejected registry write. Carries the stable error code every face reports
/// (REST status, MCP tool error, admin UI toast) so the four surfaces cannot
/// drift into four different vocabularies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePolicyError {
    PrefixInvalid(String),
    OpenRequiresFlag,
    OperandUnsupported(String),
    NotFound(String),
}

impl FilePolicyError {
    pub fn code(&self) -> &'static str {
        match self {
            FilePolicyError::PrefixInvalid(_) => FILE_POLICY_PREFIX_INVALID,
            FilePolicyError::OpenRequiresFlag => FILE_POLICY_OPEN_REQUIRES_FLAG,
            FilePolicyError::OperandUnsupported(_) => FILE_POLICY_OPERAND_UNSUPPORTED,
            FilePolicyError::NotFound(_) => FILE_POLICY_NOT_FOUND,
        }
    }

    pub fn message(&self) -> String {
        match self {
            FilePolicyError::PrefixInvalid(why) => why.clone(),
            FilePolicyError::OpenRequiresFlag => "a prefix that is neither owner-scoped nor \
                 filtered by a select clause is unrestricted: pass public_read=true to say so \
                 explicitly, or the prefix denies every read"
                .to_string(),
            FilePolicyError::OperandUnsupported(why) => why.clone(),
            FilePolicyError::NotFound(prefix) => {
                format!("no file policy registered for prefix {prefix:?}")
            }
        }
    }
}

impl std::fmt::Display for FilePolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for FilePolicyError {}

/// The synthetic collection the policy engine evaluates a file row against.
///
/// Columns are the policy-visible slice of `_system_files`. Three real columns
/// are deliberately ABSENT — `content_disposition`, `cache_control` and
/// `meta_json` — so `validate_field` refuses to reference them: the first two
/// are presentation, and `meta_json` is caller-supplied JSON the `FilterAst`
/// grammar cannot address at all (a policy over it would be a promise drust
/// cannot keep).
///
/// `id` / `created_at` / `updated_at` are NOT listed and do not need to be: the
/// engine admits those three system columns unconditionally. That is exactly
/// why `FileRow` carries `created_at` / `updated_at` — the in-memory row map
/// must have the keys, or `is_null` on a missing key reads as TRUE and the
/// prefix fails OPEN.
pub fn file_policy_schema() -> CollectionSchema {
    fn field(name: &str, sql_type: &str) -> Field {
        Field {
            name: name.to_string(),
            sql_type: sql_type.to_string(),
            nullable: true,
            ..Default::default()
        }
    }
    CollectionSchema {
        name: "_system_files".to_string(),
        fields: vec![
            field("path", "TEXT"),
            field("uploader", "TEXT"),
            field("key", "TEXT"),
            field("visibility", "TEXT"),
            field("content_type", "TEXT"),
            field("original_name", "TEXT"),
            field("size_bytes", "INTEGER"),
            field("uploaded_at", "TEXT"),
        ],
        indices: Vec::new(),
        row_count: 0,
        anon_caps: BTreeSet::new(),
        user_caps: BTreeSet::new(),
        owner_field: None,
        read_scope: None,
        vector_fields: Vec::new(),
        fts_indexes: Vec::new(),
        realtime_enabled: false,
        audit_enabled: false,
        description: None,
        policies: CollectionPolicies::default(),
    }
}

/// Validate a registry write. Shared by every face (REST now, MCP in T6) so
/// the three refusals are the same three refusals everywhere.
pub fn validate_file_policy(row: &FilePolicyRow) -> Result<(), FilePolicyError> {
    validate_file_prefix(&row.prefix).map_err(FilePolicyError::PrefixInvalid)?;
    // The clause-less gate. `delete_policy` is deliberately NOT an escape
    // hatch: it governs deletes only, so a row carrying just a delete clause
    // still says nothing about who may READ the prefix.
    if !row.owner_scoped && row.select_policy.is_none() && !row.public_read {
        return Err(FilePolicyError::OpenRequiresFlag);
    }
    let schema = file_policy_schema();
    for (op, ast) in [
        (DmlVerb::Select, row.select_policy.as_ref()),
        (DmlVerb::Delete, row.delete_policy.as_ref()),
    ] {
        let Some(ast) = ast else { continue };
        // `validate_policy` runs the field allowlist, the grammar check and the
        // #954 cross-storage-class check in one pass — the same code path a
        // collection policy takes, against the synthetic file schema. Wrapping
        // the AST as a `using` clause is what makes that reuse exact: `using`
        // is the read/target-preflight direction, which is what a file policy
        // is.
        let probe = Policy {
            using: Some(ast.clone()),
            check: None,
        };
        validate_policy(&schema, op, &probe)
            .map_err(|e| FilePolicyError::OperandUnsupported(e.to_string()))?;
    }
    Ok(())
}

/// Every registered prefix, ordered by prefix. Any failure — a missing table, a
/// row whose stored JSON no longer parses — propagates, and every caller maps a
/// propagated error to DENY (spec §授權語意: policy read failure ⇒ refuse).
///
/// Plain `prepare`, not `prepare_cached`: the REST file handlers open a fresh
/// connection per request so a cache would never be hit there, and this table
/// is small enough that the parse is not the cost.
pub fn load_file_policies(conn: &Connection) -> rusqlite::Result<Vec<FilePolicyRow>> {
    let mut stmt = conn.prepare(
        "SELECT prefix, owner_scoped, public_read, select_policy_json, delete_policy_json \
         FROM \"_system_file_policy\" ORDER BY prefix",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(FilePolicyRow {
            prefix: r.get(0)?,
            owner_scoped: r.get::<_, i64>(1)? != 0,
            public_read: r.get::<_, i64>(2)? != 0,
            select_policy: parse_stored_ast(r.get::<_, Option<String>>(3)?, 3)?,
            delete_policy: parse_stored_ast(r.get::<_, Option<String>>(4)?, 4)?,
        })
    })?;
    rows.collect()
}

fn parse_stored_ast(raw: Option<String>, idx: usize) -> rusqlite::Result<Option<FilterAst>> {
    match raw {
        None => Ok(None),
        Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
        }),
    }
}

/// The rule that governs `path` — the longest registered prefix that `path`
/// starts with, or `None` when nothing matches (the caller then applies the
/// owner-scoped default).
///
/// Byte-prefix, not character-prefix and not `LIKE`: `%` and `_` are ordinary
/// characters in a path, and the SQL side of this decision (T5) is a binary
/// range for exactly the same reason. `path = None` (an unfiled row) can only
/// ever match `''`.
pub fn longest_match<'a>(
    policies: &'a [FilePolicyRow],
    path: Option<&str>,
) -> Option<&'a FilePolicyRow> {
    match path {
        None => policies.iter().find(|p| p.prefix.is_empty()),
        Some(path) => policies
            .iter()
            .filter(|p| path.as_bytes().starts_with(p.prefix.as_bytes()))
            .max_by_key(|p| p.prefix.len()),
    }
}

/// Create or replace one prefix rule. Callers validate first
/// ([`validate_file_policy`]) — this is the storage half only.
pub fn upsert_file_policy(conn: &Connection, row: &FilePolicyRow) -> rusqlite::Result<()> {
    let to_json = |ast: &Option<FilterAst>| -> rusqlite::Result<Option<String>> {
        ast.as_ref()
            .map(|a| {
                serde_json::to_string(a)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
            })
            .transpose()
    };
    conn.execute(
        "INSERT INTO \"_system_file_policy\" \
           (prefix, owner_scoped, public_read, select_policy_json, delete_policy_json) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(prefix) DO UPDATE SET \
           owner_scoped       = excluded.owner_scoped, \
           public_read        = excluded.public_read, \
           select_policy_json = excluded.select_policy_json, \
           delete_policy_json = excluded.delete_policy_json, \
           updated_at         = datetime('now')",
        rusqlite::params![
            row.prefix,
            row.owner_scoped as i64,
            row.public_read as i64,
            to_json(&row.select_policy)?,
            to_json(&row.delete_policy)?,
        ],
    )?;
    Ok(())
}

/// Remove one prefix rule. `Ok(false)` = there was nothing to remove, which the
/// caller reports as [`FILE_POLICY_NOT_FOUND`] rather than a silent success —
/// "I cleared it" and "it was never there" are different facts to an operator
/// tightening access.
pub fn delete_file_policy(conn: &Connection, prefix: &str) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "DELETE FROM \"_system_file_policy\" WHERE prefix = ?1",
        rusqlite::params![prefix],
    )?;
    Ok(n > 0)
}

/// Which side of a rule a decision is being made against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    /// `GET /files/{key}`, `GET …/bytes`, edge `get-file`, and the list arm.
    Read,
    /// `DELETE /files/{key}`. Falls back to the select clause when the rule
    /// carries no delete clause of its own.
    Delete,
}

/// **The one per-file decision.** Every single-file face routes through it —
/// `get_one`, `stream_bytes`, `delete_one`, edge `get-file` — and the list face
/// (T5) compiles the SAME decision into SQL, so the two must be read together:
/// a change here is a change to `build_file_list_filter`.
///
/// `row_map` is `serde_json::to_value(&FileRow)` as an object. It has to be the
/// WHOLE row, system columns included: `eval_policy` reads the map by key and a
/// missing key is not an error there — it reads as Null, so an `updated_at`
/// `is_null` test on a row map lacking the key would be TRUE and open the whole
/// tenant (see [`FileRow`](crate::storage::files::FileRow)'s field docs).
///
/// **Service and the admin plane never reach here** — their callers bypass
/// before loading policies at all. Passing a `Service` ctx is therefore a
/// caller bug; it evaluates as a non-owner (so an owner-scoped prefix denies),
/// which is the fail-closed direction rather than a silent grant.
///
/// Fail-closed is the caller's job too: `load_file_policies` propagates a
/// storage error rather than returning an empty list, and every caller maps
/// that error to a refusal (spec §授權語意).
pub fn authorize_file(
    policies: &[FilePolicyRow],
    row_map: &serde_json::Map<String, serde_json::Value>,
    auth: &crate::auth::middleware::AuthCtx,
    access: FileAccess,
) -> bool {
    let path = row_map.get("path").and_then(|v| v.as_str());
    let Some(p) = longest_match(policies, path) else {
        // Nothing registered for this path — the deny-by-default arm. A tenant
        // reaches it by clearing the seeded root `''`.
        return caller_is_uploader(row_map, auth);
    };

    // (a) The clause-less shape: `owner_scoped=0`, no select clause, no
    // `public_read`. The write face refuses to create it, so this is a legacy
    // or hand-INSERTed row — "restricted but unspecified" must mean DENY on
    // reads AND deletes, never "unrestricted" (mirrors `select_read_access`'s
    // legacy-row deny, CLAUDE.md invariant 12).
    if !p.owner_scoped && p.select_policy.is_none() && !p.public_read {
        return false;
    }

    // (b) The owner clause AND-composes; it is never replaced by the policy.
    if p.owner_scoped && !caller_is_uploader(row_map, auth) {
        return false;
    }

    // (c) A delete with no delete clause inherits the select semantics —
    // "readable ⇒ possibly deletable", with the `Delete` file cap as the other
    // half of the gate.
    let ast = match access {
        FileAccess::Read => p.select_policy.as_ref(),
        FileAccess::Delete => p.delete_policy.as_ref().or(p.select_policy.as_ref()),
    };
    match ast {
        // (d) Reaching here with no clause means `public_read=1` or
        // `owner_scoped=1` already answered the question.
        None => true,
        // Strictly `true`: `eval_policy` collapses Kleene Unknown (an anon
        // `$auth`, a NULL column) to false for us, and that is the direction
        // this must round in.
        Some(ast) => crate::query::policy::eval_policy(
            ast,
            row_map,
            &crate::query::policy::PolicyCtx::from_auth(auth),
        ),
    }
}

/// `uploader == $auth`, with anon and service answering false.
///
/// The stamps drust writes (`service` / `anon` / `function` / `admin`) cannot
/// collide with a real id: every user id is server-minted as `u-<uuid>` and no
/// caller chooses its own (spec G16), so this comparison cannot be spoofed.
fn caller_is_uploader(
    row_map: &serde_json::Map<String, serde_json::Value>,
    auth: &crate::auth::middleware::AuthCtx,
) -> bool {
    match auth.user_id() {
        Some(uid) => row_map.get("uploader").and_then(|v| v.as_str()) == Some(uid),
        None => false,
    }
}

/// Seed the root policy `'' → public_read=1` if the tenant has no root rule.
///
/// This is what makes v1.63 a non-event for an existing tenant: without it the
/// unmatched default is owner-scoped, and every legacy row (uploaded as
/// `"service"`, `path` NULL) would become unreadable to the end users that can
/// read it today. The tenant opts into deny-by-default by clearing this row.
///
/// `INSERT OR IGNORE` alone is NOT idempotent in the sense that matters: it is
/// idempotent per call but RESURRECTS a deliberately cleared root every time it
/// runs, and the boot migration runs on every restart. The marker
/// (`tenants.file_policy_seeded`) is what makes it one-shot — see
/// `db::migrations::seed_file_policy_root`.
pub fn seed_root_policy(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO \"_system_file_policy\" (prefix, owner_scoped, public_read) \
         VALUES ('', 0, 1)",
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(prefix: &str) -> FilePolicyRow {
        FilePolicyRow {
            prefix: prefix.to_string(),
            owner_scoped: true,
            public_read: false,
            select_policy: None,
            delete_policy: None,
        }
    }

    fn ast(v: serde_json::Value) -> FilterAst {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn longest_match_prefers_the_deeper_prefix() {
        let ps = vec![row(""), row("avatars/"), row("avatars/alice/")];
        assert_eq!(
            longest_match(&ps, Some("avatars/alice/x.png"))
                .unwrap()
                .prefix,
            "avatars/alice/",
            "the deeper registration overrides its parent"
        );
        assert_eq!(
            longest_match(&ps, Some("avatars/bob/y.png"))
                .unwrap()
                .prefix,
            "avatars/",
            "a sibling with no rule of its own inherits the parent's"
        );
        assert_eq!(
            longest_match(&ps, Some("docs/readme.md")).unwrap().prefix,
            "",
            "anything else falls to the root"
        );
    }

    #[test]
    fn longest_match_is_a_byte_prefix_not_a_substring() {
        // The trailing '/' in the registered prefix is what stops `avatars/`
        // from claiming `avatarss/`. CJK is the case that broke the SQL side
        // when it was written with substr(): SQLite counts characters there and
        // Rust counts bytes, and the divergence direction is fail-OPEN.
        let ps = vec![row("照片/"), row("照片/alice/")];
        assert_eq!(
            longest_match(&ps, Some("照片/alice/x.png")).unwrap().prefix,
            "照片/alice/"
        );
        assert_eq!(
            longest_match(&ps, Some("照片/bob.png")).unwrap().prefix,
            "照片/"
        );
        assert!(
            longest_match(&ps, Some("照片師/y.png")).is_none(),
            "照片師/ shares the first two characters but is a different folder"
        );

        let ps = vec![row("avatars/")];
        assert!(longest_match(&ps, Some("avatarss/x.png")).is_none());
        assert!(longest_match(&ps, Some("avatar")).is_none());
    }

    #[test]
    fn an_unfiled_row_can_only_match_the_root() {
        let ps = vec![row(""), row("avatars/")];
        assert_eq!(longest_match(&ps, None).unwrap().prefix, "");
        let no_root = vec![row("avatars/")];
        assert!(
            longest_match(&no_root, None).is_none(),
            "with no root registered an unfiled row matches nothing → the \
             owner-scoped default applies"
        );
        assert!(
            longest_match(&[], Some("avatars/x.png")).is_none(),
            "an empty registry never matches"
        );
    }

    #[test]
    fn the_synthetic_schema_exposes_exactly_the_policy_visible_columns() {
        let s = file_policy_schema();
        let names: Vec<&str> = s.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "path",
                "uploader",
                "key",
                "visibility",
                "content_type",
                "original_name",
                "size_bytes",
                "uploaded_at",
            ]
        );
        for excluded in ["content_disposition", "cache_control", "meta_json"] {
            assert!(
                !names.contains(&excluded),
                "{excluded} must stay unreferenceable by a policy"
            );
        }
        assert!(
            s.vector_fields.is_empty() && s.fts_indexes.is_empty(),
            "a file row has neither vectors nor a search index"
        );
    }

    #[test]
    fn the_clause_less_shape_is_refused_and_every_specific_shape_is_not() {
        let mut open = row("open/");
        open.owner_scoped = false;
        assert_eq!(
            validate_file_policy(&open),
            Err(FilePolicyError::OpenRequiresFlag)
        );

        // A delete clause alone still says nothing about reads.
        let mut delete_only = open.clone();
        delete_only.delete_policy = Some(ast(serde_json::json!({"uploader": {"$auth": "id"}})));
        assert_eq!(
            validate_file_policy(&delete_only),
            Err(FilePolicyError::OpenRequiresFlag),
            "a delete clause is not an answer to 'who may read this prefix'"
        );

        let mut flagged = open.clone();
        flagged.public_read = true;
        assert!(validate_file_policy(&flagged).is_ok());

        let mut filtered = open.clone();
        filtered.select_policy = Some(ast(serde_json::json!({"visibility": "private"})));
        assert!(validate_file_policy(&filtered).is_ok());

        assert!(
            validate_file_policy(&open.clone()).is_err()
                && validate_file_policy(&row("a/")).is_ok(),
            "owner_scoped is the third way to be specific"
        );
    }

    #[test]
    fn prefix_grammar_and_operand_classes_are_enforced() {
        for bad in ["avatars", "/a/", "a/../", "a//"] {
            assert_eq!(
                validate_file_policy(&row(bad)).unwrap_err().code(),
                FILE_POLICY_PREFIX_INVALID,
                "{bad:?}"
            );
        }
        assert!(validate_file_policy(&row("")).is_ok(), "'' is the root");

        // #954: size_bytes is INTEGER, $auth is always the TEXT user id.
        let mut cross = row("x/");
        cross.select_policy = Some(ast(
            serde_json::json!({"size_bytes": {"$lt": {"$auth": "id"}}}),
        ));
        assert_eq!(
            validate_file_policy(&cross).unwrap_err().code(),
            FILE_POLICY_OPERAND_UNSUPPORTED
        );

        // A column deliberately kept out of the synthetic schema.
        let mut unknown = row("x/");
        unknown.select_policy = Some(ast(serde_json::json!({"meta_json": "x"})));
        assert_eq!(
            validate_file_policy(&unknown).unwrap_err().code(),
            FILE_POLICY_OPERAND_UNSUPPORTED
        );

        // The delete clause goes through the same check.
        let mut bad_delete = row("x/");
        bad_delete.delete_policy = Some(ast(
            serde_json::json!({"size_bytes": {"$gt": {"$auth": "id"}}}),
        ));
        assert_eq!(
            validate_file_policy(&bad_delete).unwrap_err().code(),
            FILE_POLICY_OPERAND_UNSUPPORTED
        );

        // System columns ARE addressable (the engine admits them
        // unconditionally) and class-check correctly as TEXT.
        let mut sys = row("x/");
        sys.select_policy = Some(ast(
            serde_json::json!({"created_at": {"$gt": "2026-01-01"}}),
        ));
        assert!(validate_file_policy(&sys).is_ok());
    }

    fn memdb() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::db::migrations::SQL_CREATE_SYSTEM_FILE_POLICY_IF_NOT_EXISTS)
            .unwrap();
        conn
    }

    #[test]
    fn upsert_replaces_and_round_trips_through_storage() {
        let conn = memdb();
        let mut r = row("avatars/");
        r.select_policy = Some(ast(serde_json::json!({"uploader": {"$auth": "id"}})));
        upsert_file_policy(&conn, &r).unwrap();
        upsert_file_policy(&conn, &r).unwrap(); // idempotent, not a PK error

        let loaded = load_file_policies(&conn).unwrap();
        assert_eq!(loaded.len(), 1, "a re-register REPLACES, never duplicates");
        assert_eq!(loaded[0].prefix, "avatars/");
        assert!(loaded[0].owner_scoped && !loaded[0].public_read);
        assert!(loaded[0].select_policy.is_some() && loaded[0].delete_policy.is_none());

        // Replacing with a different shape clears the old clause.
        let mut r2 = row("avatars/");
        r2.owner_scoped = false;
        r2.public_read = true;
        upsert_file_policy(&conn, &r2).unwrap();
        let loaded = load_file_policies(&conn).unwrap();
        assert!(!loaded[0].owner_scoped && loaded[0].public_read);
        assert!(
            loaded[0].select_policy.is_none(),
            "the stale select clause must not survive a replace"
        );

        assert!(delete_file_policy(&conn, "avatars/").unwrap());
        assert!(
            !delete_file_policy(&conn, "avatars/").unwrap(),
            "the second clear reports 'nothing there', which the faces map to 404"
        );
    }

    #[test]
    fn a_stored_clause_that_no_longer_parses_fails_closed() {
        let conn = memdb();
        conn.execute(
            "INSERT INTO \"_system_file_policy\" (prefix, select_policy_json) VALUES ('x/', ?1)",
            ["{not json"],
        )
        .unwrap();
        assert!(
            load_file_policies(&conn).is_err(),
            "an unparseable rule must surface as an error the caller turns into \
             a refusal, never as a rule that quietly does nothing"
        );
    }

    // ── authorize_file (T4) ──────────────────────────────────────────────
    //
    // The SQL half of these same decisions is T5's `build_file_list_filter`,
    // and `tests/file_policy_expression.rs` proves the two agree on a shared
    // corpus. What is pinned HERE is the decision itself.

    use crate::auth::middleware::AuthCtx;

    fn user(id: &str) -> AuthCtx {
        AuthCtx::User {
            user_id: id.to_string(),
            token_hash: String::new(),
        }
    }

    /// A file row map in the shape `serde_json::to_value(&FileRow)` produces.
    fn file_row(path: Option<&str>, uploader: &str) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert("id".into(), serde_json::json!(1));
        m.insert("key".into(), serde_json::json!("abc.bin"));
        m.insert("original_name".into(), serde_json::json!("abc.bin"));
        m.insert("content_type".into(), serde_json::json!("text/plain"));
        m.insert("size_bytes".into(), serde_json::json!(5));
        m.insert("content_disposition".into(), serde_json::Value::Null);
        m.insert("visibility".into(), serde_json::json!("private"));
        m.insert("cache_control".into(), serde_json::Value::Null);
        m.insert("meta_json".into(), serde_json::Value::Null);
        m.insert(
            "uploaded_at".into(),
            serde_json::json!("2026-08-11 00:00:00"),
        );
        m.insert("uploader".into(), serde_json::json!(uploader));
        m.insert(
            "path".into(),
            match path {
                Some(p) => serde_json::json!(p),
                None => serde_json::Value::Null,
            },
        );
        m.insert(
            "created_at".into(),
            serde_json::json!("2026-08-11 00:00:00"),
        );
        m.insert(
            "updated_at".into(),
            serde_json::json!("2026-08-11 00:00:00"),
        );
        m
    }

    #[test]
    fn the_unmatched_default_is_owner_scoped_for_everyone_but_the_uploader() {
        let row = file_row(Some("misc/x.bin"), "u-alice");
        for access in [FileAccess::Read, FileAccess::Delete] {
            assert!(authorize_file(&[], &row, &user("u-alice"), access));
            assert!(!authorize_file(&[], &row, &user("u-bob"), access));
            assert!(
                !authorize_file(&[], &row, &AuthCtx::Anon, access),
                "anon has no id, so `uploader == $auth` can never hold"
            );
        }
        // A legacy row stamped `service` (every pre-v1.63 Mode-A upload) is
        // readable by NO end user once the root is cleared — which is exactly
        // why the upgrade seeds `'' → public_read`. The comparison is plain
        // string equality, deliberately, so the SQL arm can be `uploader =
        // ?auth`; what keeps the `service`/`anon`/`function`/`admin` sentinels
        // unclaimable is that every user id is server-minted as `u-<uuid>`
        // (spec G16), never caller-chosen.
        let legacy = file_row(None, "service");
        assert!(!authorize_file(
            &[],
            &legacy,
            &user("u-alice"),
            FileAccess::Read
        ));
        assert!(!authorize_file(
            &[],
            &legacy,
            &AuthCtx::Anon,
            FileAccess::Read
        ));
    }

    #[test]
    fn a_clause_less_row_denies_reads_and_deletes() {
        let mut ps = vec![row("x/")];
        ps[0].owner_scoped = false; // 0 / 0 / NULL / NULL — the API cannot make this
        let row_map = file_row(Some("x/mine.bin"), "u-alice");
        for access in [FileAccess::Read, FileAccess::Delete] {
            assert!(
                !authorize_file(&ps, &row_map, &user("u-alice"), access),
                "'restricted but unspecified' denies even the uploader"
            );
            assert!(!authorize_file(&ps, &row_map, &AuthCtx::Anon, access));
        }
    }

    #[test]
    fn public_read_opens_a_prefix_to_anon_and_the_longest_match_can_close_it_again() {
        let mut open = row("shared/");
        open.owner_scoped = false;
        open.public_read = true;
        let ps = vec![open, row("shared/hr/")]; // hr/ is owner_scoped

        let shared = file_row(Some("shared/note.txt"), "service");
        assert!(authorize_file(
            &ps,
            &shared,
            &AuthCtx::Anon,
            FileAccess::Read
        ));
        assert!(authorize_file(
            &ps,
            &shared,
            &user("u-bob"),
            FileAccess::Read
        ));

        let hr = file_row(Some("shared/hr/pay.csv"), "service");
        assert!(
            !authorize_file(&ps, &hr, &user("u-bob"), FileAccess::Read),
            "the deeper owner-scoped rule overrides its open parent"
        );
    }

    #[test]
    fn an_unfiled_row_is_governed_by_the_root_rule() {
        let mut root = row("");
        root.owner_scoped = false;
        root.public_read = true;
        let ps = vec![root, row("avatars/")];
        let unfiled = file_row(None, "service");
        assert!(
            authorize_file(&ps, &unfiled, &AuthCtx::Anon, FileAccess::Read),
            "path NULL can only match '' — the seeded root is what keeps legacy \
             files readable after the upgrade"
        );
    }

    #[test]
    fn delete_inherits_select_until_a_delete_clause_says_otherwise() {
        let mut open = row("pub/");
        open.owner_scoped = false;
        open.public_read = true;
        let row_map = file_row(Some("pub/x.bin"), "u-alice");
        assert!(authorize_file(
            std::slice::from_ref(&open),
            &row_map,
            &user("u-bob"),
            FileAccess::Delete
        ));

        let mut strict = open.clone();
        strict.delete_policy = Some(ast(serde_json::json!({"uploader": {"$auth": "id"}})));
        let ps = vec![strict];
        assert!(
            authorize_file(&ps, &row_map, &user("u-bob"), FileAccess::Read),
            "the select side is untouched by a delete clause"
        );
        assert!(!authorize_file(
            &ps,
            &row_map,
            &user("u-bob"),
            FileAccess::Delete
        ));
        assert!(authorize_file(
            &ps,
            &row_map,
            &user("u-alice"),
            FileAccess::Delete
        ));
    }

    #[test]
    fn a_select_clause_and_composes_with_the_owner_clause() {
        // owner_scoped AND visibility='private': satisfying one is not enough.
        let mut p = row("both/");
        p.select_policy = Some(ast(serde_json::json!({"visibility": "private"})));
        let ps = vec![p];
        let private = file_row(Some("both/a.bin"), "u-alice");
        let mut public = private.clone();
        public.insert("visibility".into(), serde_json::json!("public"));

        assert!(authorize_file(
            &ps,
            &private,
            &user("u-alice"),
            FileAccess::Read
        ));
        assert!(
            !authorize_file(&ps, &public, &user("u-alice"), FileAccess::Read),
            "the clause still applies to the owner"
        );
        assert!(
            !authorize_file(&ps, &private, &user("u-bob"), FileAccess::Read),
            "the owner clause still applies to a caller the clause would admit"
        );
    }

    #[test]
    fn an_unknown_comparison_is_a_refusal_not_a_pass() {
        // `$auth` is NULL for anon, and NULL comparisons are Unknown on both
        // evaluators — which must round to DENY, not to "no opinion".
        let mut p = row("q/");
        p.owner_scoped = false;
        p.select_policy = Some(ast(serde_json::json!({"uploader": {"$auth": "id"}})));
        let ps = vec![p];
        let row_map = file_row(Some("q/x.bin"), "u-alice");
        assert!(!authorize_file(
            &ps,
            &row_map,
            &AuthCtx::Anon,
            FileAccess::Read
        ));
        assert!(authorize_file(
            &ps,
            &row_map,
            &user("u-alice"),
            FileAccess::Read
        ));

        // A NULL column on the row side is Unknown too.
        let mut null_ct = row_map.clone();
        null_ct.insert("content_type".into(), serde_json::Value::Null);
        let mut p2 = row("q/");
        p2.owner_scoped = false;
        p2.select_policy = Some(ast(serde_json::json!({"content_type": "text/plain"})));
        assert!(!authorize_file(
            std::slice::from_ref(&p2),
            &null_ct,
            &user("u-alice"),
            FileAccess::Read
        ));
    }

    #[test]
    fn a_system_column_clause_reads_the_row_map_not_a_missing_key() {
        // The whole reason `FileRow` carries created_at/updated_at: with the
        // keys present these two answer honestly; with them missing, the
        // `is_null` form would be TRUE and open every file in the tenant.
        let mut p = row("sys/");
        p.owner_scoped = false;
        p.select_policy = Some(ast(serde_json::json!({"updated_at": {"$is_null": true}})));
        let ps = vec![p];
        let row_map = file_row(Some("sys/x.bin"), "u-alice");
        assert!(
            !authorize_file(&ps, &row_map, &user("u-alice"), FileAccess::Read),
            "updated_at is present and non-null, so is_null is FALSE"
        );

        let mut without_key = row_map.clone();
        without_key.remove("updated_at");
        assert!(
            authorize_file(&ps, &without_key, &user("u-alice"), FileAccess::Read),
            "documents the fail-OPEN a missing key produces — which is why the \
             row map is built from the full FileRow and never hand-assembled"
        );
    }

    #[test]
    fn seeding_the_root_is_a_no_op_when_a_root_already_exists() {
        let conn = memdb();
        seed_root_policy(&conn).unwrap();
        let seeded = load_file_policies(&conn).unwrap();
        assert_eq!(seeded.len(), 1);
        assert_eq!(seeded[0].prefix, "");
        assert!(
            !seeded[0].owner_scoped && seeded[0].public_read,
            "the seeded root preserves today's behaviour: a file cap is the only door"
        );

        // An operator tightened the root; seeding again must not loosen it.
        let mut tightened = row("");
        tightened.owner_scoped = true;
        tightened.public_read = false;
        upsert_file_policy(&conn, &tightened).unwrap();
        seed_root_policy(&conn).unwrap();
        let after = load_file_policies(&conn).unwrap();
        assert!(
            after[0].owner_scoped && !after[0].public_read,
            "INSERT OR IGNORE must not overwrite an existing root rule"
        );
    }
}
