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

use crate::query::policy::{CollectionPolicies, Policy, compile_policy_using, validate_policy};
use crate::query::vector_filter::FilterAst;
use crate::storage::file_path::{prefix_upper_bound, validate_file_prefix};
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
/// A registry write whose `public_upload_roles` is not a non-empty subset of
/// [`PUBLIC_UPLOAD_ROLES_ALLOWED`] (v1.64, #974).
pub const FILE_POLICY_INVALID: &str = "FILE_POLICY_INVALID";

/// The only role names a publish grant may name. `service` is deliberately
/// absent: a service caller never consults the registry, so listing it would
/// imply a grant could REVOKE service publishing, which it cannot.
///
/// Order is canonical — [`canonical_public_upload_roles`] emits stored arrays in
/// it, so `["user","anon"]` and `["anon","user","anon"]` persist identically and
/// a byte comparison of the stored JSON is meaningful.
pub const PUBLIC_UPLOAD_ROLES_ALLOWED: [&str; 2] = ["anon", "user"];

/// The grandfather grant a pre-v1.64 tenant's ROOT rule receives once at boot
/// (`db::migrations::seed_public_upload_grant`) — "everyone who could publish
/// yesterday still can". Canonical order, so it round-trips through
/// [`canonical_public_upload_roles`] unchanged.
pub const PUBLIC_UPLOAD_ROLES_ALL_JSON: &str = r#"["anon","user"]"#;

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
    /// v1.64 (#974) — **the publish grant.** Which non-service roles may upload
    /// a file into this prefix with `visibility=public`; `None` = nobody, which
    /// is the deny-by-default arm and the state every un-configured prefix is
    /// in. Values are a subset of [`PUBLIC_UPLOAD_ROLES_ALLOWED`].
    ///
    /// It governs the VISIBILITY dimension only: the `upload` file cap is still
    /// the outer gate on uploading at all, and this column cannot grant a
    /// caller that lacks the cap anything. It is also write-only from the read
    /// path's point of view — neither `authorize_file` nor
    /// `build_file_list_filter` looks at it, because publishing is decided once
    /// at upload (`files::enforce_upload_visibility`) and a `public` object is
    /// then served by Caddy straight out of Garage, never reaching drust again.
    #[serde(default)]
    pub public_upload_roles: Option<Vec<String>>,
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
    PublicUploadRolesInvalid(String),
}

impl FilePolicyError {
    pub fn code(&self) -> &'static str {
        match self {
            FilePolicyError::PrefixInvalid(_) => FILE_POLICY_PREFIX_INVALID,
            FilePolicyError::OpenRequiresFlag => FILE_POLICY_OPEN_REQUIRES_FLAG,
            FilePolicyError::OperandUnsupported(_) => FILE_POLICY_OPERAND_UNSUPPORTED,
            FilePolicyError::NotFound(_) => FILE_POLICY_NOT_FOUND,
            FilePolicyError::PublicUploadRolesInvalid(_) => FILE_POLICY_INVALID,
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
            FilePolicyError::PublicUploadRolesInvalid(why) => why.clone(),
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

/// The stored form of a publish grant: `None`, or a non-empty, de-duplicated
/// subset of [`PUBLIC_UPLOAD_ROLES_ALLOWED`] in canonical order.
///
/// One function for three jobs — the write-face validation, the bytes
/// [`upsert_file_policy`] persists, and the re-check
/// [`load_file_policies`] runs on what it read back — so a grant that the API
/// would refuse can never be honoured just because it reached the table by
/// hand. Refusals:
///
/// * an EMPTY array — `[]` reads as "granted to nobody", which is what `None`
///   already means; accepting both would give the same state two spellings and
///   invite a caller to believe `[]` grants something;
/// * any name outside the allowlist, `"service"` included (see the const's doc).
pub fn canonical_public_upload_roles(
    roles: Option<&[String]>,
) -> Result<Option<Vec<String>>, FilePolicyError> {
    let Some(roles) = roles else { return Ok(None) };
    if roles.is_empty() {
        return Err(FilePolicyError::PublicUploadRolesInvalid(
            "public_upload_roles must name at least one of [\"anon\", \"user\"], \
             or be omitted entirely to grant nobody"
                .to_string(),
        ));
    }
    if let Some(bad) = roles
        .iter()
        .find(|r| !PUBLIC_UPLOAD_ROLES_ALLOWED.contains(&r.as_str()))
    {
        return Err(FilePolicyError::PublicUploadRolesInvalid(format!(
            "public_upload_roles may only contain \"anon\" or \"user\" (got {bad:?})"
        )));
    }
    // Dedup by filtering the allowlist, which canonicalizes the ORDER too.
    Ok(Some(
        PUBLIC_UPLOAD_ROLES_ALLOWED
            .iter()
            .filter(|allowed| roles.iter().any(|r| r == *allowed))
            .map(|allowed| allowed.to_string())
            .collect(),
    ))
}

/// Validate a registry write. Shared by every face (REST now, MCP in T6) so
/// the three refusals are the same three refusals everywhere.
pub fn validate_file_policy(row: &FilePolicyRow) -> Result<(), FilePolicyError> {
    validate_file_prefix(&row.prefix).map_err(FilePolicyError::PrefixInvalid)?;
    canonical_public_upload_roles(row.public_upload_roles.as_deref())?;
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
/// row whose stored JSON no longer parses, a stored prefix that is not a legal
/// prefix — propagates, and every caller maps a propagated error to DENY
/// (spec §授權語意: policy read failure ⇒ refuse).
///
/// Plain `prepare`, not `prepare_cached`: the REST file handlers open a fresh
/// connection per request so a cache would never be hit there, and this table
/// is small enough that the parse is not the cost.
///
/// **This is the only door into either evaluator**, which is why the prefix
/// grammar is re-checked HERE and not at the two decision sites: the table
/// carries no CHECK constraint, [`validate_file_prefix`] runs on the write face
/// only, and the two evaluators read a prefix differently — `authorize_file`
/// with `starts_with`, `build_file_list_filter` through
/// [`prefix_upper_bound`], whose documented contract is an already-validated
/// non-empty prefix ending in `/`. A hand-INSERTed `'avatars'` would be a
/// surprising-but-working rule on one side and a debug-build panic on the
/// other. Refusing the whole read keeps the two in lockstep by making the row
/// unreachable, exactly as an unparseable clause already does — and the error
/// names the offending prefix so the service-only list face's 500 tells an
/// operator which row to `clear_file_policy`.
pub fn load_file_policies(conn: &Connection) -> rusqlite::Result<Vec<FilePolicyRow>> {
    let mut stmt = conn.prepare(
        "SELECT prefix, owner_scoped, public_read, select_policy_json, delete_policy_json, \
                public_upload_roles \
         FROM \"_system_file_policy\" ORDER BY prefix",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(FilePolicyRow {
            prefix: checked_prefix(r.get(0)?)?,
            owner_scoped: r.get::<_, i64>(1)? != 0,
            public_read: r.get::<_, i64>(2)? != 0,
            select_policy: parse_stored_ast(r.get::<_, Option<String>>(3)?, 3)?,
            delete_policy: parse_stored_ast(r.get::<_, Option<String>>(4)?, 4)?,
            public_upload_roles: parse_stored_grant(r.get::<_, Option<String>>(5)?)?,
        })
    })?;
    rows.collect()
}

/// A stored publish grant, re-checked against the write-face rules. Unparseable
/// JSON, a non-array, an empty array or an unknown role name all propagate as a
/// load failure — which every caller turns into a refusal, so a hand-INSERTed
/// `'["admin"]'` cannot publish anything. Same door, same fail-closed answer as
/// [`checked_prefix`] and [`parse_stored_ast`].
fn parse_stored_grant(raw: Option<String>) -> rusqlite::Result<Option<Vec<String>>> {
    let Some(s) = raw else { return Ok(None) };
    let parsed: Vec<String> = serde_json::from_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })?;
    canonical_public_upload_roles(Some(&parsed)).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// A stored prefix, or the fail-closed error. See [`load_file_policies`].
fn checked_prefix(prefix: String) -> rusqlite::Result<String> {
    match validate_file_prefix(&prefix) {
        Ok(()) => Ok(prefix),
        Err(why) => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(FilePolicyError::PrefixInvalid(format!(
                "stored file policy prefix {prefix:?} is not a valid prefix ({why}) — \
                 clear it to restore file access"
            ))),
        )),
    }
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
    // Canonicalized here as well as at the write face: this is the only
    // INSERT, so a grant that reaches storage is a grant the API would accept.
    // `None` is written as SQL NULL, which is how a re-register REVOKES a
    // grant — the same replace-not-merge semantics the two clauses have.
    let grant = canonical_public_upload_roles(row.public_upload_roles.as_deref())
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?
        .map(|roles| {
            serde_json::to_string(&roles)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })
        .transpose()?;
    conn.execute(
        "INSERT INTO \"_system_file_policy\" \
           (prefix, owner_scoped, public_read, select_policy_json, delete_policy_json, \
            public_upload_roles) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(prefix) DO UPDATE SET \
           owner_scoped        = excluded.owner_scoped, \
           public_read         = excluded.public_read, \
           select_policy_json  = excluded.select_policy_json, \
           delete_policy_json  = excluded.delete_policy_json, \
           public_upload_roles = excluded.public_upload_roles, \
           updated_at          = datetime('now')",
        rusqlite::params![
            row.prefix,
            row.owner_scoped as i64,
            row.public_read as i64,
            to_json(&row.select_policy)?,
            to_json(&row.delete_policy)?,
            grant,
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
        Some(ast) => {
            let ctx = crate::query::policy::PolicyCtx::from_auth(auth);
            // (e) The compile gate — the SAME predicate `decision_sql` applies
            // (#973). A clause the compiler refuses denies the prefix over
            // there; `eval_policy` has no field allowlist and answers from the
            // row map BY KEY, so without this the two faces disagreed on a
            // hand-INSERTed clause naming a column outside the synthetic
            // schema: `{"meta_json":{"$is_null":true}}` reads as TRUE in memory
            // (the key is present and NULL) while the list SQL hides the row —
            // a single-file fail-OPEN. Running the compile here and throwing
            // the SQL away costs one pass over a tiny AST and buys lockstep BY
            // CONSTRUCTION rather than by two matching enumerations. It cannot
            // refuse a clause the write face accepted: `validate_policy`
            // compiles every `using` clause before storing it, and compile
            // failures do not depend on the caller (`$auth` resolves to NULL
            // for anon, never an error).
            if compile_file_clause(&p.prefix, ast, &ctx).is_none() {
                return false;
            }
            // Strictly `true`: `eval_policy` collapses Kleene Unknown (an anon
            // `$auth`, a NULL column) to false for us, and that is the
            // direction this must round in.
            crate::query::policy::eval_policy(ast, row_map, &ctx)
        }
    }
}

/// Compile one stored clause against the synthetic file schema, or `None` when
/// the compiler refuses it — the shared refusal both evaluators route through.
///
/// A refusal means "this prefix denies", never "drop the clause and keep the
/// arm": the only rows that can carry an uncompilable clause are legacy or
/// hand-INSERTed ones (the write face compiles every clause before storing it),
/// and honouring half of such a rule is the fail-OPEN direction.
fn compile_file_clause(
    prefix: &str,
    ast: &FilterAst,
    ctx: &crate::query::policy::PolicyCtx,
) -> Option<(String, Vec<rusqlite::types::Value>)> {
    match compile_policy_using(&file_policy_schema(), ast, ctx) {
        Ok(compiled) => Some(compiled),
        Err(e) => {
            tracing::error!(
                prefix = %prefix,
                error = %e,
                "file policy clause would not compile — denying the prefix"
            );
            None
        }
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

/// **The list face of [`authorize_file`].** Returns a `WHERE` fragment plus its
/// binds, in placeholder order, admitting exactly the rows `authorize_file`
/// would admit for `FileAccess::Read`. `tests/file_policy_expression.rs` runs
/// one corpus through both and asserts set equality — a change to either
/// function is a change to both.
///
/// **Service callers never call this**: the `list` handler bypasses before
/// loading policies, as every other RLS surface does for a service key.
///
/// ## Shape
///
/// One arm per registered prefix, OR-ed. Each arm owns exactly the rows whose
/// LONGEST match it is, which is what turns "longest prefix wins" into a flat
/// disjunction:
///
/// ```text
/// (  ((path >= ?p AND path < ?p⁺) AND NOT (…deeper prefix ranges…) AND (decision))
///  OR ((path IS NULL OR NOT (…every prefix range…))                 AND (decision)) )
/// ```
///
/// Three details are load-bearing, each for a measured reason:
///
/// * **Binary range, never `substr` and never `LIKE`.** SQLite's `substr`
///   counts CHARACTERS while Rust's `len()` counts BYTES, so a CJK prefix arm
///   would never fire and the shorter, looser arm would win — a silent
///   fail-OPEN (spec §前綴比對機制). `LIKE` is out because `%` and `_` are
///   ordinary path characters and SQLite's `LIKE` is case-insensitive. The
///   range is byte-exact under the default BINARY collation and can be served
///   by `idx_system_files_path`.
/// * **`path IS NULL OR …` is explicit.** `NOT (NULL >= ?)` is NULL, not TRUE,
///   so without that branch every unfiled row would vanish from the root arm
///   instead of being governed by it.
/// * **Every fragment is parenthesized and the whole disjunction is wrapped**,
///   so the result is safe to `AND` into any caller's `WHERE` and never depends
///   on operator precedence — nor on `compile_policy_using` happening to emit an
///   atomic fragment today. The group is never negated: wrapping it in `NOT`
///   would turn each Unknown into an admission.
pub fn build_file_list_filter(
    policies: &[FilePolicyRow],
    auth: &crate::auth::middleware::AuthCtx,
) -> (String, Vec<rusqlite::types::Value>) {
    let mut binds: Vec<rusqlite::types::Value> = Vec::new();
    let mut arms: Vec<String> = Vec::new();

    // Deepest first: only cosmetic for correctness (the arms are mutually
    // exclusive by construction) but it makes a logged statement readable
    // override-first, the way the rules are reasoned about.
    let mut filed: Vec<&FilePolicyRow> = policies.iter().filter(|p| !p.prefix.is_empty()).collect();
    filed.sort_by(|a, b| {
        b.prefix
            .len()
            .cmp(&a.prefix.len())
            .then_with(|| a.prefix.cmp(&b.prefix))
    });

    for p in &filed {
        let mut parts = vec![prefix_range_sql(&p.prefix, &mut binds)];
        // Subtract every DEEPER registration that lives under this one; those
        // rows belong to that deeper arm. A deeper prefix's range is a subset
        // of this one's, so this is the whole of "longest match wins".
        for deeper in filed.iter().filter(|q| {
            q.prefix.len() > p.prefix.len() && q.prefix.as_bytes().starts_with(p.prefix.as_bytes())
        }) {
            let range = prefix_range_sql(&deeper.prefix, &mut binds);
            parts.push(format!("NOT {range}"));
        }
        parts.push(decision_sql(p, auth, &mut binds));
        arms.push(format!("({})", parts.join(" AND ")));
    }

    // The unmatched set: unfiled rows, plus filed rows under no registration.
    // It is governed by the root rule if one is registered, and by the
    // owner-scoped default if not.
    let unmatched = if filed.is_empty() {
        "1=1".to_string()
    } else {
        let ranges: Vec<String> = filed
            .iter()
            .map(|q| prefix_range_sql(&q.prefix, &mut binds))
            .collect();
        format!("(\"path\" IS NULL OR NOT ({}))", ranges.join(" OR "))
    };
    let decision = match policies.iter().find(|p| p.prefix.is_empty()) {
        Some(root) => decision_sql(root, auth, &mut binds),
        None => owner_sql(auth, &mut binds),
    };
    arms.push(format!("({unmatched} AND {decision})"));

    (format!("({})", arms.join(" OR ")), binds)
}

/// `path` starts with `prefix`, as a half-open byte range. Pushes both bounds.
fn prefix_range_sql(prefix: &str, binds: &mut Vec<rusqlite::types::Value>) -> String {
    binds.push(rusqlite::types::Value::Text(prefix.to_string()));
    binds.push(rusqlite::types::Value::Text(prefix_upper_bound(prefix)));
    "(\"path\" >= ? AND \"path\" < ?)".to_string()
}

/// `uploader = $auth`. Anon and service bind SQL NULL, so the comparison is
/// Unknown and the row is excluded — the same answer `caller_is_uploader`
/// gives them in memory.
fn owner_sql(
    auth: &crate::auth::middleware::AuthCtx,
    binds: &mut Vec<rusqlite::types::Value>,
) -> String {
    binds.push(match auth.user_id() {
        Some(id) => rusqlite::types::Value::Text(id.to_string()),
        None => rusqlite::types::Value::Null,
    });
    "(\"uploader\" = ?)".to_string()
}

/// The per-prefix verdict — steps (a)–(e) of [`authorize_file`] as SQL.
fn decision_sql(
    p: &FilePolicyRow,
    auth: &crate::auth::middleware::AuthCtx,
    binds: &mut Vec<rusqlite::types::Value>,
) -> String {
    // (a) clause-less ⇒ deny, exactly as in memory.
    if !p.owner_scoped && p.select_policy.is_none() && !p.public_read {
        return "(0=1)".to_string();
    }
    // Compile BEFORE pushing anything: a mid-arm bail-out after a push would
    // desynchronize binds from placeholders for the whole statement. A stored
    // clause the compiler refuses (a hand-INSERTed row naming a column outside
    // the synthetic schema) denies the prefix — dropping the clause and keeping
    // the arm would publish it, and `authorize_file` step (e) refuses the same
    // clause through the same helper.
    let compiled = match &p.select_policy {
        None => None,
        Some(ast) => {
            let ctx = crate::query::policy::PolicyCtx::from_auth(auth);
            match compile_file_clause(&p.prefix, ast, &ctx) {
                Some(c) => Some(c),
                None => return "(0=1)".to_string(),
            }
        }
    };
    let mut parts: Vec<String> = Vec::new();
    // (b) the owner clause AND-composes; it never replaces the policy.
    if p.owner_scoped {
        parts.push(owner_sql(auth, binds));
    }
    if let Some((frag, mut clause_binds)) = compiled {
        parts.push(format!("({frag})"));
        binds.append(&mut clause_binds);
    }
    // (d) reaching here with neither means `public_read=1` answered it.
    if parts.is_empty() {
        return "(1=1)".to_string();
    }
    format!("({})", parts.join(" AND "))
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

/// v1.64 (#974) — grandfather the ROOT rule's publish grant to
/// `["anon","user"]`. `Ok(false)` = there was no root row to grant on.
///
/// The storage half of `db::migrations::seed_public_upload_grant`, whose doc
/// carries the reasoning. Two clauses do the load-bearing work:
///
/// * **`WHERE prefix = ''` with no INSERT.** A tenant with no root rule cleared
///   it deliberately, and inserting one here would have to invent its READ
///   half: a clause-less row denies every read on both evaluators, so
///   "granting publish" would break reading. Skipping is the respectful and the
///   fail-closed answer at once.
/// * **`AND public_upload_roles IS NULL`.** The marker already makes this
///   run-once; this makes it non-destructive even if it somehow ran twice.
///   Never widens an existing grant, never narrows one.
pub fn grant_root_public_upload(conn: &Connection) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE \"_system_file_policy\" \
            SET public_upload_roles = ?1, updated_at = datetime('now') \
          WHERE prefix = '' AND public_upload_roles IS NULL",
        [PUBLIC_UPLOAD_ROLES_ALL_JSON],
    )?;
    Ok(n > 0)
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
            public_upload_roles: None,
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

    #[test]
    fn a_stored_prefix_that_breaks_the_grammar_fails_closed() {
        // The table has no CHECK constraint and `validate_file_prefix` runs on
        // the write face only, so this row is reachable by hand-INSERT — the
        // same door the clause-less row comes through. It must not reach either
        // evaluator: `authorize_file` would honour it as a loose `starts_with`
        // rule (`avatars` claiming `avatarss/x.png`), while
        // `build_file_list_filter` would hand it to `prefix_upper_bound`, whose
        // contract says validated-and-slash-terminated and whose debug_assert
        // would abort the request. Refusing the read keeps the two in lockstep.
        for bad in ["avatars", "/a/", "a//", " "] {
            let conn = memdb();
            conn.execute(
                "INSERT INTO \"_system_file_policy\" (prefix, public_read) VALUES (?1, 1)",
                [bad],
            )
            .unwrap();
            let err = load_file_policies(&conn).unwrap_err();
            assert!(
                err.to_string().contains(bad),
                "the refusal must name the row to clear, or an operator cannot \
                 recover through the service face: {err}"
            );
        }

        // …and the two legal shapes still load.
        let conn = memdb();
        seed_root_policy(&conn).unwrap();
        upsert_file_policy(&conn, &row("avatars/")).unwrap();
        let loaded = load_file_policies(&conn).unwrap();
        assert_eq!(
            loaded.len(),
            2,
            "'' and a slash-terminated prefix are legal"
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
    fn a_delete_with_no_delete_clause_inherits_a_denying_select_clause() {
        // The test above proves inheritance through a clause-LESS open prefix,
        // where `.or(select)` is a no-op (both sides are None) — deleting the
        // fallback would not change its answer. THIS is the direction that
        // matters: a select clause that HIDES the row must also refuse the
        // delete, or a caller holding the `delete` file cap can destroy a file
        // it cannot read. The shape is API-creatable — `select` is Some, so
        // `FILE_POLICY_OPEN_REQUIRES_FLAG` does not fire.
        let mut p = row("docs/");
        p.owner_scoped = false;
        p.select_policy = Some(ast(serde_json::json!({"uploader": {"$auth": "id"}})));
        assert!(
            validate_file_policy(&p).is_ok(),
            "the registry accepts this shape, so the read path must handle it"
        );
        let ps = vec![p];
        let row_map = file_row(Some("docs/a.bin"), "u-alice");

        assert!(!authorize_file(
            &ps,
            &row_map,
            &user("u-bob"),
            FileAccess::Read
        ));
        assert!(
            !authorize_file(&ps, &row_map, &user("u-bob"), FileAccess::Delete),
            "with no delete clause the SELECT clause governs the delete too — \
             unreadable ⇒ undeletable"
        );
        assert!(
            !authorize_file(&ps, &row_map, &AuthCtx::Anon, FileAccess::Delete),
            "and anon, whose $auth is NULL, is Unknown ⇒ denied"
        );
        assert!(
            authorize_file(&ps, &row_map, &user("u-alice"), FileAccess::Delete),
            "the caller the select clause admits still deletes"
        );
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
    fn a_clause_the_compiler_refuses_denies_the_single_file_face_too() {
        // #973. The list face collapses such an arm to `0=1`
        // (`an_uncompilable_clause_denies_its_prefix` in
        // tests/file_policy_expression.rs); this is the other evaluator. Both
        // clauses below name a column deliberately kept OUT of the synthetic
        // schema, so neither can reach the table through the write face — but
        // both used to ADMIT here, because `eval_policy` has no field
        // allowlist and answers from the row map by key:
        //   * `meta_json` is present-and-NULL on every row map ⇒ `$is_null`
        //     was TRUE,
        //   * an entirely unknown key is missing ⇒ reads as Null ⇒ TRUE.
        // Either one was a single-file read the list face hid — a fail-OPEN.
        for clause in [
            serde_json::json!({"meta_json": {"$is_null": true}}),
            serde_json::json!({"no_such_column": {"$is_null": true}}),
            serde_json::json!({"content_disposition": {"$is_null": true}}),
        ] {
            let mut p = row("x/");
            p.owner_scoped = false;
            p.select_policy = Some(ast(clause.clone()));
            assert!(
                validate_file_policy(&p).is_err(),
                "{clause} must be unreachable through the write face, or this \
                 test is pinning a shape operators can legitimately create"
            );
            let ps = vec![p];
            let row_map = file_row(Some("x/secret.bin"), "u-alice");
            for access in [FileAccess::Read, FileAccess::Delete] {
                assert!(
                    !authorize_file(&ps, &row_map, &user("u-alice"), access),
                    "{clause} must deny — the uploader included, exactly as the \
                     compiled arm's `0=1` denies every row under the prefix"
                );
                assert!(!authorize_file(&ps, &row_map, &AuthCtx::Anon, access));
            }
        }

        // The delete side inherits the select clause when it has none of its
        // own, so the refusal must travel with it rather than being skipped.
        let mut p = row("x/");
        p.owner_scoped = false;
        p.public_read = true;
        p.delete_policy = Some(ast(serde_json::json!({"meta_json": "x"})));
        let ps = vec![p];
        let row_map = file_row(Some("x/secret.bin"), "u-alice");
        assert!(
            authorize_file(&ps, &row_map, &user("u-alice"), FileAccess::Read),
            "the read side is governed by public_read and is untouched"
        );
        assert!(
            !authorize_file(&ps, &row_map, &user("u-alice"), FileAccess::Delete),
            "an uncompilable DELETE clause denies the delete"
        );
    }

    // ── the publish grant (#974) ─────────────────────────────────────────
    //
    // The DECISION lives in `files::enforce_upload_visibility`; what is pinned
    // here is the column's write face: what may be stored, what round-trips,
    // and what a hand-INSERTed value does.

    #[test]
    fn a_publish_grant_is_validated_deduped_and_canonically_ordered() {
        let mut r = row("up/");
        for bad in [
            vec![],
            vec!["service".to_string()],
            vec!["admin".to_string()],
            vec!["User".to_string()],
            vec!["user".to_string(), "root".to_string()],
        ] {
            r.public_upload_roles = Some(bad.clone());
            assert_eq!(
                validate_file_policy(&r).unwrap_err().code(),
                FILE_POLICY_INVALID,
                "{bad:?} must be refused — an empty array is not a grant to \
                 nobody, it is a spelling of `None` that invites confusion, and \
                 `service` never consults the registry at all"
            );
        }

        r.public_upload_roles = None;
        assert!(
            validate_file_policy(&r).is_ok(),
            "omission is the deny state"
        );
        for good in [vec!["anon"], vec!["user"], vec!["anon", "user"]] {
            r.public_upload_roles = Some(good.iter().map(|s| s.to_string()).collect());
            assert!(validate_file_policy(&r).is_ok(), "{good:?}");
        }

        // Dedup + canonical order, so two spellings of one grant persist
        // identically and the seeded constant round-trips unchanged.
        let messy: Vec<String> = ["user", "anon", "user"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            canonical_public_upload_roles(Some(&messy)).unwrap(),
            Some(vec!["anon".to_string(), "user".to_string()])
        );
        let seeded: Vec<String> = serde_json::from_str(PUBLIC_UPLOAD_ROLES_ALL_JSON).unwrap();
        assert_eq!(
            serde_json::to_string(
                &canonical_public_upload_roles(Some(&seeded))
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            PUBLIC_UPLOAD_ROLES_ALL_JSON,
            "the boot grant must be its own canonical form, or every seeded \
             tenant's row differs byte-wise from an API-written one"
        );
    }

    #[test]
    fn the_grant_column_round_trips_and_a_re_register_revokes_it() {
        let conn = memdb();
        let mut r = row("up/");
        r.public_upload_roles = Some(vec!["user".to_string(), "anon".to_string()]);
        upsert_file_policy(&conn, &r).unwrap();
        assert_eq!(
            load_file_policies(&conn).unwrap()[0].public_upload_roles,
            Some(vec!["anon".to_string(), "user".to_string()]),
            "stored canonically, not as the caller happened to order it"
        );

        // Replace WITHOUT the field: the grant is revoked, exactly as a stale
        // select clause is dropped. Registry writes replace, never merge.
        upsert_file_policy(&conn, &row("up/")).unwrap();
        assert_eq!(
            load_file_policies(&conn).unwrap()[0].public_upload_roles,
            None,
            "a re-register that omits the grant must REVOKE it — a merge would \
             make a grant impossible to remove through the write face"
        );

        // Storage refuses a grant the API would refuse, so the only INSERT
        // cannot become the door a bad value walks through.
        let mut bad = row("up/");
        bad.public_upload_roles = Some(vec!["service".to_string()]);
        assert!(upsert_file_policy(&conn, &bad).is_err());
    }

    #[test]
    fn a_hand_inserted_grant_that_the_api_would_refuse_fails_closed() {
        for bad in [
            "[\"admin\"]",
            "[]",
            "{\"user\":true}",
            "not json",
            "\"user\"",
        ] {
            let conn = memdb();
            conn.execute(
                "INSERT INTO \"_system_file_policy\" (prefix, public_read, public_upload_roles) \
                 VALUES ('', 1, ?1)",
                [bad],
            )
            .unwrap();
            assert!(
                load_file_policies(&conn).is_err(),
                "{bad} must break the LOAD — every caller maps that to a \
                 refusal, so a grant nobody could have written cannot publish"
            );
        }
    }

    #[test]
    fn the_grandfather_grant_lands_on_the_root_only_and_never_inserts_one() {
        let conn = memdb();
        // No root row: the tenant cleared it deliberately. Inserting one here
        // would have to invent its read half, and a clause-less row DENIES
        // every read — "granting publish" would break reading.
        assert!(!grant_root_public_upload(&conn).unwrap());
        assert!(load_file_policies(&conn).unwrap().is_empty());

        seed_root_policy(&conn).unwrap();
        upsert_file_policy(&conn, &row("deep/")).unwrap();
        assert!(grant_root_public_upload(&conn).unwrap());
        let loaded = load_file_policies(&conn).unwrap();
        assert_eq!(
            loaded[0].public_upload_roles,
            Some(vec!["anon".to_string(), "user".to_string()]),
            "the root reproduces the pre-v1.64 rule: anyone with the upload cap \
             could publish"
        );
        assert_eq!(
            loaded[1].public_upload_roles, None,
            "a deeper prefix is NOT grandfathered — only the root is"
        );
        assert!(
            !loaded[0].owner_scoped && loaded[0].public_read,
            "the read half of the root rule is untouched by the grant"
        );

        // A second run cannot widen or overwrite an existing grant (the marker
        // already makes it run-once; this makes it harmless if it were not).
        let mut narrowed = row("");
        narrowed.owner_scoped = false;
        narrowed.public_read = true;
        narrowed.public_upload_roles = Some(vec!["user".to_string()]);
        upsert_file_policy(&conn, &narrowed).unwrap();
        assert!(!grant_root_public_upload(&conn).unwrap());
        assert_eq!(
            load_file_policies(&conn).unwrap()[0].public_upload_roles,
            Some(vec!["user".to_string()])
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
