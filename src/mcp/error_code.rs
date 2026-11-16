//! The one classifier behind MCP's JSON-RPC `data.error_code`.
//!
//! Tool code is asked to fail with `"<CODE>: <message>"` (see `bail_mcp` in
//! `handler.rs`), and new code should keep doing so. This module is the
//! backstop for everything that does not: shared tool modules whose messages
//! REST and edge also show (a prefix there would change their bytes), native
//! SQLite errors that have no drust origin to edit, and the handler-level
//! errors that never went through `bail_mcp` at all.
//!
//! Every step but the first returns a constant from the tables below, so caller
//! text (a JSON key, a collection name, SQL) can steer WHICH drust code those
//! steps choose but can never BECOME it. The first step, the leading-code step,
//! hands back message bytes: it fires only when the message STARTS with an
//! `UPPER_SNAKE` token followed by `:` or the end. That is drust's own prefix
//! as long as no message starts with caller text. The tool-module literals are
//! pinned (`bail_mcp_tests::every_unprefixed_tool_literal_has_a_code`); a
//! message forwarded verbatim from another type's `Display` or from
//! `e.to_string()` in `handler.rs` is not, and none found starts with caller
//! text today. The surface is service-only either way.

use rmcp::model::ErrorCode;
use std::borrow::Cow;

/// Sentinels drust itself writes directly after `PrepareError`'s Display prefix
/// (`crate::rpc::prepare::PREPARE_REJECTED_PREFIX`). Step 2 of
/// [`mcp_error_code`] returns one of these — the array's constant, never the
/// message slice — and only when the remainder of the message starts with it.
pub(crate) const EMBEDDED_SENTINELS: &[&str] = &[
    crate::rpc::prepare::RPC_ANON_OWNER_SCOPED,
    crate::rpc::prepare::RPC_KIND_INVALID,
    crate::rpc::prepare::RPC_QUERY_GRANT_ACTIVE,
    "COLLECTION_NOT_FOUND",
    "PROTECTED_COLLECTION",
    "FIELD_NOT_FOUND",
    "INDEX_NOT_FOUND",
];

/// How a needle row matches a message.
enum Match {
    /// The message starts with this fixed fragment. Used wherever the fixed
    /// text opens the message and the variable tail is caller or SQLite text,
    /// so the tail can never select the row.
    Prefix(&'static str),
    /// The message starts with the fixed fragment AND contains every other
    /// fragment. Used where a fixed opener (SQLite's object kind, a drust
    /// sentence start) is followed by a name and then more fixed text, so a
    /// name that happens to contain another row's fragment cannot pick that
    /// row.
    PrefixAll(&'static str, &'static [&'static str]),
    /// The message contains every fragment. Used only where the fixed text sits
    /// mid-message (after a field name, or inside a native SQLite sentence).
    All(&'static [&'static str]),
}

impl Match {
    fn matches(&self, msg: &str) -> bool {
        match self {
            Match::Prefix(p) => msg.starts_with(p),
            Match::PrefixAll(p, frags) => {
                msg.starts_with(p) && frags.iter().all(|f| msg[p.len()..].contains(f))
            }
            Match::All(frags) => frags.iter().all(|f| msg.contains(f)),
        }
    }
}

/// Ordered, first match wins. Specific rows precede generic ones: the
/// `unknown collection or field` row before `unknown collection`, the
/// `query error:` row before the native `no such table` row, and so on.
const NEEDLES: &[(Match, &str)] = &[
    // `query` tool (src/mcp/tools/read.rs).
    (
        Match::Prefix("access to SQLite metadata tables is denied"),
        "QUERY_FORBIDDEN",
    ),
    (Match::Prefix("`query` is read-only"), "QUERY_FORBIDDEN"),
    (Match::Prefix("query too large"), "QUERY_TOO_LARGE"),
    (Match::Prefix("query timed out"), "QUERY_TIMEOUT"),
    (Match::Prefix("query error:"), "SQL_ERROR"),
    // Unknown names. `unknown field '` is the insert/update/upsert unknown-key
    // refusal (write.rs) — REST answers FIELD_NOT_FOUND for the same thing.
    (
        Match::Prefix("unknown collection or field"),
        "FIELD_NOT_FOUND",
    ),
    (Match::Prefix("unknown field '"), "FIELD_NOT_FOUND"),
    (Match::Prefix("unknown collection"), "COLLECTION_NOT_FOUND"),
    (Match::Prefix("no such collection"), "COLLECTION_NOT_FOUND"),
    (Match::Prefix("no such index"), "INDEX_NOT_FOUND"),
    (Match::Prefix("rpc not found"), "RPC_NOT_FOUND"),
    (Match::Prefix("no such rpc"), "RPC_NOT_FOUND"),
    (Match::Prefix("rpc already exists"), "RPC_EXISTS"),
    (Match::Prefix("invalid params_json"), "PARAM_BAD_STORED"),
    // Record-write body shape: REST's code for the same condition.
    (Match::Prefix("data must be object"), "TYPE_MISMATCH"),
    (
        Match::Prefix("data must have at least one field"),
        "TYPE_MISMATCH",
    ),
    (
        Match::Prefix("meta connection not available in this context"),
        "META_UNAVAILABLE",
    ),
    // A policy filter that does not parse (policy.rs, file_policy.rs). The
    // tail is serde's message, which can echo caller text — so the row is
    // anchored on drust's opener and sits before every `All` row, where that
    // echo could otherwise select a field-spec or name row.
    (
        Match::PrefixAll("invalid `", &["` filter: "]),
        "FILTER_PARSE_ERROR",
    ),
    // SQLite's ALTER TABLE ADD COLUMN / CREATE TABLE with a name already
    // used: a caller mistake, not a server fault.
    (Match::Prefix("duplicate column name"), "INVALID_PARAMS"),
    (Match::All(&["not found on collection"]), "FIELD_NOT_FOUND"),
    (
        Match::All(&["foreign_key references unknown collection"]),
        "COLLECTION_NOT_FOUND",
    ),
    (
        Match::All(&["protected by _system_ prefix"]),
        "PROTECTED_COLLECTION",
    ),
    (
        Match::All(&["cannot drop system column"]),
        "SYSTEM_FIELD_READONLY",
    ),
    (Match::All(&["foreign-key references from"]), "FK_RESTRICT"),
    (Match::All(&["invalid identifier"]), "INVALID_IDENTIFIER"),
    // Field-spec validation (schema.rs).
    (Match::All(&["> max"]), "INVALID_PARAMS"),
    (Match::All(&["max_length must be >= 1"]), "INVALID_PARAMS"),
    (Match::All(&["enum has"]), "INVALID_PARAMS"),
    (Match::All(&["enum value"]), "INVALID_PARAMS"),
    (
        Match::All(&["enum_values must be non-empty"]),
        "INVALID_PARAMS",
    ),
    (Match::All(&["not numeric for"]), "INVALID_PARAMS"),
    (Match::All(&["requires `dim`"]), "INVALID_PARAMS"),
    (Match::All(&["must be 1..=4096"]), "INVALID_PARAMS"),
    (
        Match::All(&["default.sql must be a string"]),
        "INVALID_PARAMS",
    ),
    (
        Match::All(&["SQL default expression not in allowlist"]),
        "INVALID_PARAMS",
    ),
    (Match::All(&["default must be a literal"]), "INVALID_PARAMS"),
    (Match::All(&["unsupported sql_type"]), "INVALID_PARAMS"),
    // Index spec (index.rs) and signed-URL lifetime (files.rs).
    (Match::All(&["fields must be non-empty"]), "INVALID_PARAMS"),
    (
        Match::All(&["duplicate field in index spec"]),
        "INVALID_PARAMS",
    ),
    (Match::All(&["expires_in must be"]), "INVALID_PARAMS"),
    // Policies (policy.rs, file_policy.rs).
    (
        Match::All(&["must be select|insert|update|delete"]),
        "POLICY_INVALID",
    ),
    (
        Match::All(&["not found in meta.sqlite"]),
        "TENANT_NOT_FOUND",
    ),
    // A PrepareError with no step-2 sentinel. After step 2 on purpose: it
    // would otherwise swallow every sentinel.
    (
        Match::Prefix("rpc sql failed prepare-time validation"),
        "INVALID_SQL_FOR_MODE",
    ),
    // Native SQLite errors, propagated verbatim. The names are the ones the
    // cross-face constraint classifier reserves (rest-errors-audit d1), so REST
    // can adopt them later without MCP changing again.
    (
        Match::All(&["UNIQUE constraint failed"]),
        "UNIQUE_VIOLATION",
    ),
    (
        Match::All(&["NOT NULL constraint failed"]),
        "NOT_NULL_VIOLATION",
    ),
    (
        Match::All(&["FOREIGN KEY constraint failed"]),
        "FK_VIOLATION",
    ),
    (
        Match::All(&["CHECK constraint failed"]),
        "CHECK_CONSTRAINT_FAILED",
    ),
    (Match::All(&["cannot store", "value in"]), "TYPE_MISMATCH"),
    // SQLite opens these with the object kind (`table "x" already exists`,
    // `index x already exists`). Anchored on that kind, so a collection named
    // `index_log` is not an index. Not a bare `Prefix("index ")`: SQLite's
    // `index associated with UNIQUE or PRIMARY KEY constraint cannot be
    // dropped` also opens that way.
    (
        Match::PrefixAll("index ", &["already exists"]),
        "INDEX_EXISTS",
    ),
    (
        Match::PrefixAll("table ", &["already exists"]),
        "COLLECTION_EXISTS",
    ),
    // `VectorCodecError` forwarded by `{e}` (search_vector, tools/vector.rs).
    // The field name is a stored schema identifier, and the codes are the ones
    // REST and MCP's write path give the same failures.
    (
        Match::PrefixAll("vector field ", &["-element array, got "]),
        "VECTOR_DIM_MISMATCH",
    ),
    (
        Match::PrefixAll("vector field ", &["is not a finite number"]),
        "VECTOR_NON_FINITE",
    ),
    (
        Match::PrefixAll("vector field ", &[": element at index ", "is not numeric"]),
        "VECTOR_TYPE_ERROR",
    ),
    (
        Match::PrefixAll("vector field ", &[": input is not a JSON array"]),
        "VECTOR_TYPE_ERROR",
    ),
    (Match::All(&["no such table"]), "COLLECTION_NOT_FOUND"),
    (Match::All(&["no such column"]), "FIELD_NOT_FOUND"),
];

/// A message's leading `UPPER_SNAKE` token (everything before the first `:`,
/// trimmed), if it is one. `DB` is aliased to `DB_ERROR` — the 18
/// `"DB: {e}"` sites in `src/mcp/tools` predate the convention, and
/// `DB_ERROR` is the code REST uses for the same failure.
fn leading_code(msg: &str) -> Option<Cow<'_, str>> {
    let head = msg.split(':').next().unwrap_or("").trim();
    let mut chars = head.chars();
    let first = chars.next()?;
    if !first.is_ascii_uppercase() {
        return None;
    }
    if !chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
        return None;
    }
    if head == "DB" {
        return Some(Cow::Borrowed("DB_ERROR"));
    }
    Some(Cow::Borrowed(head))
}

/// The sentinel directly after `PrepareError`'s Display prefix, if it is one
/// of [`EMBEDDED_SENTINELS`]. Anchored at the START of the message, so a
/// prefix-shaped string inside caller text (a collection name, a JSON key) is
/// never consulted.
pub(crate) fn embedded_sentinel(msg: &str) -> Option<&'static str> {
    let rest = msg.strip_prefix(crate::rpc::prepare::PREPARE_REJECTED_PREFIX)?;
    let token = rest.split(':').next().unwrap_or("").trim();
    EMBEDDED_SENTINELS.iter().copied().find(|s| *s == token)
}

/// The `data.error_code` for an MCP tool error with this message and JSON-RPC
/// class. In order: a leading `CODE:`; else a closed-set sentinel directly
/// after `PrepareError`'s prefix; else the first matching needle row; else
/// `INVALID_PARAMS` for a `-32602` and `INTERNAL` for anything else.
pub(crate) fn mcp_error_code(msg: &str, rpc: ErrorCode) -> Cow<'_, str> {
    if let Some(c) = leading_code(msg) {
        return c;
    }
    if let Some(s) = embedded_sentinel(msg) {
        return Cow::Borrowed(s);
    }
    for (m, code) in NEEDLES {
        if m.matches(msg) {
            return Cow::Borrowed(code);
        }
    }
    if rpc == ErrorCode::INVALID_PARAMS {
        Cow::Borrowed("INVALID_PARAMS")
    } else {
        Cow::Borrowed("INTERNAL")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PFX: &str = "rpc sql failed prepare-time validation: ";

    fn code(msg: &str) -> String {
        let c = mcp_error_code(msg, ErrorCode::INTERNAL_ERROR).into_owned();
        assert!(is_upper_snake(&c), "{msg:?} classified as non-code {c:?}");
        c
    }

    fn is_upper_snake(s: &str) -> bool {
        let mut it = s.chars();
        matches!(it.next(), Some(c) if c.is_ascii_uppercase())
            && it.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    #[test]
    fn leading_code_wins_and_db_aliases() {
        assert_eq!(code("MADE_UP: x"), "MADE_UP");
        assert_eq!(code("LARGE_TABLE"), "LARGE_TABLE");
        assert_eq!(code("DB: disk I/O error"), "DB_ERROR");
        assert_eq!(code("just a free-form message"), "INTERNAL");
        // A drust prefix wins over a native error it wraps.
        assert_eq!(
            code("CHECK_CONSTRAINT_FAILED: UNIQUE constraint failed: t.x"),
            "CHECK_CONSTRAINT_FAILED"
        );
    }

    #[test]
    fn prose_before_first_colon_is_never_a_code() {
        let write_refusal = "`query` is read-only — use `insert_record` / `update_record` / \
                             `delete_record` for row writes, or `create_collection` / \
                             `drop_collection` / `add_field` / `drop_field` for schema changes \
                             (underlying: not authorized)";
        assert_eq!(code(write_refusal), "QUERY_FORBIDDEN");
        let meta = "access to SQLite metadata tables is denied — use `list_collections` or \
                    `describe_collection` to inspect schema (underlying: sqlite_master)";
        assert_eq!(code(meta), "QUERY_FORBIDDEN");
        assert_eq!(
            code("query too large: 9 bytes (limit 1)"),
            "QUERY_TOO_LARGE"
        );
        assert_eq!(code("query timed out after 5ms"), "QUERY_TIMEOUT");
        assert_eq!(code("unknown collection: 'notes'"), "COLLECTION_NOT_FOUND");
        assert_eq!(
            code("unknown collection or field: notes.x"),
            "FIELD_NOT_FOUND"
        );
        assert_eq!(code("no such rpc: nope"), "RPC_NOT_FOUND");
        assert_eq!(code("rpc not found: 'nope'"), "RPC_NOT_FOUND");
        assert_eq!(code("rpc already exists: 'r'"), "RPC_EXISTS");
        assert_eq!(
            code("meta connection not available in this context"),
            "META_UNAVAILABLE"
        );
    }

    #[test]
    fn embedded_sentinel_is_anchored_and_closed() {
        assert_eq!(
            code(&format!("{PFX}RPC_ANON_OWNER_SCOPED: x")),
            "RPC_ANON_OWNER_SCOPED"
        );
        assert_eq!(
            code(&format!("{PFX}COLLECTION_NOT_FOUND: no such collection: t")),
            "COLLECTION_NOT_FOUND"
        );
        assert_eq!(
            code(&format!("{PFX}RPC_QUERY_GRANT_ACTIVE: x")),
            "RPC_QUERY_GRANT_ACTIVE"
        );
        // Not in the closed set → the generic prepare row, never the token.
        assert_eq!(code(&format!("{PFX}NOT_IN_SET: x")), "INVALID_SQL_FOR_MODE");
        assert_eq!(
            code(&format!("{PFX}not authorized")),
            "INVALID_SQL_FOR_MODE"
        );
        assert_eq!(embedded_sentinel(&format!("{PFX}NOT_IN_SET: x")), None);
        // Not anchored at the start → not consulted.
        assert_eq!(
            embedded_sentinel(&format!("wrapped: {PFX}RPC_KIND_INVALID: x")),
            None
        );
    }

    /// Review item M1: caller text in a key or collection name never becomes
    /// the code, whatever shape it takes.
    #[test]
    fn caller_text_never_becomes_the_code() {
        assert_eq!(
            code("unknown field 'A_B: x' for collection 'c' (allowed: a)"),
            "FIELD_NOT_FOUND"
        );
        assert_eq!(
            code("unknown field 'RPC_KIND_INVALID: x' for collection 'c' (allowed: a)"),
            "FIELD_NOT_FOUND"
        );
        assert_eq!(code("unknown collection: 'A_B: x'"), "COLLECTION_NOT_FOUND");
        assert_eq!(
            code("query error: no such table: UNIQUE constraint failed"),
            "SQL_ERROR"
        );
        assert_eq!(
            code(&format!("unknown collection: '{PFX}RPC_KIND_INVALID: x'")),
            "COLLECTION_NOT_FOUND"
        );
    }

    /// Review item M2: the unknown-key refusal of insert/update/upsert matches
    /// REST's FIELD_NOT_FOUND.
    #[test]
    fn unknown_field_matches_rest() {
        let lit = format!(
            "unknown field '{}' for collection '{}' (allowed: {})",
            "titel", "notes", "title, body"
        );
        assert_eq!(code(&lit), "FIELD_NOT_FOUND");
    }

    /// Review item M3: REST's code for a `data` that is not a non-empty object.
    #[test]
    fn data_shape_errors_are_type_mismatch() {
        assert_eq!(code("data must be object"), "TYPE_MISMATCH");
        assert_eq!(code("data must have at least one field"), "TYPE_MISMATCH");
    }

    /// Real SQLite messages, stringified the way they reach `bail_mcp`.
    #[test]
    fn native_sqlite_texts() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE p(id INTEGER PRIMARY KEY) STRICT;
             CREATE TABLE t(id INTEGER PRIMARY KEY, u TEXT UNIQUE, n TEXT NOT NULL,
                            k INTEGER REFERENCES p(id), v INTEGER CHECK (v > 0)) STRICT;
             CREATE INDEX t_n ON t(n);
             INSERT INTO t(u, n) VALUES ('a', 'x');",
        )
        .unwrap();
        let err = |sql: &str| c.execute_batch(sql).unwrap_err().to_string();
        assert_eq!(
            code(&err("INSERT INTO t(u, n) VALUES ('a', 'y')")),
            "UNIQUE_VIOLATION"
        );
        assert_eq!(
            code(&err("INSERT INTO t(u) VALUES ('b')")),
            "NOT_NULL_VIOLATION"
        );
        assert_eq!(
            code(&err("INSERT INTO t(n, k) VALUES ('y', 42)")),
            "FK_VIOLATION"
        );
        assert_eq!(
            code(&err("INSERT INTO t(n, v) VALUES ('y', -1)")),
            "CHECK_CONSTRAINT_FAILED"
        );
        assert_eq!(
            code(&err("INSERT INTO t(n, v) VALUES ('y', 'abc')")),
            "TYPE_MISMATCH"
        );
        assert_eq!(
            code(&err("CREATE TABLE p(id INTEGER PRIMARY KEY)")),
            "COLLECTION_EXISTS"
        );
        assert_eq!(code(&err("CREATE INDEX t_n ON t(n)")), "INDEX_EXISTS");
        // A collection whose NAME contains "index" is still a collection:
        // create_collection has no existence pre-check, so this is the text it
        // forwards for a repeat.
        c.execute_batch("CREATE TABLE \"index_log\"(id INTEGER PRIMARY KEY) STRICT")
            .unwrap();
        let dup = err("CREATE TABLE \"index_log\"(id INTEGER PRIMARY KEY) STRICT");
        assert!(dup.contains("index_log"), "{dup}");
        assert_eq!(code(&dup), "COLLECTION_EXISTS");
        // An index whose name contains "table" is still an index.
        c.execute_batch("CREATE INDEX table_idx ON t(n)").unwrap();
        assert_eq!(code(&err("CREATE INDEX table_idx ON t(n)")), "INDEX_EXISTS");
        // add_field / create_collection with a name already used.
        assert_eq!(
            code(&err("ALTER TABLE t ADD COLUMN n TEXT")),
            "INVALID_PARAMS"
        );
        assert_eq!(code(&err("SELECT * FROM nope")), "COLLECTION_NOT_FOUND");
        assert_eq!(code(&err("SELECT nope FROM t")), "FIELD_NOT_FOUND");
    }

    /// The policy-filter refusal's serde tail can echo caller text; that text
    /// must not reach the field-spec rows (which used to come first).
    #[test]
    fn policy_filter_error_is_anchored_on_its_opener() {
        assert_eq!(
            code("invalid `using` filter: unknown variant `> max`, expected one of eq, ne"),
            "FILTER_PARSE_ERROR"
        );
        assert_eq!(
            code("invalid `check` filter: field x not found on collection y"),
            "FILTER_PARSE_ERROR"
        );
        // The opener is required: the same fragments mid-message do not count.
        assert_eq!(code("x: invalid `using` filter: y"), "INTERNAL");
    }

    /// `VectorCodecError` forwarded verbatim gets the codes REST gives it.
    #[test]
    fn vector_codec_errors_get_rest_codes() {
        use crate::query::vector_codec::VectorCodecError as V;
        let f = || "emb".to_string();
        let msg = |e: V| e.to_string();
        assert_eq!(
            code(&msg(V::DimMismatch {
                field: f(),
                expected: 3,
                got: 2
            })),
            "VECTOR_DIM_MISMATCH"
        );
        assert_eq!(
            code(&msg(V::NonFinite {
                field: f(),
                index: 0
            })),
            "VECTOR_NON_FINITE"
        );
        assert_eq!(
            code(&msg(V::NotNumeric {
                field: f(),
                index: 1
            })),
            "VECTOR_TYPE_ERROR"
        );
        assert_eq!(code(&msg(V::NotArray { field: f() })), "VECTOR_TYPE_ERROR");
        // A stored BLOB of the wrong length is not the caller's mistake.
        assert_eq!(code(&msg(V::BadBlobLen { field: f(), got: 5 })), "INTERNAL");
    }

    #[test]
    fn prefix_all_needs_the_opener_and_the_fragments() {
        let m = Match::PrefixAll("index ", &["already exists"]);
        assert!(m.matches("index i already exists"));
        assert!(!m.matches("table \"index_x\" already exists"));
        assert!(
            !m.matches("index associated with UNIQUE or PRIMARY KEY constraint cannot be dropped")
        );
        // The fragment is looked for AFTER the opener only.
        let m = Match::PrefixAll("ab", &["ab"]);
        assert!(!m.matches("ab"));
        assert!(m.matches("abab"));
    }

    #[test]
    fn fallback_follows_jsonrpc_class() {
        assert_eq!(
            mcp_error_code("something odd", ErrorCode::INVALID_PARAMS),
            "INVALID_PARAMS"
        );
        assert_eq!(
            mcp_error_code("something odd", ErrorCode::INTERNAL_ERROR),
            "INTERNAL"
        );
        // A matching row beats the class fallback.
        assert_eq!(
            mcp_error_code("no such rpc: x", ErrorCode::INVALID_PARAMS),
            "RPC_NOT_FOUND"
        );
    }

    #[test]
    fn every_needle_code_is_upper_snake() {
        for (_, c) in NEEDLES {
            assert!(is_upper_snake(c), "{c}");
        }
        for s in EMBEDDED_SENTINELS {
            assert!(is_upper_snake(s), "{s}");
        }
    }
}
