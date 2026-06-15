//! v1.26 — Static suggested_fix catalog. Maps every error_code drust
//! emits to a one-line "what to do next" hint that gets attached to
//! REST `ErrorBody` and MCP `ErrorData.data` so LLM callers can
//! self-correct without round-tripping to documentation.
//!
//! Keep the array sorted by code — `lookup` uses `binary_search_by_key`.

/// Sorted (by error code) catalog. Add new entries in alphabetical order.
pub const SUGGESTED_FIXES: &[(&str, &str)] = &[
    (
        "ANON_CAP_DENIED",
        "Anonymous role lacks the required DML capability on this collection. Either authenticate with a user/service token, or have the tenant owner widen anon_caps.",
    ),
    (
        "ANON_DENIED",
        "Anonymous role is not permitted here. For a read-mode stored RPC, set anon_callable=true or call with a user/service token.",
    ),
    (
        "ANON_QUERY_DENIED_ON_POLICY",
        "Use POST /collections/<c>/list (FilterAst) or /search; /query (raw SELECT) is unavailable to anon once the tenant uses row-level policies, because drust cannot rewrite raw SQL to enforce them.",
    ),
    (
        "COLLECTION_NOT_FOUND",
        "Collection does not exist. Call `get_schema_overview` or `list_collections` to see existing collections.",
    ),
    (
        "DESCRIPTION_INVALID",
        "Description failed validation. Strip control characters and ensure UTF-8.",
    ),
    (
        "DESCRIPTION_TOO_LONG",
        "Descriptions are capped at 2048 bytes. Shorten the text and retry.",
    ),
    (
        "FIELD_NOT_FOUND",
        "Named field does not exist on this collection. Call `describe_collection` to see existing fields.",
    ),
    (
        "FK_RESTRICT",
        "Row is referenced by another collection's foreign key (ON DELETE RESTRICT). Delete the referencing rows first, or use `dry_run: true` to see which collections block.",
    ),
    (
        "FN_LIMIT",
        "Tenant function cap reached (DRUST_FN_MAX_PER_TENANT, default 10). Delete an unused function first (GET /t/<id>/functions to list).",
    ),
    (
        "FN_NAME_INVALID",
        "Function names must match [a-z0-9_-]{1,64}.",
    ),
    (
        "FN_NOT_FOUND",
        "No function with that name. GET /t/<id>/functions to list existing ones.",
    ),
    (
        "FN_TRIGGERS_INVALID",
        "triggers must be a JSON array of {\"collection\":\"…\",\"events\":[\"created\"|\"updated\"|\"deleted\"]} or {\"file_uploaded\":true}.",
    ),
    (
        "FN_WASM_TOO_LARGE",
        "Artifact exceeds DRUST_FN_MAX_WASM_BYTES (default 20 MiB). Build with --release, opt-level=\"s\", lto=true, strip=true.",
    ),
    (
        "INDEX_NOT_FOUND",
        "Named index does not exist on this collection. Call `describe_collection` to see existing indexes.",
    ),
    (
        "INVALID_PARAMS",
        "Required parameter missing or malformed. Re-read the tool's input schema.",
    ),
    (
        "INVALID_SQL_FOR_MODE",
        "RPC body contains SQL not allowed for this mode. Read-mode RPCs accept only SELECT; write-mode RPCs accept INSERT/UPDATE/DELETE on user collections only — DDL, ATTACH, and _system_* writes are always rejected.",
    ),
    (
        "LARGE_TABLE",
        "Table exceeds DRUST_INDEX_LARGE_TABLE_ROWS rows. Retry with `force: true` to bypass the guard (will lock the table briefly).",
    ),
    (
        "MCP_USER_DENIED",
        "End-user tokens (`drust_user_*`) cannot use MCP. Use REST `/records` / `/list` / `/search` endpoints, or a stored RPC.",
    ),
    (
        "OAUTH_ONLY_NO_PASSWORD",
        "This user signed up via OAuth and has no password. Use the OAuth sign-in flow instead.",
    ),
    (
        "OWNER_FIELD_REQUIRED",
        "This collection has an owner_field; service-key INSERT must populate it explicitly. User-token INSERT auto-fills it from the authenticated user.",
    ),
    (
        "POLICY_CHECK_FAILED",
        "The row violates this collection's row-level policy CHECK for this op. Adjust the field values so they satisfy the policy, or change the policy via PUT /collections/<c>/policies.",
    ),
    (
        "POLICY_COMPILE_ERROR",
        "drust could not compile this collection's policy to SQL. The policy references an unknown field or a bad operand. Valid operands are field names, {\"$auth\":\"id\"}, {\"$data\":\"<field>\"}, and {\"$authenticated\":true}. Fix the policy via PUT /collections/<c>/policies.",
    ),
    (
        "POLICY_INVALID",
        "The submitted policy failed validation: it references an unknown field or uses a bad operand. Valid operands are field names, {\"$auth\":\"id\"}, {\"$data\":\"<field>\"}, and {\"$authenticated\":true}.",
    ),
    (
        "PROTECTED_COLLECTION",
        "`_system_*` collections are not writable via /records or MCP record tools. Use the matching admin endpoint (e.g. `_system_users` → POST /admin/users).",
    ),
    (
        "PUBLISH_ANON_DENIED",
        "Anon tokens cannot publish to broadcast rooms on this tenant. Ask the admin to PATCH /admin/tenants/<id>/publish-policy with {\"allow_anon_publish\": true}, or use a service / user token.",
    ),
    (
        "PUBLISH_USER_DENIED",
        "User tokens cannot publish to broadcast rooms on this tenant. Ask the admin to PATCH /admin/tenants/<id>/publish-policy with {\"allow_user_publish\": true}, or use a service token.",
    ),
    (
        "QUERY_USER_DENIED",
        "End-user tokens cannot use `/query` (raw SELECT). Use `/list` (FilterAst), `/search` (vector), or a stored RPC with `:user_id`.",
    ),
    (
        "RATE_LIMITED",
        "Too many requests in the window. Wait for the `Retry-After` seconds and retry.",
    ),
    (
        "RECENT_WRITES_UNAVAILABLE",
        "Audit log is temporarily unreadable. Retry in a few seconds.",
    ),
    (
        "RECORD_NOT_FOUND",
        "Row id does not exist in this collection (or it was already deleted).",
    ),
    (
        "RPC_DENIED",
        "RPC is not callable by your role. Service tokens always work; user/anon tokens require anon_callable=true on the stored RPC.",
    ),
    (
        "RPC_STATEMENT_FAILED",
        "One statement in the multi-statement RPC body failed; all changes from this call were rolled back via SAVEPOINT. Inspect the failing statement (statement_index field, 1-based) and retry.",
    ),
    (
        "SERVICE_REQUIRED",
        "Operation requires a service-key bearer token. This is the canonical code; older responses may use WRITE_DENIED as the primary.",
    ),
    (
        "TENANT_NOT_FOUND",
        "Tenant id is not registered or has been deleted. Check the tenant id in the URL path.",
    ),
    (
        "TX_COMMIT_FAILED",
        "drust failed to RELEASE the per-RPC SAVEPOINT. Usually indicates disk full or fsync error on the tenant's data.sqlite. Check disk free space and dmesg.",
    ),
    (
        "UNAUTHENTICATED",
        "Bearer token missing or invalid. Set `Authorization: Bearer <token>` and check the token has not been revoked.",
    ),
    (
        "USER_FILTER_DENIED_ON_OWNER_SCOPED",
        "User tokens cannot pass raw `?filter` / `?sort` against owner-scoped collections. Use `/list` POST body with FilterAst.",
    ),
    (
        "USER_ID_BINDING_REQUIRED",
        "This RPC declares a :user_id parameter, which is auto-bound from the authenticated user's session. Anon tokens cannot satisfy this binding — call with a user/service token.",
    ),
    (
        "VECTOR_DIM_MISMATCH",
        "Vector length does not match the field's declared `dim`. Re-check the embedding dimension.",
    ),
    (
        "VECTOR_NON_FINITE",
        "Vector contains NaN or Inf. Replace non-finite values before insert.",
    ),
    (
        "VECTOR_TYPE_ERROR",
        "Vector field expects an array of numbers. Check the input type.",
    ),
    (
        "WASM_COMPILE_FAILED",
        "The uploaded file is not a valid wasm32-wasip2 component for the drust:function world. Build from sdk/edge-function-template with `cargo build --target wasm32-wasip2 --release`.",
    ),
    (
        "WRITE_DENIED",
        "Operation requires a service-key bearer token. Anon tokens cannot write.",
    ),
];

/// Look up a suggested_fix for an error code. Returns `None` when the code
/// is absent (catalog is intentionally finite — unknown codes get no fix).
pub fn lookup(code: &str) -> Option<&'static str> {
    SUGGESTED_FIXES
        .binary_search_by_key(&code, |&(k, _)| k)
        .ok()
        .map(|i| SUGGESTED_FIXES[i].1)
}

/// Context for a context-aware fix. Each variant carries just what its
/// template needs; sites without context use `lookup` directly.
pub enum ErrorContext<'a> {
    FieldNotFound {
        field: &'a str,
        collection: &'a str,
        existing: &'a [String],
    },
    CollectionNotFound {
        collection: &'a str,
        existing: &'a [String],
    },
    VectorDimMismatch {
        field: &'a str,
        expected_dim: u32,
        actual_dim: u32,
    },
    OwnerFieldRequired {
        collection: &'a str,
        field: &'a str,
    },
}

/// Build a context-aware fix string. Returns `None` when the code
/// has no context-aware variant; caller should fall back to `lookup`.
pub fn contextual_fix(ctx: &ErrorContext<'_>) -> String {
    match ctx {
        ErrorContext::FieldNotFound {
            field,
            collection,
            existing,
        } => format!(
            "Field `{field}` not found on collection `{collection}`. \
             Existing fields: [{}].",
            existing.join(", ")
        ),
        ErrorContext::CollectionNotFound {
            collection,
            existing,
        } => format!(
            "Collection `{collection}` not found. \
             Existing collections: [{}]. \
             Use `get_schema_overview` for the full schema.",
            existing.join(", ")
        ),
        ErrorContext::VectorDimMismatch {
            field,
            expected_dim,
            actual_dim,
        } => format!(
            "Field `{field}` expects vector of dim={expected_dim}; \
             got length={actual_dim}."
        ),
        ErrorContext::OwnerFieldRequired { collection, field } => format!(
            "Collection `{collection}` has owner_field=`{field}`. \
             Populate this field on INSERT. \
             (User-token INSERT auto-fills it from the authenticated user; \
             service-token INSERT must set it explicitly.)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_sorted() {
        // binary_search correctness depends on sorted-by-key.
        let mut prev = "";
        for &(k, _) in SUGGESTED_FIXES {
            assert!(k > prev, "catalog out of order at {k}");
            prev = k;
        }
    }

    #[test]
    fn lookup_finds_known_code() {
        let fix = lookup("LARGE_TABLE").expect("LARGE_TABLE present");
        assert!(fix.contains("force"));
    }

    #[test]
    fn lookup_returns_none_for_unknown() {
        assert!(lookup("MADE_UP_CODE").is_none());
    }

    #[test]
    fn every_entry_is_non_empty() {
        for &(k, v) in SUGGESTED_FIXES {
            assert!(!v.is_empty(), "{k} has empty fix");
        }
    }

    #[test]
    fn contextual_field_not_found_lists_existing() {
        let ctx = ErrorContext::FieldNotFound {
            field: "xxx",
            collection: "posts",
            existing: &["title".into(), "body".into()],
        };
        let s = contextual_fix(&ctx);
        assert!(s.contains("Field `xxx`"));
        assert!(s.contains("collection `posts`"));
        assert!(s.contains("title, body"));
    }

    #[test]
    fn contextual_collection_not_found_lists_existing() {
        let ctx = ErrorContext::CollectionNotFound {
            collection: "ghost",
            existing: &["posts".into(), "users".into()],
        };
        let s = contextual_fix(&ctx);
        assert!(s.contains("`ghost`"));
        assert!(s.contains("posts, users"));
    }

    #[test]
    fn contextual_vector_dim_includes_numbers() {
        let ctx = ErrorContext::VectorDimMismatch {
            field: "embedding",
            expected_dim: 1536,
            actual_dim: 768,
        };
        let s = contextual_fix(&ctx);
        assert!(s.contains("dim=1536"));
        assert!(s.contains("length=768"));
    }

    #[test]
    fn lookup_finds_policy_check_failed() {
        let fix = lookup("POLICY_CHECK_FAILED").expect("POLICY_CHECK_FAILED present");
        assert!(fix.contains("policies"), "got: {fix}");
        assert!(fix.contains("CHECK"), "got: {fix}");
    }

    #[test]
    fn lookup_finds_anon_query_denied_on_policy() {
        let fix =
            lookup("ANON_QUERY_DENIED_ON_POLICY").expect("ANON_QUERY_DENIED_ON_POLICY present");
        assert!(fix.contains("/list"), "got: {fix}");
        assert!(fix.contains("/search"), "got: {fix}");
        assert!(fix.contains("/query"), "got: {fix}");
    }

    #[test]
    fn lookup_finds_policy_invalid() {
        let fix = lookup("POLICY_INVALID").expect("POLICY_INVALID present");
        assert!(fix.contains("$auth"), "got: {fix}");
        assert!(fix.contains("$data"), "got: {fix}");
        assert!(fix.contains("$authenticated"), "got: {fix}");
    }

    #[test]
    fn lookup_finds_policy_compile_error() {
        let fix = lookup("POLICY_COMPILE_ERROR").expect("POLICY_COMPILE_ERROR present");
        assert!(fix.contains("$auth"), "got: {fix}");
        assert!(fix.contains("$data"), "got: {fix}");
        assert!(fix.contains("$authenticated"), "got: {fix}");
    }

    #[test]
    fn catalog_hygiene_anon_denied_present_mode_mismatch_absent() {
        // ANON_DENIED is emitted as a primary wire code by the read-mode
        // stored-RPC role denial (src/rpc/handler.rs) and must have a fix.
        assert!(
            lookup("ANON_DENIED").is_some(),
            "ANON_DENIED must have a suggested_fix"
        );
        // MODE_MISMATCH is never emitted as a wire code (the runtime path
        // emits INVALID_SQL_FOR_MODE); the dead entry must be gone.
        assert!(
            lookup("MODE_MISMATCH").is_none(),
            "MODE_MISMATCH is dead and must not be in the catalog"
        );
    }

    #[test]
    fn contextual_owner_field_required_names_field() {
        let ctx = ErrorContext::OwnerFieldRequired {
            collection: "posts",
            field: "author_id",
        };
        let s = contextual_fix(&ctx);
        assert!(s.contains("`posts`"));
        assert!(s.contains("`author_id`"));
    }
}
