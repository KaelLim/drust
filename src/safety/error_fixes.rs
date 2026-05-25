//! v1.26 — Static suggested_fix catalog. Maps every error_code drust
//! emits to a one-line "what to do next" hint that gets attached to
//! REST `ErrorBody` and MCP `ErrorData.data` so LLM callers can
//! self-correct without round-tripping to documentation.
//!
//! Keep the array sorted by code — `lookup` uses `binary_search_by_key`.

/// Sorted (by error code) catalog. Add new entries in alphabetical order.
pub const SUGGESTED_FIXES: &[(&str, &str)] = &[
    ("COLLECTION_NOT_FOUND", "Collection does not exist. Call `get_schema_overview` or `list_collections` to see existing collections."),
    ("DESCRIPTION_INVALID", "Description failed validation. Strip control characters and ensure UTF-8."),
    ("DESCRIPTION_TOO_LONG", "Descriptions are capped at 2048 bytes. Shorten the text and retry."),
    ("FIELD_NOT_FOUND", "Named field does not exist on this collection. Call `describe_collection` to see existing fields."),
    ("FK_RESTRICT", "Row is referenced by another collection's foreign key (ON DELETE RESTRICT). Delete the referencing rows first, or use `dry_run: true` to see which collections block."),
    ("INDEX_NOT_FOUND", "Named index does not exist on this collection. Call `describe_collection` to see existing indexes."),
    ("INVALID_PARAMS", "Required parameter missing or malformed. Re-read the tool's input schema."),
    ("LARGE_TABLE", "Table exceeds DRUST_INDEX_LARGE_TABLE_ROWS rows. Retry with `force: true` to bypass the guard (will lock the table briefly)."),
    ("MCP_USER_DENIED", "End-user tokens (`drust_user_*`) cannot use MCP. Use REST `/records` / `/list` / `/search` endpoints, or a stored RPC."),
    ("OAUTH_ONLY_NO_PASSWORD", "This user signed up via OAuth and has no password. Use the OAuth sign-in flow instead."),
    ("OWNER_FIELD_REQUIRED", "This collection has an owner_field; service-key INSERT must populate it explicitly. User-token INSERT auto-fills it from the authenticated user."),
    ("PROTECTED_COLLECTION", "`_system_*` collections are not writable via /records or MCP record tools. Use the matching admin endpoint (e.g. `_system_users` → POST /admin/users)."),
    ("QUERY_USER_DENIED", "End-user tokens cannot use `/query` (raw SELECT). Use `/list` (FilterAst), `/search` (vector), or a stored RPC with `:user_id`."),
    ("RATE_LIMITED", "Too many requests in the window. Wait for the `Retry-After` seconds and retry."),
    ("RECENT_WRITES_UNAVAILABLE", "Audit log is temporarily unreadable. Retry in a few seconds."),
    ("RECORD_NOT_FOUND", "Row id does not exist in this collection (or it was already deleted)."),
    ("TENANT_NOT_FOUND", "Tenant id is not registered or has been deleted. Check the tenant id in the URL path."),
    ("UNAUTHENTICATED", "Bearer token missing or invalid. Set `Authorization: Bearer <token>` and check the token has not been revoked."),
    ("USER_FILTER_DENIED_ON_OWNER_SCOPED", "User tokens cannot pass raw `?filter` / `?sort` against owner-scoped collections. Use `/list` POST body with FilterAst."),
    ("VECTOR_DIM_MISMATCH", "Vector length does not match the field's declared `dim`. Re-check the embedding dimension."),
    ("VECTOR_NON_FINITE", "Vector contains NaN or Inf. Replace non-finite values before insert."),
    ("VECTOR_TYPE_ERROR", "Vector field expects an array of numbers. Check the input type."),
    ("WRITE_DENIED", "Operation requires a service-key bearer token. Anon tokens cannot write."),
];

/// Look up a suggested_fix for an error code. Returns `None` when the code
/// is absent (catalog is intentionally finite — unknown codes get no fix).
pub fn lookup(code: &str) -> Option<&'static str> {
    SUGGESTED_FIXES
        .binary_search_by_key(&code, |&(k, _)| k)
        .ok()
        .map(|i| SUGGESTED_FIXES[i].1)
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
}
