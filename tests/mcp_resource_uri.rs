//! v1.56 M4 — URI-hardening corpus for the resource-template parser.
//!
//! `parse_resource_uri` is a pure fn (single `url::Url` parse + deny-by-default
//! routing), so this corpus exercises it directly — no DB, no `DrustMcp`. Every
//! reject must be `-32002` (`resource_not_found`); every accept must land on the
//! right `ResourceUri` variant. The query-hardening cases pin the codex
//! design-review finding: `as_str()==raw` canonicalizes the PATH but NOT the
//! query (`?p%61ge=2` survives as_str==raw yet `query_pairs()` form-decodes it to
//! `page`), so the parser must additionally reject `%`/`+`/dup/unknown query keys.

use drust::mcp::resources::{ResourceUri, parse_resource_uri};

const T: &str = "t-abc";

fn deny(uri: &str) {
    let e = parse_resource_uri(uri, T)
        .err()
        .unwrap_or_else(|| panic!("expected reject, got Ok for {uri}"));
    assert_eq!(e.code.0, -32002, "wrong code for {uri}");
}

#[test]
fn accepts_collection_schema_template() {
    match parse_resource_uri("drust://t-abc/collections/posts/schema", T).unwrap() {
        ResourceUri::CollectionSchema { collection } => assert_eq!(collection, "posts"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn accepts_records_list_template_no_query() {
    match parse_resource_uri("drust://t-abc/collections/posts/records", T).unwrap() {
        ResourceUri::Records {
            collection,
            page,
            per_page,
            sort,
            order,
        } => {
            assert_eq!(collection, "posts");
            assert_eq!(page, None);
            assert_eq!(per_page, None);
            assert_eq!(sort, None);
            assert_eq!(order, None);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn accepts_records_query_and_clamps_per_page() {
    match parse_resource_uri("drust://t-abc/collections/posts/records?per_page=999", T).unwrap() {
        ResourceUri::Records { per_page, .. } => assert_eq!(per_page, Some(200), "clamped to max"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn accepts_records_full_query() {
    match parse_resource_uri(
        "drust://t-abc/collections/posts/records?page=2&per_page=25&sort=created_at&order=desc",
        T,
    )
    .unwrap()
    {
        ResourceUri::Records {
            page,
            per_page,
            sort,
            order,
            ..
        } => {
            assert_eq!(page, Some(2));
            assert_eq!(per_page, Some(25));
            assert_eq!(sort.as_deref(), Some("created_at"));
            assert_eq!(order.as_deref(), Some("desc"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn accepts_single_record_canonical_i64() {
    match parse_resource_uri("drust://t-abc/collections/posts/records/5", T).unwrap() {
        ResourceUri::Record { collection, id } => {
            assert_eq!(collection, "posts");
            assert_eq!(id, 5);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn accepts_rpc_template() {
    match parse_resource_uri("drust://t-abc/rpcs/my_rpc", T).unwrap() {
        ResourceUri::Rpc { name } => assert_eq!(name, "my_rpc"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn statics_still_parse_and_reject_query() {
    assert!(matches!(
        parse_resource_uri("drust://t-abc/schema", T).unwrap(),
        ResourceUri::Schema
    ));
    // A static resource takes no query.
    deny("drust://t-abc/schema?x=1");
}

#[test]
fn rejects_cross_tenant_on_templates() {
    deny("drust://t-other/collections/posts/records/5");
    deny("drust://t-other/collections/posts/schema");
    deny("drust://t-other/rpcs/x");
}

#[test]
fn rejects_protected_collection() {
    deny("drust://t-abc/collections/_system_files/records/5");
    deny("drust://t-abc/collections/_system_files/schema");
    deny("drust://t-abc/collections/_system_record_history/records");
}

#[test]
fn rejects_traversal_and_encoding() {
    // url resolves literal AND %2e-encoded dot-segments → as_str()!=raw catches.
    deny("drust://t-abc/collections/../schema");
    deny("drust://t-abc/collections/posts/records/../schema");
    deny("drust://t-abc/collections/%2e%2e/schema");
    // Encoded slash / NUL survive as literal segments containing `%` → no-% rule.
    deny("drust://t-abc/collections/a%2fb/schema");
    deny("drust://t-abc/collections/a%00b/records/5");
}

#[test]
fn rejects_bad_identifier_and_shape() {
    deny("drust://t-abc/collections/a-b!/schema"); // identifier() rejects `-`/`!`
    deny("drust://t-abc/collections/Posts/schema"); // uppercase not an identifier
    deny("drust://t-abc/collections/a/records/5/extra"); // over-segment
    deny("drust://t-abc/collections/posts"); // missing 3rd segment
    deny("drust://t-abc/collections//records"); // empty segment
    deny("drust://t-abc/nope/x"); // unknown top segment
    deny("drust://t-abc/rpcs/x/y"); // rpc over-segment
}

#[test]
fn rejects_noncanonical_or_bad_id() {
    deny("drust://t-abc/collections/posts/records/05"); // leading zero != canonical i64
    deny("drust://t-abc/collections/posts/records/abc"); // not an integer
    deny("drust://t-abc/collections/posts/records/5?x=1"); // record takes no query
    deny("drust://t-abc/collections/posts/records/ "); // space
}

#[test]
fn rejects_query_encoding_and_unknown_keys() {
    // THE codex finding: %-encoded key survives as_str==raw but query_pairs
    // form-decodes `p%61ge` → `page`. Reject any `%` or `+` in the raw query.
    deny("drust://t-abc/collections/posts/records?p%61ge=2");
    deny("drust://t-abc/collections/posts/records?sort=created%5Fat");
    deny("drust://t-abc/collections/posts/records?sort=a+b");
    // Unknown / duplicate keys, bad values.
    deny("drust://t-abc/collections/posts/records?evil=1");
    deny("drust://t-abc/collections/posts/records?page=1&page=2");
    deny("drust://t-abc/collections/posts/records?per_page=abc");
    deny("drust://t-abc/collections/posts/records?order=sideways");
    // Query is not allowed on the schema / single-record templates.
    deny("drust://t-abc/collections/posts/schema?x=1");
}

#[test]
fn dropped_templates_are_not_resources() {
    // history + function-logs were pulled from the resource surface (spec §3:
    // auto-fetchable resources must not carry uncontrolled log/old-snapshot
    // secrets). They remain reachable only via the explicit MCP tools.
    deny("drust://t-abc/collections/posts/history");
    deny("drust://t-abc/collections/posts/history?record_id=5");
    deny("drust://t-abc/functions/f1/logs");
    deny("drust://t-abc/functions/f1/logs?limit=10");
}
