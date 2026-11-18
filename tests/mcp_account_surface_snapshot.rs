//! The account-level endpoint's whole static surface as one SHA-256: the
//! `initialize` result (server version masked), `tools/list`,
//! `resources/templates/list`, the files handbook, `prompts/list` and every
//! `prompts/get`. A change to any tool description, schema, instruction,
//! resource text or prompt text changes the digest. On a mismatch the actual
//! surface is written under `CARGO_TARGET_TMPDIR` for a diff. The tenant has
//! one collection, `x`, which every prompt argument but `tenant` names.

mod helpers;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const TENANT: &str = "snap";
const PINNED: &str = "765e43bda925e2bd3825c0a56b9eca8f92b75ea4b226a20ea042af9bfbba5499";

async fn rpc(h: &helpers::AccountMcpHarness, method: &str, params: Value) -> Value {
    let (status, _, mut m) = helpers::mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{method}");
    assert!(!m.is_empty(), "{method}: no answer");
    let m = m.swap_remove(0);
    assert!(m.get("error").is_none(), "{method}: {m}");
    m["result"].clone()
}

#[tokio::test]
async fn account_surface_is_pinned() {
    let h = helpers::spin_up_account_mcp(TENANT).await;
    // `secure_collection` renders only for a collection that exists, so the
    // value every prompt argument but `tenant` gets must name one.
    let made = helpers::mcp_call(
        &h.app,
        &h.access,
        TENANT,
        "create_collection",
        json!({"name": "x", "fields": [{"name": "title", "sql_type": "text"}]}),
    )
    .await;
    assert_ne!(made["result"]["isError"], json!(true), "{made}");
    let (_, _, mut init) =
        helpers::mcp_rpc(&h.app, Some(&h.access), helpers::mcp_init("2025-06-18")).await;
    let mut init = init.swap_remove(0)["result"].clone();
    init["serverInfo"]["version"] = json!("<masked>");
    let prompts = rpc(&h, "prompts/list", json!({})).await;
    let mut rendered = serde_json::Map::new();
    for p in prompts["prompts"].as_array().expect("prompts array") {
        let name = p["name"].as_str().unwrap();
        let mut args = serde_json::Map::new();
        for a in p["arguments"].as_array().into_iter().flatten() {
            let n = a["name"].as_str().unwrap();
            args.insert(n.into(), json!(if n == "tenant" { TENANT } else { "x" }));
        }
        rendered.insert(
            name.into(),
            rpc(&h, "prompts/get", json!({"name": name, "arguments": args})).await,
        );
    }
    let surface = json!({
        "initialize": init,
        "tools": rpc(&h, "tools/list", json!({})).await,
        "templates": rpc(&h, "resources/templates/list", json!({})).await,
        "files_guide": rpc(&h, "resources/read", json!({"uri": format!("drust://{TENANT}/files-guide.md")})).await,
        "prompts": prompts,
        "prompt_texts": Value::Object(rendered),
    });
    let text = serde_json::to_string_pretty(&surface).unwrap();
    let got = format!("{:x}", Sha256::digest(text.as_bytes()));
    if got != PINNED {
        let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("mcp_account_surface.actual.json");
        std::fs::write(&out, &text).unwrap();
        panic!(
            "account surface digest {got} != pinned {PINNED}; actual written to {}",
            out.display()
        );
    }
}
