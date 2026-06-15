// tests/functions_schema.rs — lazy table creation + row CRUD + log trim.
mod helpers;

use drust::functions::schema::{self, CreateFunctionParams, FN_LOG_KEEP_PER_FUNCTION};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

fn pool_for(dir: &std::path::Path) -> drust::storage::pool::SharedTenantPool {
    let reg = Arc::new(TenantRegistry::new(dir.to_path_buf(), 2));
    reg.get_or_open("t-fn").expect("open tenant pool")
}

#[tokio::test]
async fn create_list_get_delete_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool_for(dir.path());

    let row = schema::create_function(
        &pool,
        CreateFunctionParams {
            name: "thumb".into(),
            wasm_sha256: "ab".repeat(32),
            size_bytes: 1024,
            triggers_json: r#"[{"file_uploaded":true}]"#.into(),
            description: "test fn".into(),
        },
        10, // max_per_tenant
    )
    .await
    .expect("create");
    assert_eq!(row.name, "thumb");
    assert!(row.active);

    let all = schema::list_functions(&pool).await.expect("list");
    assert_eq!(all.len(), 1);

    let one = schema::get_function(&pool, "thumb")
        .await
        .expect("get")
        .expect("some");
    assert_eq!(one.wasm_sha256, "ab".repeat(32));

    schema::set_active(&pool, "thumb", false)
        .await
        .expect("toggle");
    assert!(
        !schema::get_function(&pool, "thumb")
            .await
            .unwrap()
            .unwrap()
            .active
    );

    let deleted = schema::delete_function(&pool, "thumb").await.expect("del");
    assert!(deleted);
    assert!(
        schema::get_function(&pool, "thumb")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn name_validation_and_per_tenant_cap() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool_for(dir.path());
    // invalid names rejected
    for bad in ["", "UPPER", "has space", &"x".repeat(65)] {
        let r = schema::create_function(
            &pool,
            CreateFunctionParams {
                name: bad.into(),
                wasm_sha256: "00".repeat(32),
                size_bytes: 1,
                triggers_json: "[]".into(),
                description: String::new(),
            },
            10,
        )
        .await;
        let msg = r
            .expect_err(&format!("name {bad:?} must be rejected"))
            .to_string();
        assert!(
            msg.starts_with("FN_NAME_INVALID:"),
            "name {bad:?}: got {msg}"
        );
    }
    // cap enforced
    for i in 0..2 {
        schema::create_function(
            &pool,
            CreateFunctionParams {
                name: format!("f{i}"),
                wasm_sha256: "00".repeat(32),
                size_bytes: 1,
                triggers_json: "[]".into(),
                description: String::new(),
            },
            2,
        )
        .await
        .expect("under cap");
    }
    let over = schema::create_function(
        &pool,
        CreateFunctionParams {
            name: "f2".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        2,
    )
    .await;
    let msg = over.expect_err("cap").to_string();
    assert!(msg.starts_with("FN_LIMIT:"), "got {msg}");
}

#[tokio::test]
async fn create_with_same_name_replaces() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool_for(dir.path());
    for sha in ["aa", "bb"] {
        schema::create_function(
            &pool,
            CreateFunctionParams {
                name: "same".into(),
                wasm_sha256: sha.repeat(32),
                size_bytes: 1,
                triggers_json: "[]".into(),
                description: String::new(),
            },
            10,
        )
        .await
        .expect("upsert");
    }
    let all = schema::list_functions(&pool).await.unwrap();
    assert_eq!(all.len(), 1, "same-name create is replace, not duplicate");
    assert_eq!(all[0].wasm_sha256, "bb".repeat(32));
}

#[tokio::test]
async fn log_insert_and_trim() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool_for(dir.path());
    for i in 0..(FN_LOG_KEEP_PER_FUNCTION + 20) {
        schema::insert_log(
            &pool,
            schema::LogRow {
                invocation_id: format!("inv-{i}"),
                function_name: "f".into(),
                trigger: "manual".into(),
                status: "ok".into(),
                duration_ms: 1,
                log_text: String::new(),
                result_json: Some("{}".into()),
            },
        )
        .await
        .expect("log");
    }
    let logs = schema::list_logs(&pool, "f", 1000).await.expect("list");
    assert_eq!(
        logs.len(),
        FN_LOG_KEEP_PER_FUNCTION as usize,
        "trim-on-write keeps newest N"
    );
    // newest first
    assert_eq!(
        logs[0].invocation_id,
        format!("inv-{}", FN_LOG_KEEP_PER_FUNCTION + 19)
    );
}

#[tokio::test]
async fn delete_purges_logs_for_that_name() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool_for(dir.path());
    schema::create_function(
        &pool,
        CreateFunctionParams {
            name: "ephemeral".into(),
            wasm_sha256: "cc".repeat(32),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        10,
    )
    .await
    .expect("create");
    for i in 0..3 {
        schema::insert_log(
            &pool,
            schema::LogRow {
                invocation_id: format!("inv-{i}"),
                function_name: "ephemeral".into(),
                trigger: "manual".into(),
                status: "ok".into(),
                duration_ms: 1,
                log_text: String::new(),
                result_json: None,
            },
        )
        .await
        .expect("log");
    }
    assert!(
        schema::delete_function(&pool, "ephemeral")
            .await
            .expect("del")
    );
    // Trim-on-write only fires per live function_name; delete must purge the
    // dead name's logs or repeated create/invoke/delete grows the table forever.
    let logs = schema::list_logs(&pool, "ephemeral", 1000)
        .await
        .expect("list");
    assert!(
        logs.is_empty(),
        "delete_function must purge that name's log rows"
    );
}
