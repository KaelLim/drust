//! v1.27 — Schema codegen module. Emits OpenAPI 3.1 / TypeScript /
//! Zod artifacts derived from per-tenant schema metadata.
//!
//! Pipeline:
//!   pool.schema_cache + _system_collection_meta  →  build_ir(...)  →  render_*
//!
//! Renderers are pure (CodegenIr → String / JSON Value), so unit
//! testing is golden-file diffing against a synthetic IR.

pub mod ir;
pub mod filter_ast_schema;
pub mod handlers;
pub mod openapi;
pub mod typescript;
pub mod zod;

pub use ir::{build_ir, CodegenIr, CollectionIr, DefaultValue, FieldIr, FieldType, IndexIr};

#[cfg(any(test, debug_assertions))]
pub fn synthetic_ir() -> CodegenIr {
    use ir::*;
    CodegenIr {
        tenant_id: "demo".into(),
        base_url: "https://example.com/drust".into(),
        include_descriptions: true,
        collections: vec![
            CollectionIr {
                name: "posts".into(),
                description: Some("Blog posts".into()),
                fields: vec![
                    FieldIr { name: "id".into(), ty: FieldType::Integer, nullable: false, default: None, fk: None, description: None, server_managed: true },
                    FieldIr { name: "title".into(), ty: FieldType::Text, nullable: false, default: None, fk: None, description: None, server_managed: false },
                    FieldIr { name: "body".into(), ty: FieldType::Text, nullable: true, default: None, fk: None, description: Some("Markdown body".into()), server_managed: false },
                    FieldIr { name: "author_id".into(), ty: FieldType::Integer, nullable: false, default: None, fk: Some("users".into()), description: None, server_managed: false },
                    FieldIr { name: "embedding".into(), ty: FieldType::Vector { dim: 1536 }, nullable: true, default: None, fk: None, description: None, server_managed: false },
                ],
                indexes: vec![],
                owner_field: Some("author_id".into()),
                realtime_enabled: true,
                has_vector: true,
            },
            CollectionIr {
                name: "users".into(),
                description: None,
                fields: vec![
                    FieldIr { name: "id".into(), ty: FieldType::Integer, nullable: false, default: None, fk: None, description: None, server_managed: true },
                    FieldIr { name: "email".into(), ty: FieldType::Text, nullable: false, default: None, fk: None, description: None, server_managed: false },
                ],
                indexes: vec![],
                owner_field: None,
                realtime_enabled: false,
                has_vector: false,
            },
        ],
    }
}

#[cfg(any(test, debug_assertions))]
pub fn render_openapi_for_test() -> serde_json::Value { openapi::render_openapi(&synthetic_ir()) }
#[cfg(any(test, debug_assertions))]
pub fn render_typescript_for_test() -> String { typescript::render_typescript(&synthetic_ir()) }
#[cfg(any(test, debug_assertions))]
pub fn render_zod_for_test() -> String { zod::render_zod(&synthetic_ir()) }
