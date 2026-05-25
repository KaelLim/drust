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

pub use ir::{build_ir, CodegenIr, CollectionIr, DefaultValue, FieldIr, FieldType, IndexIr};
