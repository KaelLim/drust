//! Admin-only POST /admin/tenants/<id>/collections/<coll>/_list endpoint
//! that backs the v1.28 chip filter on the collection editor.
//!
//! Browser sends `{filters, sort, page, per_page}` with filter ops drawn
//! from the toolbar dropdown (`eq`, `contains`, `between`, `is_null`, …).
//! Handler bridges these to FilterAst (`src/query/vector_filter.rs`),
//! compiles to SQL with `?` binds, runs against the read-only connection,
//! and returns `{columns, rows, total, page, per_page, total_pages}`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ListRequest {
    #[serde(default)]
    pub filters: Vec<FilterTriple>,
    #[serde(default)]
    pub sort: Option<SortSpec>,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 { 1 }
fn default_per_page() -> u32 { 50 }

#[derive(Debug, Deserialize)]
pub struct FilterTriple {
    pub field: String,
    pub op: String,
    /// Always present in JSON; for `is_null` / `is_not_null` / `is_true`
    /// / `is_false` the value is ignored by the bridge.
    #[serde(default)]
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct SortSpec {
    pub field: String,
    pub dir: SortDir,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDir {
    Asc,
    Desc,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}
