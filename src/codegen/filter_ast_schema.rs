//! v1.27 — Neutral schema descriptions of FilterAst, shared across all
//! collections in the OpenAPI document (referenced via $ref) and
//! emitted as named types in TS / Zod outputs.
//!
//! Source of truth for the shape: src/query/vector_filter.rs::FilterAst.

/// OpenAPI 3.1 schema for FilterAst, as a JSON Value. References itself
/// recursively via `$ref: '#/components/schemas/FilterAst'`.
pub fn filter_ast_openapi_schema() -> serde_json::Value {
    serde_json::json!({
        "oneOf": [
            { "type": "object", "required": ["op", "field", "value"], "properties": {
                "op": { "type": "string", "enum": ["eq", "neq", "lt", "lte", "gt", "gte", "like", "in"] },
                "field": { "type": "string" },
                "value": {}
            }},
            { "type": "object", "required": ["op", "filters"], "properties": {
                "op": { "type": "string", "enum": ["and", "or"] },
                "filters": { "type": "array", "items": { "$ref": "#/components/schemas/FilterAst" } }
            }},
            { "type": "object", "required": ["op", "filter"], "properties": {
                "op": { "type": "string", "enum": ["not"] },
                "filter": { "$ref": "#/components/schemas/FilterAst" }
            }}
        ]
    })
}

/// TypeScript type definition for FilterAst as a single string block.
pub const FILTER_AST_TS: &str = "\
export type FilterAst =
  | { op: 'eq' | 'neq' | 'lt' | 'lte' | 'gt' | 'gte' | 'like' | 'in'; field: string; value: unknown }
  | { op: 'and' | 'or'; filters: FilterAst[] }
  | { op: 'not'; filter: FilterAst };
";

/// Zod schema for FilterAst — self-referential via z.lazy.
pub const FILTER_AST_ZOD: &str = "\
export const FilterAstSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.object({ op: z.enum(['eq','neq','lt','lte','gt','gte','like','in']), field: z.string(), value: z.unknown() }),
    z.object({ op: z.enum(['and','or']), filters: z.array(FilterAstSchema) }),
    z.object({ op: z.literal('not'), filter: FilterAstSchema }),
  ])
);
";
