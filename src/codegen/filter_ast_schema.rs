//! Neutral schema descriptions of FilterAst, shared across all collections in
//! the OpenAPI document (referenced via `$ref`) and emitted as named types in
//! TS / Zod outputs.
//!
//! Source of truth for the shape: `src/query/vector_filter.rs::FilterAst`.
//! The wire format is a boolean tree — `{"and":[...]}` / `{"or":[...]}` /
//! `{"not":{...}}` — whose leaves are `{field: scalar}` (equality shorthand)
//! or `{field: {op: operand}}` with `op` one of eq, ne, gt, gte, lt, lte,
//! like, in, nin, is_null, is_not_null. `in`/`nin` take arrays; `is_null` /
//! `is_not_null` take any value (ignored). A leaf names EXACTLY ONE field and
//! an op object holds EXACTLY ONE operator.
//!
//! > This description must stay in lockstep with the real parser. It was once
//! > `{op, field, value}` — a shape the parser never accepted — which sent
//! > clients (and LLMs reading `openapi.json`) building filters that always
//! > failed. `src/query/vector_filter.rs::documented_shapes_match_the_real_parser`
//! > pins the true shape against the compiler, and the `codegen_ops_*` test in
//! > this module ties the operator NAMES here to the parser so the `neq`-class
//! > of drift can't return silently. The JSON-Schema branches use `anyOf`, not
//! > `oneOf`: the untagged enum matches the FIRST variant that fits, so a leaf
//! > on a field literally named `and`/`or`/`not` must not be an exclusive-match
//! > error.

/// The operand for a leaf: a bare scalar (eq shorthand) or a one-key op
/// object. Shared by every leaf-value position in the OpenAPI schema.
fn leaf_operand_openapi_schema() -> serde_json::Value {
    serde_json::json!({
        "anyOf": [
            { "type": ["string", "number", "boolean", "null"] },
            {
                "type": "object",
                "description": "one operator: {op: operand}. op ∈ eq|ne|gt|gte|lt|lte|like|in|nin|is_null|is_not_null. in/nin take arrays.",
                "minProperties": 1,
                "maxProperties": 1,
                "properties": {
                    "eq": {}, "ne": {}, "gt": {}, "gte": {}, "lt": {}, "lte": {},
                    "like": { "type": "string" },
                    "in": { "type": "array" }, "nin": { "type": "array" },
                    "is_null": { "type": "boolean" }, "is_not_null": { "type": "boolean" }
                },
                "additionalProperties": false
            }
        ]
    })
}

/// OpenAPI 3.1 schema for FilterAst, as a JSON Value. References itself
/// recursively via `$ref: '#/components/schemas/FilterAst'`.
pub fn filter_ast_openapi_schema() -> serde_json::Value {
    serde_json::json!({
        "anyOf": [
            { "type": "object", "required": ["and"], "additionalProperties": false, "properties": {
                "and": { "type": "array", "items": { "$ref": "#/components/schemas/FilterAst" } }
            }},
            { "type": "object", "required": ["or"], "additionalProperties": false, "properties": {
                "or": { "type": "array", "items": { "$ref": "#/components/schemas/FilterAst" } }
            }},
            { "type": "object", "required": ["not"], "additionalProperties": false, "properties": {
                "not": { "$ref": "#/components/schemas/FilterAst" }
            }},
            { "type": "object", "required": ["$fts"], "additionalProperties": false, "properties": {
                "$fts": {
                    "type": "object",
                    "description": "full-text search: MATCH the named fts index (create_fts_index) for `query`. Yields candidate rows AND-ed under the same owner/policy/caps filter as any other operand.",
                    "required": ["index", "query"],
                    "additionalProperties": false,
                    "properties": {
                        "index": { "type": "string" },
                        "query": { "type": "string" }
                    }
                }
            }},
            {
                "type": "object",
                "description": "leaf: exactly one {field: operand}, where operand is a scalar (eq shorthand) or a one-key {op: value} object.",
                "minProperties": 1,
                "maxProperties": 1,
                "additionalProperties": leaf_operand_openapi_schema()
            }
        ]
    })
}

/// TypeScript type definition for FilterAst as a single string block.
pub const FILTER_AST_TS: &str = "\
export type FilterScalar = string | number | boolean | null;
export type FilterOp =
  | { eq: FilterScalar } | { ne: FilterScalar }
  | { gt: FilterScalar } | { gte: FilterScalar }
  | { lt: FilterScalar } | { lte: FilterScalar }
  | { like: string }
  | { in: FilterScalar[] } | { nin: FilterScalar[] }
  | { is_null: boolean } | { is_not_null: boolean };
// A leaf names EXACTLY ONE field; a TS index signature cannot express that
// bound, so the runtime parser (not this type) enforces it — {} and multi-field
// objects type-check here but are rejected server-side.
// A `$fts` leaf runs a full-text MATCH against a named fts index; it is a
// reserved key, distinct from the {field: operand} leaf below.
export type FilterFts = { \"$fts\": { index: string; query: string } };
export type FilterAst =
  | { and: FilterAst[] }
  | { or: FilterAst[] }
  | { not: FilterAst }
  | FilterFts
  | { [field: string]: FilterScalar | FilterOp };
";

/// Zod schema for FilterAst — self-referential via z.lazy. Op objects are
/// `.strict()` so an extra operator (e.g. `{gte,lte}` — which the parser
/// rejects) fails validation instead of being silently stripped, and the leaf
/// is refined to exactly one field to match the parser.
pub const FILTER_AST_ZOD: &str = "\
export const FilterScalarSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);
export const FilterOpSchema = z.union([
  z.object({ eq: FilterScalarSchema }).strict(), z.object({ ne: FilterScalarSchema }).strict(),
  z.object({ gt: FilterScalarSchema }).strict(), z.object({ gte: FilterScalarSchema }).strict(),
  z.object({ lt: FilterScalarSchema }).strict(), z.object({ lte: FilterScalarSchema }).strict(),
  z.object({ like: z.string() }).strict(),
  z.object({ in: z.array(FilterScalarSchema) }).strict(), z.object({ nin: z.array(FilterScalarSchema) }).strict(),
  z.object({ is_null: z.boolean() }).strict(), z.object({ is_not_null: z.boolean() }).strict(),
]);
export const FilterFtsSchema = z.object({
  '$fts': z.object({ index: z.string(), query: z.string() }).strict(),
}).strict();
export const FilterAstSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.object({ and: z.array(FilterAstSchema) }),
    z.object({ or: z.array(FilterAstSchema) }),
    z.object({ not: FilterAstSchema }),
    FilterFtsSchema,
    z.record(z.union([FilterScalarSchema, FilterOpSchema]))
      .refine((o) => Object.keys(o).length === 1, { message: 'filter leaf must name exactly one field' }),
  ])
);
";

#[cfg(test)]
mod tests {
    use super::*;

    /// Ties the operator NAMES emitted by every renderer to the set the parser
    /// accepts, and asserts the pre-v1.58.6 drifted shape (`neq`, the
    /// `{op,field,value}` keys) is gone everywhere. `documented_shapes_match_the_real_parser`
    /// guards the parser side; this guards the codegen side, so the `neq`-class
    /// of drift cannot silently reappear in either.
    #[test]
    fn codegen_ops_match_parser_and_drop_the_drifted_shape() {
        let oa = serde_json::to_string(&filter_ast_openapi_schema()).unwrap();
        // Real operators the parser accepts must all appear in TS + Zod.
        for op in [
            "eq",
            "ne",
            "gt",
            "gte",
            "lt",
            "lte",
            "like",
            "in",
            "nin",
            "is_null",
            "is_not_null",
        ] {
            let key = format!("{op}:");
            assert!(FILTER_AST_TS.contains(&key), "TS missing operator `{op}`");
            assert!(FILTER_AST_ZOD.contains(&key), "Zod missing operator `{op}`");
        }
        // The stale shape/operator names must not survive in ANY renderer.
        for bad in ["neq", "\"op\"", "\"field\"", "\"filters\""] {
            assert!(
                !FILTER_AST_TS.contains(bad),
                "TS still carries stale `{bad}`"
            );
            assert!(
                !FILTER_AST_ZOD.contains(bad),
                "Zod still carries stale `{bad}`"
            );
            assert!(!oa.contains(bad), "OpenAPI still carries stale `{bad}`");
        }
        // The real boolean-node keys are present in the OpenAPI schema.
        for good in ["\"and\"", "\"or\"", "\"not\""] {
            assert!(oa.contains(good), "OpenAPI missing boolean node `{good}`");
        }

        // The `$fts` reserved-key operand (Wave 2 M3) is advertised by every
        // renderer with its `index`/`query` shape — codegen stays in lockstep
        // with the parser's `compile_fts`.
        for piece in ["$fts", "index", "query"] {
            assert!(oa.contains(piece), "OpenAPI missing $fts piece `{piece}`");
        }
        assert!(FILTER_AST_TS.contains("$fts"), "TS missing $fts operand");
        assert!(FILTER_AST_ZOD.contains("$fts"), "Zod missing $fts operand");
    }

    /// #950 anti-drift: the `$param` / `$auth` template-only leaf operands exist
    /// ONLY inside a stored `kind='query'` template
    /// (`query_template::template_filter_json_schema`), NEVER in a
    /// caller-supplied filter — so the SHARED FilterAst schema every codegen
    /// renderer publishes (and the shared MCP `filter_arg_json_schema`) must not
    /// mention them. Leaking either into the caller schema would tell clients to
    /// send `{"$auth":"id"}` as a normal filter, which the parser rejects and
    /// which — if it ever compiled — would be an identity-injection channel.
    #[test]
    fn shared_filter_schema_carries_no_template_operands() {
        let oa = serde_json::to_string(&filter_ast_openapi_schema()).unwrap();
        let shared_mcp =
            serde_json::to_string(&crate::query::vector_filter::filter_arg_json_schema(
                &mut schemars::SchemaGenerator::default(),
            ))
            .unwrap();
        for operand in ["$param", "$auth"] {
            assert!(
                !oa.contains(operand),
                "OpenAPI FilterAst schema leaks template operand `{operand}`"
            );
            assert!(
                !FILTER_AST_TS.contains(operand),
                "TS FilterAst leaks template operand `{operand}`"
            );
            assert!(
                !FILTER_AST_ZOD.contains(operand),
                "Zod FilterAst leaks template operand `{operand}`"
            );
            assert!(
                !shared_mcp.contains(operand),
                "shared MCP filter_arg_json_schema leaks template operand `{operand}`"
            );
        }

        // Positive control: the template schema (the ONE place these belong)
        // DOES advertise both. If a refactor moved the operands out of the
        // template and into the shared schema, THIS assertion reds alongside the
        // negatives above, so the guard can never pass vacuously.
        let tpl = serde_json::to_string(&crate::rpc::query_template::template_filter_json_schema(
            &mut schemars::SchemaGenerator::default(),
        ))
        .unwrap();
        assert!(
            tpl.contains("$param") && tpl.contains("$auth"),
            "template schema must be the sole home of the $param/$auth operands: {tpl}"
        );
    }
}
