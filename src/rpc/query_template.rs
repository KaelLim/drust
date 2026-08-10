//! Stored **query-kind** RPC templates (#950 Phase 1).
//!
//! A `kind='query'` row in `_system_rpc` stores a curated `FilterAst`
//! *template* instead of raw SQL. This module is the pure half of that
//! feature: parse the stored JSON, substitute the two template-only leaf
//! operands (`{"$param":"<name>"}` / `{"$auth":"id"}`) at the **JSON level
//! BEFORE** the `FilterAst` parse, and validate a template at save time.
//!
//! No DB, no async, no authorization — the execution arm supplies those.
//!
//! > The scalar-only argument rule (`NotScalar`) is THE AST-injection gate:
//! > an argument that is a JSON object or array could otherwise inject
//! > `{"$fts":…}` / `{"$gt":…}` operator structure into a curated template.
//! > A scalar can only ever land as a `?`-bound operand.
//!
//! Spec: `docs/superpowers/specs/2026-08-10-rpc-rls-readmode-design.md`
//! §參數代入 (normative).

use crate::query::list_builder::{self, ListRequest, SortSpec};
use crate::query::vector_filter::{FilterAst, filter_shape_hint};
use crate::rpc::params::{self, ParamError, ParamSpec, ParamType};
use crate::storage::schema::{CollectionSchema, is_protected_collection};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Template-only leaf operand: substitute a declared caller param.
const PARAM_KEY: &str = "$param";
/// Template-only leaf operand: substitute the caller's end-user id.
const AUTH_KEY: &str = "$auth";
/// The only accepted `$auth` sub-key (mirrors the RLS policy grammar's
/// `{"$auth":"id"}`).
const AUTH_ID: &str = "id";

/// Hard ceiling on a stored `query_json` blob.
///
/// [`substitute`] CLONES an argument once per `{"$param":…}` reference, so a
/// template with N references and an M-byte argument allocates N×M — the
/// template is the only bound on N. 64 KiB is far above any curated filter
/// and also belts the walk's node count.
const MAX_TEMPLATE_BYTES: usize = 64 * 1024;

/// `schemars` override for [`QueryTemplate::filter`]. A bare
/// `serde_json::Value` renders as schemars' untyped "any", which strict MCP
/// clients stringify — the v1.58.6 double-encoding bug. Steer it to `object`
/// and describe the two template-only operands HERE: the shared
/// [`crate::query::vector_filter::filter_arg_json_schema`] must NOT gain
/// `$param` / `$auth` (spec §周邊面 — they exist only inside a stored
/// template, never in a caller-supplied filter).
pub fn template_filter_json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "description": "Structured filter template (FilterAst). A boolean node \
            {\"and\":[...]} / {\"or\":[...]} / {\"not\":{...}}, or a leaf \
            {field: scalar} (equality) or {field: {op: operand}} where op is \
            one of eq, ne, gt, gte, lt, lte, like, in, nin, is_null, \
            is_not_null. Two TEMPLATE-ONLY leaf operands are also accepted, \
            each an object with exactly one key: {\"$param\":\"<declared \
            param name>\"} substitutes the caller's argument (scalars only) \
            and {\"$auth\":\"id\"} substitutes the caller's end-user id (null \
            for anon/service/admin/cron). They are valid ONLY here, not in a \
            caller-supplied filter. Pass as a JSON object, not a \
            JSON-encoded string."
    })
}

/// The stored shape of a `kind='query'` RPC (`_system_rpc.query_json`).
///
/// `filter` stays an untyped [`Value`] on purpose: `$param` / `$auth`
/// substitution happens at the JSON level **before** the [`FilterAst`]
/// parse, so the template itself is not a valid `FilterAst` yet.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryTemplate {
    pub collection: String,
    #[serde(default)]
    #[schemars(schema_with = "crate::rpc::query_template::template_filter_json_schema")]
    pub filter: Option<Value>,
    /// `{"field":"<name>","dir":"asc"|"desc"}`. Both halves are IDENTIFIER
    /// positions — `$param` cannot appear there (they are typed `String`, so
    /// a `$param` object fails [`parse_template`]).
    #[serde(default)]
    pub sort: Option<SortSpec>,
    #[serde(default)]
    pub select: Option<Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// A caller argument was an object or an array. Wire code
    /// `RPC_PARAM_NOT_SCALAR`.
    #[error("param '{0}' must be a JSON scalar (string, number, boolean or null)")]
    NotScalar(String),
    /// The template references a `$param` no `params_json` entry declares.
    #[error("template references undeclared param '{0}'")]
    UndeclaredParam(String),
    /// A declared param the template never references.
    #[error("declared param '{0}' is never referenced by the template")]
    UnusedParam(String),
    /// A `$auth` node whose sub-key is not `"id"`.
    #[error("$auth key must be \"id\", got {0}")]
    BadAuthKey(String),
    /// Malformed template JSON, or a template that does not compile.
    #[error("invalid query template: {0}")]
    BadShape(String),
    /// A caller-argument failure that the sql arm reports identically
    /// (`PARAM_UNKNOWN` / `PARAM_TYPE_MISMATCH` / missing required).
    #[error(transparent)]
    Arg(ParamError),
}

/// Parse `_system_rpc.query_json`. Every serde failure — malformed JSON,
/// unknown key, wrong type — becomes [`TemplateError::BadShape`], as does a
/// blob over [`MAX_TEMPLATE_BYTES`] (checked BEFORE the parse, so an
/// oversized template costs no allocation).
pub fn parse_template(query_json: &str) -> Result<QueryTemplate, TemplateError> {
    if query_json.len() > MAX_TEMPLATE_BYTES {
        return Err(TemplateError::BadShape(format!(
            "template too large: {} bytes (max {MAX_TEMPLATE_BYTES})",
            query_json.len()
        )));
    }
    serde_json::from_str(query_json).map_err(|e| TemplateError::BadShape(e.to_string()))
}

/// The `$param` NAMES reachable in `filter`.
///
/// Reachability is byte-identical to [`substitute`]'s: any single-key
/// `$param` object is a substitution SITE and the walk stops there (only a
/// string value also yields a name — a non-string one is a site that
/// [`substitute`] rejects, so descending into it would report a phantom
/// reference); a single-key `$auth` object is likewise a site the walk does
/// not descend into. Sharing the predicate is what keeps
/// [`validate_template`]'s declared↔referenced check from disagreeing with
/// what substitution will actually do.
pub fn referenced_params(filter: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    collect_params(filter, &mut out);
    out
}

fn collect_params(node: &Value, out: &mut BTreeSet<String>) {
    match node {
        Value::Object(obj) => {
            if let Some(v) = single_key(obj, PARAM_KEY) {
                if let Value::String(name) = v {
                    out.insert(name.clone());
                }
                // A `$param` site is a leaf for BOTH walks, valid or not.
                return;
            }
            if single_key(obj, AUTH_KEY).is_some() {
                // Ditto for `$auth`: substitute replaces the whole node.
                return;
            }
            for v in obj.values() {
                collect_params(v, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                collect_params(v, out);
            }
        }
        _ => {}
    }
}

/// `Some(value)` when `obj` is exactly `{key: value}`.
fn single_key<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    if obj.len() == 1 { obj.get(key) } else { None }
}

/// Validate caller arguments and return the map [`substitute`] must be fed.
///
/// The ONE entry point an execution arm calls: validation and default
/// resolution are a single step precisely because doing them in two was a
/// footgun — [`substitute`] is mechanical, so skipping the default fill
/// makes an optional param with a `default` silently filter on NULL.
///
/// ```text
/// resolve_args(specs, body) -> substitute_to_filter_ast(template, args, auth_id)
/// ```
pub fn resolve_args(
    specs: &[ParamSpec],
    args: &Map<String, Value>,
) -> Result<Map<String, Value>, TemplateError> {
    check_args(specs, args)?;
    Ok(apply_defaults(specs, args))
}

/// Validate caller arguments against the declared params, in the order the
/// spec fixes: **unknown key → shape → type**.
///
/// Shape (`NotScalar`) must precede type coercion: an object argument is an
/// AST-injection attempt, not a type mismatch, and must be reported as such.
///
/// Missing / null / default handling is a verbatim mirror of the sql arm
/// (`params::validate_and_bind`): missing + required → `Arg(Missing)` **even
/// when the spec also declares a `default`** (the sql arm's `(true, _)`
/// arm); missing + optional + default → the declared default is type-checked;
/// missing + optional, no default → null; an explicit null is accepted for
/// any declared type. The [`params::BoundValue`] is discarded — the query
/// arm binds through the list builder, not through rusqlite params.
fn check_args(specs: &[ParamSpec], args: &Map<String, Value>) -> Result<(), TemplateError> {
    // (1) unknown keys — the sql arm's fast typo signal.
    for k in args.keys() {
        if !specs.iter().any(|p| &p.name == k) {
            return Err(TemplateError::Arg(ParamError::Unknown(k.clone())));
        }
    }
    // (2) SHAPE, before any type reasoning.
    for (k, v) in args {
        if v.is_object() || v.is_array() {
            return Err(TemplateError::NotScalar(k.clone()));
        }
    }
    // (3) type, through the shared coercion so the two arms cannot drift.
    for spec in specs {
        let value = match args.get(&spec.name) {
            Some(v) => v.clone(),
            None => match (spec.required, &spec.default) {
                (true, _) => {
                    return Err(TemplateError::Arg(ParamError::Missing(spec.name.clone())));
                }
                (false, Some(d)) => d.clone(),
                (false, None) => Value::Null,
            },
        };
        params::coerce(spec, &value).map_err(TemplateError::Arg)?;
    }
    Ok(())
}

/// Fill declared defaults into a caller argument map. A caller-supplied
/// value always wins. Runs AFTER [`check_args`] has type-checked the
/// default, and only ever through [`resolve_args`].
fn apply_defaults(specs: &[ParamSpec], args: &Map<String, Value>) -> Map<String, Value> {
    let mut out = args.clone();
    for spec in specs {
        if !out.contains_key(&spec.name)
            && let Some(d) = &spec.default
        {
            out.insert(spec.name.clone(), d.clone());
        }
    }
    out
}

/// Substitute the template-only operands at the JSON level.
///
/// - object with **exactly one** key `$param` → the argument's value.
///   Non-string param name → [`TemplateError::BadShape`]; object/array
///   argument → [`TemplateError::NotScalar`]; absent argument → null.
/// - object with **exactly one** key `$auth` → `auth_id` as a JSON string,
///   or null when the caller has no end-user identity (anon, service,
///   admin, cron). Any sub-key but `"id"` → [`TemplateError::BadAuthKey`].
/// - anything else → recursed into (objects and arrays) or cloned (scalars).
///
/// Execution arms call [`substitute_to_filter_ast`], which pairs this with
/// the ONLY safe parse. This stays public for [`validate_template`]'s dry
/// run and for tests.
///
/// Recursion is bounded by serde_json's own 128-level nesting limit, which
/// [`parse_template`] (a `from_str` parse) has already applied to every
/// template this walks; [`MAX_TEMPLATE_BYTES`] bounds the node count.
pub fn substitute(
    node: &Value,
    args: &Map<String, Value>,
    auth_id: Option<&str>,
) -> Result<Value, TemplateError> {
    match node {
        Value::Object(obj) => {
            if let Some(name) = single_key(obj, PARAM_KEY) {
                let name = name.as_str().ok_or_else(|| {
                    TemplateError::BadShape(format!("{PARAM_KEY} must be a string param name"))
                })?;
                return match args.get(name) {
                    Some(Value::Object(_)) | Some(Value::Array(_)) => {
                        Err(TemplateError::NotScalar(name.to_string()))
                    }
                    Some(scalar) => Ok(scalar.clone()),
                    // check_args is the presence gate; absent here is null.
                    None => Ok(Value::Null),
                };
            }
            if let Some(key) = single_key(obj, AUTH_KEY) {
                check_auth_operand(key)?;
                return Ok(match auth_id {
                    Some(id) => Value::String(id.to_string()),
                    None => Value::Null,
                });
            }
            let mut out = Map::with_capacity(obj.len());
            for (k, v) in obj {
                out.insert(k.clone(), substitute(v, args, auth_id)?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => items
            .iter()
            .map(|v| substitute(v, args, auth_id))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        scalar => Ok(scalar.clone()),
    }
}

/// [`substitute`] + the only safe parse of its result.
///
/// > [!WARNING]
/// > The substituted value MUST be parsed with **strict**
/// > `serde_json::from_value::<FilterAst>` — NEVER the string-tolerant
/// > `vector_filter::parse_filter_value`, which re-parses a JSON *string*
/// > into structure and would therefore turn a scalar string argument back
/// > into operator structure, defeating the `NotScalar` gate. Keeping the
/// > two steps welded together here is what makes that unskippable by
/// > construction; call this, not [`substitute`], from an execution arm.
///
/// A parse failure reports [`filter_shape_hint`] rather than serde's opaque
/// "did not match any variant of untagged enum FilterAst".
pub fn substitute_to_filter_ast(
    node: &Value,
    args: &Map<String, Value>,
    auth_id: Option<&str>,
) -> Result<FilterAst, TemplateError> {
    let substituted = substitute(node, args, auth_id)?;
    serde_json::from_value::<FilterAst>(substituted)
        .map_err(|_| TemplateError::BadShape(filter_shape_hint()))
}

fn check_auth_operand(key: &Value) -> Result<(), TemplateError> {
    match key.as_str() {
        Some(AUTH_ID) => Ok(()),
        _ => Err(TemplateError::BadAuthKey(key.to_string())),
    }
}

/// Walk every `$auth` node and reject any sub-key but `"id"`.
///
/// A separate save-time pass so the verdict does not depend on the dry
/// compile running. Honest note: today it is REDUNDANT by construction —
/// the dry compile's [`substitute`] walks the same nodes through the same
/// [`check_auth_operand`] and would reject an identical set, so no test can
/// red on its removal alone. It is kept as the explicit save-time step the
/// spec enumerates, not as an independently load-bearing gate.
fn check_auth_keys(node: &Value) -> Result<(), TemplateError> {
    match node {
        Value::Object(obj) => {
            if let Some(key) = single_key(obj, AUTH_KEY) {
                return check_auth_operand(key);
            }
            for v in obj.values() {
                check_auth_keys(v)?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(check_auth_keys),
        _ => Ok(()),
    }
}

fn dummy_for(ty: ParamType) -> Value {
    match ty {
        ParamType::Text => Value::from("x"),
        ParamType::Integer => Value::from(1),
        ParamType::Real => Value::from(1.0),
        ParamType::Boolean => Value::from(true),
    }
}

/// Save-time validation of a stored template (`create_rpc` / `update_rpc`).
///
/// 0. `schema` IS the schema of `tpl.collection` — a mismatch means the
///    caller loaded the wrong schema, and every check below would then be
///    vacuous (a template for `posts` dry-compiled against `_system_users`
///    "passes" while naming a collection nothing here inspected);
/// 1. the target collection is not `_system_*` / `sqlite_*`;
/// 2. declared ↔ referenced params agree in BOTH directions;
/// 3. every declared default is itself a scalar of its declared type;
/// 4. every `$auth` node keys on `"id"`;
/// 5. the template DRY-COMPILES: substituted with per-type dummy values it
///    parses as a [`FilterAst`] and builds through the unchanged
///    [`list_builder::build_structured_list_sql`] (no owner, no policy — a
///    structural check, not an authorization one), so a broken template dies
///    at save instead of at every call.
pub fn validate_template(
    schema: &CollectionSchema,
    tpl: &QueryTemplate,
    specs: &[ParamSpec],
) -> Result<(), TemplateError> {
    if schema.name != tpl.collection {
        return Err(TemplateError::BadShape(format!(
            "schema/template collection mismatch: '{}' != '{}'",
            schema.name, tpl.collection
        )));
    }

    if is_protected_collection(&tpl.collection) {
        return Err(TemplateError::BadShape(format!(
            "collection is protected: '{}'",
            tpl.collection
        )));
    }

    let referenced = tpl
        .filter
        .as_ref()
        .map(referenced_params)
        .unwrap_or_default();
    let declared: BTreeSet<String> = specs.iter().map(|s| s.name.clone()).collect();
    if let Some(name) = referenced.difference(&declared).next() {
        return Err(TemplateError::UndeclaredParam(name.clone()));
    }
    if let Some(name) = declared.difference(&referenced).next() {
        return Err(TemplateError::UnusedParam(name.clone()));
    }

    // A declared default is substituted verbatim at call time, so it obeys
    // the same scalar-only + declared-type rules a caller argument does —
    // enforced at save, not at every call.
    for spec in specs {
        if let Some(d) = &spec.default {
            if d.is_object() || d.is_array() {
                return Err(TemplateError::NotScalar(spec.name.clone()));
            }
            params::coerce(spec, d).map_err(TemplateError::Arg)?;
        }
    }

    if let Some(f) = &tpl.filter {
        check_auth_keys(f)?;
    }

    let dummies: Map<String, Value> = specs
        .iter()
        .map(|s| (s.name.clone(), dummy_for(s.ty)))
        .collect();
    let filter = match &tpl.filter {
        Some(f) => Some(substitute_to_filter_ast(f, &dummies, Some("dummy"))?),
        None => None,
    };
    let req = ListRequest {
        filter,
        sort: tpl.sort.clone(),
        select: tpl.select.clone(),
        page: None,
        per_page: None,
    };
    list_builder::build_structured_list_sql(schema, &req, None, None)
        .map_err(|e| TemplateError::BadShape(e.to_string()))?;

    // Cross-storage-class check on the dry-compiled AST, sharing the policy
    // save-time machinery (#954) — see `check_template_operand_classes` for the
    // one divergence ($fts) and why the rest must NOT be a second copy. It runs
    // on the SUBSTITUTED ast, so `$auth` is the text "dummy" and each `$param`
    // is a literal of its DECLARED type; that is exactly the class each will
    // carry at call time. Without it, `{"score":{"lt":{"$auth":"id"}}}` saves
    // clean and then matches EVERY row (SQLite orders all INTEGERs before all
    // TEXT), which reads as a working "my rows" filter while it is a full-table
    // read — the #954 footgun, one template away.
    if let Some(f) = &req.filter {
        crate::query::policy::check_template_operand_classes(schema, f)
            .map_err(|e| TemplateError::BadShape(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::vector_filter::FilterAst;
    use crate::rpc::params::{ParamSpec, ParamType};
    use crate::storage::schema::{CollectionSchema, Field};
    use serde_json::{Map, Value, json};
    use std::collections::BTreeSet;

    fn spec(n: &str, t: ParamType) -> ParamSpec {
        ParamSpec {
            name: n.into(),
            ty: t,
            required: true,
            default: None,
        }
    }

    fn args(pairs: &[(&str, Value)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    fn field(name: &str, sql_type: &str) -> Field {
        Field {
            name: name.into(),
            sql_type: sql_type.into(),
            ..Default::default()
        }
    }

    fn fixture_schema() -> CollectionSchema {
        CollectionSchema {
            name: "posts".into(),
            fields: vec![
                field("title", "TEXT"),
                field("status", "TEXT"),
                field("score", "INTEGER"),
                field("owner_id", "TEXT"),
            ],
            indices: vec![],
            row_count: 0,
            anon_caps: BTreeSet::new(),
            user_caps: BTreeSet::new(),
            owner_field: None,
            read_scope: None,
            vector_fields: vec![],
            fts_indexes: vec![],
            realtime_enabled: true,
            audit_enabled: true,
            description: None,
            policies: Default::default(),
        }
    }

    fn tpl(v: Value) -> QueryTemplate {
        parse_template(&v.to_string()).unwrap()
    }

    // ── substitute ────────────────────────────────────────────────────

    #[test]
    fn substitute_replaces_param_and_auth() {
        let t = json!({"status":"published","author":{"$param":"who"},"me":{"$auth":"id"}});
        let a = args(&[("who", json!("alice"))]);
        let out = substitute(&t, &a, Some("u42")).unwrap();
        assert_eq!(
            out,
            json!({"status":"published","author":"alice","me":"u42"})
        );
        // anon (and every caller with no end-user identity) → JSON null.
        let anon = substitute(&t, &a, None).unwrap();
        assert_eq!(anon["me"], Value::Null);
    }

    #[test]
    fn object_and_array_args_are_not_scalar() {
        let t = json!({"a":{"$param":"p"}});
        for bad in [json!({"$fts":{"index":"i","query":"x"}}), json!([1, 2])] {
            let a = args(&[("p", bad)]);
            assert!(matches!(
                substitute(&t, &a, None),
                Err(TemplateError::NotScalar(p)) if p == "p"
            ));
        }
    }

    #[test]
    fn auth_key_other_than_id_rejected() {
        for bad in [json!({"a":{"$auth":"email"}}), json!({"a":{"$auth":7}})] {
            assert!(matches!(
                substitute(&bad, &Map::new(), Some("u1")),
                Err(TemplateError::BadAuthKey(_))
            ));
        }
    }

    #[test]
    fn param_ref_with_non_string_name_is_bad_shape() {
        let t = json!({"a":{"$param":7}});
        assert!(matches!(
            substitute(&t, &Map::new(), None),
            Err(TemplateError::BadShape(_))
        ));
    }

    #[test]
    fn missing_arg_substitutes_null() {
        // check_args is the presence gate; substitute is mechanical.
        let t = json!({"a":{"$param":"p"}});
        assert_eq!(
            substitute(&t, &Map::new(), None).unwrap(),
            json!({"a":null})
        );
    }

    #[test]
    fn param_nested_in_in_array_is_found_and_substituted() {
        let t = json!({"status":{"in":[{"$param":"a"},"draft",{"$param":"b"}]}});
        assert_eq!(
            referenced_params(&t),
            ["a".to_string(), "b".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        let out = substitute(&t, &args(&[("a", json!("live")), ("b", json!(3))]), None).unwrap();
        assert_eq!(out, json!({"status":{"in":["live","draft",3]}}));
    }

    #[test]
    fn object_with_param_and_extra_key_is_not_a_param_ref() {
        // Exactly-one-key is the rule: a two-key object is an ordinary node
        // and must be recursed into, never treated as a substitution site.
        let t = json!({"a":{"$param":"p","gt":1}, "b":{"$auth":"id","x":2}});
        assert!(referenced_params(&t).is_empty());
        let out = substitute(&t, &args(&[("p", json!("zzz"))]), Some("u1")).unwrap();
        assert_eq!(out, t);
    }

    #[test]
    fn template_scalars_pass_through_untouched() {
        let t = json!({"a":null,"b":true,"c":1,"d":1.5,"e":"lit","f":[null,false,"x"]});
        assert_eq!(substitute(&t, &Map::new(), Some("u1")).unwrap(), t);
        assert!(referenced_params(&t).is_empty());
    }

    #[test]
    fn string_arg_is_never_reparsed_as_filter_structure() {
        // THE AST-injection pin: a scalar arg stays a scalar, and the
        // welded parse in `substitute_to_filter_ast` refuses it rather than
        // re-parsing the string into operator structure (which the
        // string-tolerant `parse_filter_value` WOULD do).
        let t = json!({"$param":"p"});
        let a = args(&[("p", json!(r#"{"or":[]}"#))]);
        let out = substitute(&t, &a, None).unwrap();
        assert_eq!(out, json!(r#"{"or":[]}"#));
        assert!(serde_json::from_value::<FilterAst>(out).is_err());
        assert!(matches!(
            substitute_to_filter_ast(&t, &a, None),
            Err(TemplateError::BadShape(m)) if m == filter_shape_hint()
        ));
    }

    #[test]
    fn substituted_non_ast_reports_filter_shape_hint() {
        // A double-encoded filter template: the stored `filter` is a JSON
        // *string*. It must die with the shared human-facing hint, not with
        // serde's "did not match any variant of untagged enum FilterAst".
        let s = fixture_schema();
        let t = tpl(json!({"collection":"posts","filter":"{\"status\":\"published\"}"}));
        assert!(matches!(
            validate_template(&s, &t, &[]),
            Err(TemplateError::BadShape(m)) if m == filter_shape_hint()
        ));
    }

    #[test]
    fn nested_param_inside_a_two_key_object_still_substitutes() {
        // The two-key object is NOT a substitution site, but the walk must
        // still descend into it: "dead" stays literal template text while
        // the nested `gte` operand is substituted.
        let t = json!({"score":{"$param":"dead","gte":{"$param":"live"}}});
        assert_eq!(
            referenced_params(&t),
            ["live".to_string()].into_iter().collect::<BTreeSet<_>>()
        );
        let out = substitute(&t, &args(&[("live", json!(5)), ("dead", json!(9))]), None).unwrap();
        assert_eq!(out, json!({"score":{"$param":"dead","gte":5}}));
    }

    #[test]
    fn walker_stops_at_substitution_sites_exactly_like_substitute() {
        // Both walks treat ANY single-key `$param` / `$auth` object as a
        // leaf. Descending into an invalid one would report a phantom
        // reference that substitution can never reach.
        let bad_param = json!({"a":{"$param":{"$param":"ghost"}}});
        let bad_auth = json!({"a":{"$auth":{"$param":"ghost"}}});
        assert!(referenced_params(&bad_param).is_empty());
        assert!(referenced_params(&bad_auth).is_empty());
        // …and dropping the phantom never turns an invalid template valid:
        // both still fail validation, just with the honest error.
        let s = fixture_schema();
        assert!(
            validate_template(
                &s,
                &tpl(json!({"collection":"posts","filter":bad_param})),
                &[]
            )
            .is_err()
        );
        assert!(
            validate_template(
                &s,
                &tpl(json!({"collection":"posts","filter":bad_auth})),
                &[]
            )
            .is_err()
        );
    }

    // ── resolve_args (check_args + apply_defaults) ────────────────────

    #[test]
    fn resolve_args_shape_precedes_type() {
        let specs = vec![spec("p", ParamType::Integer)];
        let a = args(&[("p", json!({"$gt": 1}))]);
        assert!(matches!(
            resolve_args(&specs, &a),
            Err(TemplateError::NotScalar(p)) if p == "p"
        ));
        let a = args(&[("p", json!("not-an-int"))]);
        assert!(matches!(
            resolve_args(&specs, &a),
            Err(TemplateError::Arg(_))
        ));
        let a = args(&[("p", json!(7))]);
        assert_eq!(resolve_args(&specs, &a).unwrap(), a);
    }

    #[test]
    fn resolve_args_unknown_key_precedes_shape() {
        // An undeclared key wins even when its value is a non-scalar —
        // the sql arm's fast typo signal (PARAM_UNKNOWN) is preserved.
        let specs = vec![spec("p", ParamType::Integer)];
        let a = args(&[("yolo", json!({"$fts": {}}))]);
        assert!(matches!(
            resolve_args(&specs, &a),
            Err(TemplateError::Arg(crate::rpc::params::ParamError::Unknown(k))) if k == "yolo"
        ));
    }

    #[test]
    fn resolve_args_mirrors_sql_arm_missing_and_null_semantics() {
        // missing + required → Missing (same as validate_and_bind)
        let specs = vec![spec("p", ParamType::Text)];
        assert!(matches!(
            resolve_args(&specs, &Map::new()),
            Err(TemplateError::Arg(crate::rpc::params::ParamError::Missing(k))) if k == "p"
        ));
        // explicit null is accepted regardless of declared type
        resolve_args(&specs, &args(&[("p", json!(null))])).unwrap();
        // REQUIRED + a declared default is STILL Missing when absent —
        // validate_and_bind's `(true, _)` arm ignores the default and the
        // two arms must not diverge.
        let mut req_default = spec("p", ParamType::Text);
        req_default.default = Some(json!("fallback"));
        assert!(matches!(
            resolve_args(&[req_default], &Map::new()),
            Err(TemplateError::Arg(crate::rpc::params::ParamError::Missing(
                _
            )))
        ));
        // optional + no default → null at substitution; nothing is filled in
        let mut bare = spec("p", ParamType::Integer);
        bare.required = false;
        assert!(resolve_args(&[bare], &Map::new()).unwrap().is_empty());
    }

    #[test]
    fn resolve_args_fills_declared_defaults_and_caller_wins() {
        // The reason validation and default-fill are ONE call: substitute
        // is mechanical, so a skipped fill silently filters on NULL.
        let mut opt = spec("p", ParamType::Integer);
        opt.required = false;
        opt.default = Some(json!(20));
        let mut bare = spec("q", ParamType::Text);
        bare.required = false;
        let filled = resolve_args(&[opt.clone(), bare], &Map::new()).unwrap();
        assert_eq!(filled.get("p"), Some(&json!(20)));
        assert_eq!(filled.get("q"), None);
        assert_eq!(
            substitute(&json!({"score":{"$param":"p"}}), &filled, None).unwrap(),
            json!({"score":20})
        );
        let filled = resolve_args(&[opt], &args(&[("p", json!(5))])).unwrap();
        assert_eq!(filled.get("p"), Some(&json!(5)));
    }

    #[test]
    fn auth_node_is_template_side_not_a_caller_arg() {
        // `$auth` needs no declaration and is not an arg key.
        let t = json!({"owner_id":{"$auth":"id"}});
        assert!(referenced_params(&t).is_empty());
        validate_template(
            &fixture_schema(),
            &tpl(json!({"collection":"posts","filter":t})),
            &[],
        )
        .unwrap();
        // a caller that tries to pass it as an arg gets the unknown-key deny
        assert!(matches!(
            resolve_args(&[], &args(&[("$auth", json!("u1"))])),
            Err(TemplateError::Arg(crate::rpc::params::ParamError::Unknown(
                _
            )))
        ));
    }

    // ── parse_template ────────────────────────────────────────────────

    #[test]
    fn parse_template_rejects_oversized_blob() {
        // Bounded BEFORE the parse: N `$param` refs × an M-byte argument is
        // a clone amplifier and the template is the only bound on N.
        let big = json!({"collection":"posts","filter":{"title":"x".repeat(MAX_TEMPLATE_BYTES)}})
            .to_string();
        assert!(big.len() > MAX_TEMPLATE_BYTES);
        assert!(matches!(
            parse_template(&big),
            Err(TemplateError::BadShape(m)) if m.contains("too large")
        ));
        // under the ceiling still parses
        parse_template(&json!({"collection":"posts","filter":{"title":"x"}}).to_string()).unwrap();
    }

    #[test]
    fn param_in_identifier_positions_fails_at_parse() {
        // `collection`, `sort.field`, `sort.dir` and `select[]` are
        // IDENTIFIER positions typed `String`, so a `$param` object cannot
        // even be stored — `$param` is an operand-only construct.
        for bad in [
            json!({"collection":{"$param":"c"}}),
            json!({"collection":"posts","sort":{"field":{"$param":"f"},"dir":"asc"}}),
            json!({"collection":"posts","sort":{"field":"title","dir":{"$param":"d"}}}),
            json!({"collection":"posts","select":[{"$param":"c"}]}),
            json!({"collection":"posts","select":{"$param":"c"}}),
        ] {
            assert!(
                matches!(
                    parse_template(&bad.to_string()),
                    Err(TemplateError::BadShape(_))
                ),
                "should not parse: {bad}"
            );
        }
        // SortSpec has NO deny_unknown_fields — it is shared verbatim with
        // /list, so do NOT add one. A stray key inside `sort` is therefore
        // IGNORED, not rejected; pinned so the tolerance stays a choice.
        let t = tpl(json!({
            "collection":"posts",
            "sort":{"field":"title","dir":"asc","$param":"d"}
        }));
        let sort = t.sort.unwrap();
        assert_eq!((sort.field.as_str(), sort.dir.as_str()), ("title", "asc"));
    }

    #[test]
    fn template_filter_schema_advertises_object_with_the_template_operands() {
        // v1.58.6 recurrence guard: a bare `Value` publishes schemars'
        // untyped "any", which strict MCP clients stringify.
        let root = serde_json::to_value(schemars::schema_for!(QueryTemplate)).unwrap();
        let f = &root["properties"]["filter"];
        assert_eq!(
            f.get("type").and_then(|t| t.as_str()),
            Some("object"),
            "filter must advertise an object schema, got {root}"
        );
        let desc = f["description"].as_str().unwrap();
        assert!(desc.contains("$param") && desc.contains("$auth"), "{desc}");
        // …and the SHARED caller-facing filter schema must NOT learn them.
        let mut g = schemars::SchemaGenerator::default();
        let shared =
            serde_json::to_value(crate::query::vector_filter::filter_arg_json_schema(&mut g))
                .unwrap();
        let shared_desc = shared["description"].as_str().unwrap();
        assert!(!shared_desc.contains("$param") && !shared_desc.contains("$auth"));
    }

    #[test]
    fn parse_template_rejects_bad_json_and_unknown_fields() {
        assert!(matches!(
            parse_template("{not json"),
            Err(TemplateError::BadShape(_))
        ));
        assert!(matches!(
            parse_template(r#"{"collection":"posts","limit":10}"#),
            Err(TemplateError::BadShape(_))
        ));
        let t = parse_template(r#"{"collection":"posts"}"#).unwrap();
        assert_eq!(t.collection, "posts");
        assert!(t.filter.is_none() && t.sort.is_none() && t.select.is_none());
    }

    // ── validate_template ─────────────────────────────────────────────

    #[test]
    fn validate_declared_vs_referenced_both_ways() {
        let s = fixture_schema();
        let t = tpl(json!({"collection":"posts","filter":{"title":{"$param":"who"}}}));
        // referenced but not declared
        assert!(matches!(
            validate_template(&s, &t, &[]),
            Err(TemplateError::UndeclaredParam(p)) if p == "who"
        ));
        // declared but not referenced
        let empty = tpl(json!({"collection":"posts","filter":{"status":"published"}}));
        assert!(matches!(
            validate_template(&s, &empty, &[spec("who", ParamType::Text)]),
            Err(TemplateError::UnusedParam(p)) if p == "who"
        ));
        // both directions satisfied
        validate_template(&s, &t, &[spec("who", ParamType::Text)]).unwrap();
    }

    #[test]
    fn validate_rejects_schema_collection_mismatch() {
        // The schema IS the binding: without this, a template naming
        // `posts` dry-compiles against whatever schema the caller passed —
        // every check below it would be about a different collection.
        let s = fixture_schema(); // name = "posts"
        let t = tpl(json!({"collection":"other","filter":{"title":"x"}}));
        assert!(matches!(
            validate_template(&s, &t, &[]),
            Err(TemplateError::BadShape(m)) if m.contains("collection mismatch")
        ));
    }

    #[test]
    fn validate_rejects_a_bad_declared_default() {
        let s = fixture_schema();
        let t = tpl(json!({"collection":"posts","filter":{"score":{"gte":{"$param":"p"}}}}));
        // wrong type for the declared param type → save-time, not call-time
        let mut wrong = spec("p", ParamType::Integer);
        wrong.required = false;
        wrong.default = Some(json!("not-an-int"));
        assert!(matches!(
            validate_template(&s, &t, &[wrong]),
            Err(TemplateError::Arg(_))
        ));
        // a structured default is the same AST-injection shape as a
        // structured argument
        let mut structured = spec("p", ParamType::Integer);
        structured.required = false;
        structured.default = Some(json!({"$gt": 1}));
        assert!(matches!(
            validate_template(&s, &t, &[structured]),
            Err(TemplateError::NotScalar(p)) if p == "p"
        ));
        // a well-typed scalar default is fine
        let mut ok = spec("p", ParamType::Integer);
        ok.required = false;
        ok.default = Some(json!(3));
        validate_template(&s, &t, &[ok]).unwrap();
    }

    #[test]
    fn in_operand_needs_a_literal_array_never_a_param() {
        // Phase 1 has no list param type: `$param` is scalar-only, so a
        // parameterised `in` dies at SAVE time, not at call time.
        let s = fixture_schema();
        let scalar_in =
            tpl(json!({"collection":"posts","filter":{"status":{"in":{"$param":"p"}}}}));
        assert!(matches!(
            validate_template(&s, &scalar_in, &[spec("p", ParamType::Text)]),
            Err(TemplateError::BadShape(_))
        ));
        // the supported shape: a LITERAL array whose elements may be params
        let literal_in = tpl(json!({
            "collection":"posts",
            "filter":{"status":{"in":[{"$param":"p"},"draft"]}}
        }));
        validate_template(&s, &literal_in, &[spec("p", ParamType::Text)]).unwrap();
    }

    #[test]
    fn validate_rejects_protected_collection() {
        let mut s = fixture_schema();
        s.name = "_system_users".into();
        let t = tpl(json!({"collection":"_system_users"}));
        assert!(matches!(
            validate_template(&s, &t, &[]),
            Err(TemplateError::BadShape(_))
        ));
    }

    #[test]
    fn validate_rejects_bad_auth_key() {
        let s = fixture_schema();
        let t = tpl(json!({"collection":"posts","filter":{"owner_id":{"$auth":"email"}}}));
        assert!(matches!(
            validate_template(&s, &t, &[]),
            Err(TemplateError::BadAuthKey(_))
        ));
    }

    #[test]
    fn validate_dry_compiles_and_rejects_unknown_field() {
        let s = fixture_schema();
        // unknown filter field
        let bad = tpl(json!({"collection":"posts","filter":{"nope":{"$param":"p"}}}));
        assert!(matches!(
            validate_template(&s, &bad, &[spec("p", ParamType::Text)]),
            Err(TemplateError::BadShape(_))
        ));
        // unknown sort field
        let bad_sort = tpl(json!({"collection":"posts","sort":{"field":"nope","dir":"asc"}}));
        assert!(matches!(
            validate_template(&s, &bad_sort, &[]),
            Err(TemplateError::BadShape(_))
        ));
        // unknown select field
        let bad_select = tpl(json!({"collection":"posts","select":["nope"]}));
        assert!(matches!(
            validate_template(&s, &bad_select, &[]),
            Err(TemplateError::BadShape(_))
        ));
        // a whole-filter `$param` substitutes to a scalar → not a FilterAst
        let scalar_filter = tpl(json!({"collection":"posts","filter":{"$param":"p"}}));
        assert!(matches!(
            validate_template(&s, &scalar_filter, &[spec("p", ParamType::Text)]),
            Err(TemplateError::BadShape(_))
        ));
        // the healthy shape compiles
        let good = tpl(json!({
            "collection":"posts",
            "filter":{"and":[{"status":"published"},{"score":{"gte":{"$param":"min"}}}]},
            "sort":{"field":"created_at","dir":"desc"},
            "select":["id","title"]
        }));
        validate_template(&s, &good, &[spec("min", ParamType::Integer)]).unwrap();
    }

    #[test]
    fn validate_rejects_auth_against_a_numeric_column() {
        // #950 T4b / #954 recurrence: `$auth` is always a TEXT user id, and
        // SQLite orders every INTEGER before every TEXT — so `score < '<uid>'`
        // saves clean and then matches EVERY row. A template author reaching
        // for "$auth" on a numeric column always means a different column.
        let s = fixture_schema();
        for f in [
            json!({"score":{"lt":{"$auth":"id"}}}),
            json!({"score":{"$auth":"id"}}),
            json!({"or":[{"title":"x"},{"score":{"eq":{"$auth":"id"}}}]}),
            json!({"score":{"in":[1,{"$auth":"id"}]}}),
        ] {
            let t = tpl(json!({"collection":"posts","filter":f}));
            assert!(
                matches!(
                    validate_template(&s, &t, &[]),
                    Err(TemplateError::BadShape(_))
                ),
                "cross-class $auth must die at save: {t:?}"
            );
        }
        // The legitimate owner pattern — a TEXT column — still saves.
        let ok = tpl(json!({"collection":"posts","filter":{"owner_id":{"$auth":"id"}}}));
        validate_template(&s, &ok, &[]).unwrap();
    }

    #[test]
    fn validate_matches_param_class_against_the_column() {
        // A `$param`'s storage class IS its DECLARED type, so the same
        // save-time class rule applies to it — one declaration away from the
        // `$auth` footgun above.
        let s = fixture_schema();
        let t = tpl(json!({"collection":"posts","filter":{"score":{"lt":{"$param":"n"}}}}));
        validate_template(&s, &t, &[spec("n", ParamType::Integer)]).unwrap();
        assert!(
            matches!(
                validate_template(&s, &t, &[spec("n", ParamType::Text)]),
                Err(TemplateError::BadShape(_))
            ),
            "a Text param compared to an INTEGER column must die at save"
        );
        // …and the mirror image on a TEXT column.
        let text = tpl(json!({"collection":"posts","filter":{"title":{"eq":{"$param":"n"}}}}));
        validate_template(&s, &text, &[spec("n", ParamType::Text)]).unwrap();
        assert!(matches!(
            validate_template(&s, &text, &[spec("n", ParamType::Integer)]),
            Err(TemplateError::BadShape(_))
        ));
    }

    #[test]
    fn validate_still_allows_an_fts_leaf() {
        // The ONE place templates diverge from policies: `$fts` is a legal
        // template leaf (it compiles through the same /list pipeline), while
        // policies refuse it. Guards the class walk from being bolted on with
        // the policy door by mistake.
        let mut s = fixture_schema();
        s.fts_indexes = vec![crate::storage::schema::FtsIndex {
            name: "main".into(),
            fields: vec!["title".into()],
            tokenizer: "trigram".into(),
        }];
        let t = tpl(json!({
            "collection":"posts",
            "filter":{"and":[{"status":"published"},{"$fts":{"index":"main","query":"hello"}}]}
        }));
        validate_template(&s, &t, &[]).unwrap();
    }

    #[test]
    fn param_in_is_null_position_is_ignored_not_rejected() {
        // Honest pin of CURRENT compiler behaviour: `is_null` accepts and
        // IGNORES its operand (vector_filter.rs `"is_null" | "is_not_null"`),
        // so a `$param` there dry-compiles fine and the arg is a dead value.
        // The spec's test-plan bullet claiming it "explodes at dry-run" does
        // not hold; nothing is injectable either way (no operand is emitted).
        let s = fixture_schema();
        let t = tpl(json!({"collection":"posts","filter":{"title":{"is_null":{"$param":"p"}}}}));
        validate_template(&s, &t, &[spec("p", ParamType::Text)]).unwrap();
    }
}
