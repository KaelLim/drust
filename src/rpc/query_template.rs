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
use crate::query::vector_filter::FilterAst;
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
    pub filter: Option<Value>,
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
/// unknown key, wrong type — becomes [`TemplateError::BadShape`].
pub fn parse_template(query_json: &str) -> Result<QueryTemplate, TemplateError> {
    serde_json::from_str(query_json).map_err(|e| TemplateError::BadShape(e.to_string()))
}

/// Every `{"$param":"<name>"}` node reachable in `filter`.
///
/// Only an object with **exactly one** key `$param` whose value is a string
/// counts — the same rule [`substitute`] applies, so the two walks cannot
/// disagree about what a substitution site is.
pub fn referenced_params(filter: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    collect_params(filter, &mut out);
    out
}

fn collect_params(node: &Value, out: &mut BTreeSet<String>) {
    match node {
        Value::Object(obj) => {
            if let Some(Value::String(name)) = single_key(obj, PARAM_KEY) {
                out.insert(name.clone());
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

/// Validate caller arguments against the declared params, in the order the
/// spec fixes: **unknown key → shape → type**.
///
/// Shape (`NotScalar`) must precede type coercion: an object argument is an
/// AST-injection attempt, not a type mismatch, and must be reported as such.
///
/// Missing / null / default handling is a verbatim mirror of the sql arm
/// (`params::validate_and_bind`): missing + required → `Arg(Missing)`;
/// missing + optional + default → the declared default is type-checked;
/// missing + optional, no default → null; an explicit null is accepted for
/// any declared type. The [`params::BoundValue`] is discarded — the query
/// arm binds through the list builder, not through rusqlite params.
pub fn check_args(specs: &[ParamSpec], args: &Map<String, Value>) -> Result<(), TemplateError> {
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

/// Fill declared defaults into a caller argument map.
///
/// [`substitute`] is mechanical — a missing argument becomes JSON null — so
/// an execution arm MUST run the args through here before substituting, or
/// an optional param carrying a `default` silently filters on NULL instead
/// of on its default. Call it AFTER [`check_args`] (which type-checks the
/// default); a caller-supplied value always wins.
pub fn apply_defaults(specs: &[ParamSpec], args: &Map<String, Value>) -> Map<String, Value> {
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
/// > [!WARNING]
/// > The result must be parsed with **strict** `serde_json::from_value::<FilterAst>`,
/// > NEVER the string-tolerant `vector_filter::parse_filter_value` — that
/// > helper re-parses a JSON *string* into structure, which would turn a
/// > scalar string argument back into operator structure and defeat the
/// > `NotScalar` gate.
///
/// Recursion is bounded by serde_json's own 128-level nesting limit, which
/// [`parse_template`] (a `from_str` parse) has already applied to every
/// template this walks.
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
/// 1. the target collection is not `_system_*` / `sqlite_*`;
/// 2. declared ↔ referenced params agree in BOTH directions;
/// 3. every `$auth` node keys on `"id"`;
/// 4. the template DRY-COMPILES: substituted with per-type dummy values it
///    parses as a [`FilterAst`] and builds through the unchanged
///    [`list_builder::build_structured_list_sql`] (no owner, no policy — a
///    structural check, not an authorization one), so a broken template dies
///    at save instead of at every call.
pub fn validate_template(
    schema: &CollectionSchema,
    tpl: &QueryTemplate,
    specs: &[ParamSpec],
) -> Result<(), TemplateError> {
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

    if let Some(f) = &tpl.filter {
        check_auth_keys(f)?;
    }

    let dummies: Map<String, Value> = specs
        .iter()
        .map(|s| (s.name.clone(), dummy_for(s.ty)))
        .collect();
    let filter = match &tpl.filter {
        Some(f) => {
            let substituted = substitute(f, &dummies, Some("dummy"))?;
            // Strict parse — see the WARNING on `substitute`.
            Some(
                serde_json::from_value::<FilterAst>(substituted)
                    .map_err(|e| TemplateError::BadShape(e.to_string()))?,
            )
        }
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
        // THE AST-injection pin: a scalar arg stays a scalar. The caller
        // must parse the substituted value with strict `from_value`, never
        // the string-tolerant `parse_filter_value`, or this string would
        // become operator structure.
        let t = json!({"$param":"p"});
        let out = substitute(&t, &args(&[("p", json!(r#"{"or":[]}"#))]), None).unwrap();
        assert_eq!(out, json!(r#"{"or":[]}"#));
        assert!(serde_json::from_value::<FilterAst>(out).is_err());
    }

    // ── check_args ────────────────────────────────────────────────────

    #[test]
    fn check_args_shape_precedes_type() {
        let specs = vec![spec("p", ParamType::Integer)];
        let a = args(&[("p", json!({"$gt": 1}))]);
        assert!(matches!(
            check_args(&specs, &a),
            Err(TemplateError::NotScalar(p)) if p == "p"
        ));
        let a = args(&[("p", json!("not-an-int"))]);
        assert!(matches!(check_args(&specs, &a), Err(TemplateError::Arg(_))));
        let a = args(&[("p", json!(7))]);
        check_args(&specs, &a).unwrap();
    }

    #[test]
    fn check_args_unknown_key_precedes_shape() {
        // An undeclared key wins even when its value is a non-scalar —
        // the sql arm's fast typo signal (PARAM_UNKNOWN) is preserved.
        let specs = vec![spec("p", ParamType::Integer)];
        let a = args(&[("yolo", json!({"$fts": {}}))]);
        assert!(matches!(
            check_args(&specs, &a),
            Err(TemplateError::Arg(crate::rpc::params::ParamError::Unknown(k))) if k == "yolo"
        ));
    }

    #[test]
    fn check_args_mirrors_sql_arm_missing_and_null_semantics() {
        // missing + required → Missing (same as validate_and_bind)
        let specs = vec![spec("p", ParamType::Text)];
        assert!(matches!(
            check_args(&specs, &Map::new()),
            Err(TemplateError::Arg(crate::rpc::params::ParamError::Missing(k))) if k == "p"
        ));
        // explicit null is accepted regardless of declared type
        check_args(&specs, &args(&[("p", json!(null))])).unwrap();
        // optional + default → the default is type-checked, not the absence
        let mut opt = spec("p", ParamType::Integer);
        opt.required = false;
        opt.default = Some(json!(20));
        check_args(&[opt], &Map::new()).unwrap();
        // optional + no default → null
        let mut bare = spec("p", ParamType::Integer);
        bare.required = false;
        check_args(&[bare], &Map::new()).unwrap();
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
            check_args(&[], &args(&[("$auth", json!("u1"))])),
            Err(TemplateError::Arg(crate::rpc::params::ParamError::Unknown(
                _
            )))
        ));
    }

    #[test]
    fn apply_defaults_fills_declared_defaults_only() {
        let mut opt = spec("p", ParamType::Integer);
        opt.required = false;
        opt.default = Some(json!(20));
        let filled = apply_defaults(&[opt.clone(), spec("q", ParamType::Text)], &Map::new());
        assert_eq!(filled.get("p"), Some(&json!(20)));
        assert_eq!(filled.get("q"), None);
        // a caller-supplied value always wins over the default
        let filled = apply_defaults(&[opt], &args(&[("p", json!(5))]));
        assert_eq!(filled.get("p"), Some(&json!(5)));
    }

    // ── parse_template ────────────────────────────────────────────────

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
