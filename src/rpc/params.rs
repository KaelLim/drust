//! RPC parameter schema and request validation.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    Text,
    Integer,
    Real,
    Boolean,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ParamSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: ParamType,
    #[serde(default = "default_required")]
    pub required: bool,
    #[serde(default)]
    pub default: Option<Json>,
}

fn default_required() -> bool {
    true
}

#[derive(Debug, thiserror::Error)]
pub enum ParamError {
    #[error("missing required param: '{0}'")]
    Missing(String),
    #[error("type mismatch on param '{name}': expected {expected:?}, got {got}")]
    TypeMismatch { name: String, expected: ParamType, got: String },
    #[error("unknown param '{0}' in body — not declared on this RPC")]
    Unknown(String),
    #[error("invalid params_json on stored RPC: {0}")]
    BadParamsJson(String),
}

pub fn parse_params_json(s: &str) -> Result<Vec<ParamSpec>, ParamError> {
    serde_json::from_str(s).map_err(|e| ParamError::BadParamsJson(e.to_string()))
}

/// Validate an incoming JSON body against a declared param list and
/// return a name → SQL-typed value map ready to bind.
///
/// Strict in both directions: missing required → `Missing`; extra
/// undeclared keys → `Unknown`; type mismatch → `TypeMismatch`.
pub fn validate_and_bind(
    declared: &[ParamSpec],
    body: &serde_json::Map<String, Json>,
) -> Result<BTreeMap<String, BoundValue>, ParamError> {
    // Reject any extra keys first so users get a fast typo signal.
    for k in body.keys() {
        if !declared.iter().any(|p| &p.name == k) {
            return Err(ParamError::Unknown(k.clone()));
        }
    }

    let mut bound = BTreeMap::new();
    for spec in declared {
        let value = match body.get(&spec.name) {
            Some(v) => v.clone(),
            None => match (spec.required, &spec.default) {
                (true, _) => return Err(ParamError::Missing(spec.name.clone())),
                (false, Some(d)) => d.clone(),
                (false, None) => Json::Null,
            },
        };
        bound.insert(spec.name.clone(), coerce(spec, &value)?);
    }
    Ok(bound)
}

#[derive(Debug, Clone)]
pub enum BoundValue {
    Text(String),
    Int(i64),
    Real(f64),
    Bool(bool),
    Null,
}

fn coerce(spec: &ParamSpec, v: &Json) -> Result<BoundValue, ParamError> {
    let mismatch = |got: &str| ParamError::TypeMismatch {
        name: spec.name.clone(),
        expected: spec.ty,
        got: got.to_string(),
    };
    match (spec.ty, v) {
        (_, Json::Null) => Ok(BoundValue::Null),
        (ParamType::Text, Json::String(s)) => Ok(BoundValue::Text(s.clone())),
        (ParamType::Integer, Json::Number(n)) => n
            .as_i64()
            .map(BoundValue::Int)
            .ok_or_else(|| mismatch("non-integer number")),
        (ParamType::Real, Json::Number(n)) => n
            .as_f64()
            .map(BoundValue::Real)
            .ok_or_else(|| mismatch("non-finite number")),
        (ParamType::Boolean, Json::Bool(b)) => Ok(BoundValue::Bool(*b)),
        (_, Json::String(_))  => Err(mismatch("string")),
        (_, Json::Number(_))  => Err(mismatch("number")),
        (_, Json::Bool(_))    => Err(mismatch("boolean")),
        (_, Json::Array(_))   => Err(mismatch("array")),
        (_, Json::Object(_))  => Err(mismatch("object")),
    }
}

impl BoundValue {
    pub fn to_sql(&self) -> rusqlite::types::Value {
        use rusqlite::types::Value;
        match self {
            BoundValue::Text(s) => Value::Text(s.clone()),
            BoundValue::Int(i) => Value::Integer(*i),
            BoundValue::Real(r) => Value::Real(*r),
            BoundValue::Bool(b) => Value::Integer(*b as i64),
            BoundValue::Null => Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec(name: &str, ty: ParamType, required: bool) -> ParamSpec {
        ParamSpec { name: name.into(), ty, required, default: None }
    }

    #[test]
    fn missing_required_errors() {
        let specs = vec![spec("active", ParamType::Boolean, true)];
        let body = serde_json::Map::new();
        let err = validate_and_bind(&specs, &body).unwrap_err();
        matches!(err, ParamError::Missing(s) if s == "active");
    }

    #[test]
    fn missing_optional_falls_to_default() {
        let mut s = spec("limit", ParamType::Integer, false);
        s.default = Some(json!(20));
        let body = serde_json::Map::new();
        let bound = validate_and_bind(&[s], &body).unwrap();
        match bound.get("limit").unwrap() {
            BoundValue::Int(20) => {}
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn missing_optional_no_default_is_null() {
        let s = spec("note", ParamType::Text, false);
        let body = serde_json::Map::new();
        let bound = validate_and_bind(&[s], &body).unwrap();
        matches!(bound.get("note").unwrap(), BoundValue::Null);
    }

    #[test]
    fn type_mismatch_errors() {
        let specs = vec![spec("active", ParamType::Boolean, true)];
        let mut body = serde_json::Map::new();
        body.insert("active".into(), json!("yes"));
        let err = validate_and_bind(&specs, &body).unwrap_err();
        matches!(err, ParamError::TypeMismatch { .. });
    }

    #[test]
    fn unknown_param_errors() {
        let specs = vec![spec("active", ParamType::Boolean, true)];
        let mut body = serde_json::Map::new();
        body.insert("active".into(), json!(true));
        body.insert("yolo".into(), json!(42));
        let err = validate_and_bind(&specs, &body).unwrap_err();
        matches!(err, ParamError::Unknown(s) if s == "yolo");
    }

    #[test]
    fn null_is_accepted_regardless_of_declared_type() {
        let specs = vec![spec("note", ParamType::Text, true)];
        let mut body = serde_json::Map::new();
        body.insert("note".into(), json!(null));
        let bound = validate_and_bind(&specs, &body).unwrap();
        matches!(bound.get("note").unwrap(), BoundValue::Null);
    }

    #[test]
    fn integer_overflow_yields_mismatch() {
        let specs = vec![spec("n", ParamType::Integer, true)];
        let mut body = serde_json::Map::new();
        body.insert("n".into(), json!(1.5));
        let err = validate_and_bind(&specs, &body).unwrap_err();
        matches!(err, ParamError::TypeMismatch { .. });
    }
}
