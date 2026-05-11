//! Profile encoding/decoding helpers shared by REST + MCP user paths.
//!
//! `_system_users.profile` is stored as TEXT (JSON-encoded). Different
//! clients send the field with different shapes:
//!
//! - Native MCP / well-formed REST: `Value::Object` / `Value::Array` etc.
//! - Older or hand-rolled clients: pre-stringified JSON, arriving as
//!   `Value::String("{\"kind\":\"x\"}")`.
//!
//! Without normalisation, the string-of-JSON path double-encodes on
//! INSERT and the read path surfaces a string instead of the structure
//! the client meant. These helpers make the round-trip idempotent.
//!
//! Round-trip rules:
//! - `Object/Array/Number/Bool/Null` → JSON-encoded, decoded back to same kind.
//! - `String(s)` where `s` parses as JSON object/array → stored as inner JSON,
//!   decoded back to that object/array.
//! - `String(s)` where `s` is just a plain string (not JSON) → stored
//!   as quoted JSON string, decoded back to the same plain string.
//!
//! The second rule treats `"{\"k\":\"v\"}"` and `{"k":"v"}` as the same
//! intent — the underlying truth is the structured object.
use serde_json::Value;

/// Encode a client-supplied `profile` value to the TEXT form stored in
/// `_system_users.profile`. Returns `None` for absent values.
pub fn encode(v: Option<&Value>) -> Option<String> {
    let v = v?;
    Some(match v {
        Value::String(s) => match serde_json::from_str::<Value>(s) {
            // Inner JSON is structured — store the inner form so it round-trips.
            // Plain strings (parse to Value::String) fall through to quoted form.
            Ok(inner) if !inner.is_string() => inner.to_string(),
            _ => v.to_string(),
        },
        _ => v.to_string(),
    })
}

/// Decode the TEXT form read from `_system_users.profile`. Returns
/// `Value::Null` for absent or malformed values. If the parsed value is
/// itself a JSON-encoded string (legacy double-encoded rows), parses one
/// more level so the client sees a structured object.
pub fn decode(raw: Option<&str>) -> Value {
    let Some(s) = raw else { return Value::Null };
    let v = match serde_json::from_str::<Value>(s) {
        Ok(v) => v,
        Err(_) => return Value::Null,
    };
    // Heal legacy double-encoded rows: inner string that is itself JSON
    // surfaces as the underlying structure.
    if let Value::String(inner) = &v
        && let Ok(deeper) = serde_json::from_str::<Value>(inner)
        && !deeper.is_string()
    {
        return deeper;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rt(v: Value) -> Value {
        let encoded = encode(Some(&v));
        decode(encoded.as_deref())
    }

    #[test]
    fn object_round_trips() {
        let v = json!({"kind": "x", "n": 1});
        assert_eq!(rt(v.clone()), v);
    }

    #[test]
    fn array_round_trips() {
        let v = json!([1, 2, "three"]);
        assert_eq!(rt(v.clone()), v);
    }

    #[test]
    fn plain_string_round_trips_as_string() {
        let v = json!("hello world");
        assert_eq!(rt(v.clone()), v);
    }

    #[test]
    fn stringified_object_round_trips_as_object() {
        // Client double-encoded — we recover the structure.
        let v = Value::String(r#"{"kind":"x","n":1}"#.to_string());
        let want = json!({"kind": "x", "n": 1});
        assert_eq!(rt(v), want);
    }

    #[test]
    fn stringified_array_round_trips_as_array() {
        let v = Value::String("[1,2,3]".to_string());
        let want = json!([1, 2, 3]);
        assert_eq!(rt(v), want);
    }

    #[test]
    fn null_passes_through() {
        assert_eq!(encode(None), None);
        assert_eq!(decode(None), Value::Null);
    }

    #[test]
    fn legacy_double_encoded_row_heals_on_read() {
        // A row written by the pre-fix code path: object .to_string()'d twice.
        let buggy_storage = r#""{\"kind\":\"x\"}""#; // outer quotes + escaped inner
        assert_eq!(decode(Some(buggy_storage)), json!({"kind": "x"}));
    }

    #[test]
    fn malformed_decodes_to_null() {
        assert_eq!(decode(Some("not json")), Value::Null);
    }
}
