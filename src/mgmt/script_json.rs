//! HTML-`<script>`-safe JSON serialization — single canonical escaper.
//!
//! Inlining JSON into an HTML `<script>` element is unsafe: the HTML
//! tokenizer closes the element on the literal byte sequence `</script>`
//! (case-insensitive, regardless of `type=`), and `<!--` opens a comment
//! state — both let attacker-controlled string values inside the JSON break
//! out of the script context (stored XSS). U+2028 / U+2029 are valid JSON
//! but are ECMAScript line terminators that break inline-JS parsing.
//!
//! Everything we emit stays valid JSON — `\/`, ` `, ` ` are all
//! legal per RFC 8259 section 7 and `JSON.parse` decodes them identically —
//! so the escaping is invisible to well-behaved consumers and neutralizing to
//! hostile ones. This is the ONE canonical escaper: do not re-inline the
//! `.replace("</", ...)` dance at call sites.

use serde::Serialize;

/// Neutralize `<script>`-breakout sequences in an already-serialized JSON
/// (or any) string. Use when the caller owns serialization and needs a
/// shape-specific fallback (e.g. the audit producer defaulting to `[]`).
pub fn escape_json_for_script(json: &str) -> String {
    json.replace("</", "<\\/")
        .replace("<!--", "<\\!--")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Serialize `value` to script-safe JSON in one step. On the (practically
/// impossible) serialization error returns the JSON literal `null` — a valid
/// JS expression, unlike an empty string which would yield `const x = ;`.
pub fn json_for_script<T: Serialize + ?Sized>(value: &T) -> String {
    let json = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    escape_json_for_script(&json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::tools::schema::FieldSpec;

    #[test]
    fn escapes_script_closer_and_comment_open() {
        let safe = escape_json_for_script(r#"</script><!--x--></SCRIPT>"#);
        assert!(!safe.contains("</"), "raw `</` must be gone: {safe}");
        assert!(!safe.contains("<!--"), "raw `<!--` must be gone: {safe}");
        assert!(
            safe.contains("<\\/script>"),
            "closer must become <\\/script>: {safe}"
        );
        assert!(
            safe.contains("<\\/SCRIPT>"),
            "closer is case-insensitive: {safe}"
        );
    }

    #[test]
    fn escapes_line_and_paragraph_separators() {
        let safe = escape_json_for_script("a\u{2028}b\u{2029}c");
        assert!(!safe.contains('\u{2028}'), "U+2028 must be gone: {safe:?}");
        assert!(!safe.contains('\u{2029}'), "U+2029 must be gone: {safe:?}");
        assert!(
            safe.contains("\\u2028") && safe.contains("\\u2029"),
            "got: {safe:?}"
        );
    }

    #[test]
    fn json_for_script_neutralizes_hostile_field_description() {
        let fields = vec![FieldSpec {
            name: "note".into(),
            sql_type: "text".into(),
            nullable: true,
            unique: false,
            default_value: None,
            foreign_key: None,
            dim: None,
            description: Some("</script><img src=x onerror=alert(1)>".into()),
            ..Default::default()
        }];
        let out = json_for_script(&fields);
        assert!(!out.contains("</script>"), "live closer leaked: {out}");
        assert!(out.contains("<\\/script>"), "closer not escaped: {out}");
        // Lossless: re-parses to the exact original description.
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed[0]["description"],
            "</script><img src=x onerror=alert(1)>"
        );
    }

    #[test]
    fn json_for_script_serialize_failure_yields_valid_js_literal() {
        // Practically unreachable for our types, but the fallback must never be
        // an empty string (which would render `const x = ;` — a JS syntax error).
        assert_eq!(
            json_for_script(&serde_json::json!({"ok": true})),
            r#"{"ok":true}"#
        );
    }
}
