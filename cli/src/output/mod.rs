//! Output rendering: `Human` (tables/keyed lines) vs `Json` (server JSON passthrough).
use crate::client::error::ApiError;

pub enum Renderer {
    Human,
    Json,
}

impl Renderer {
    /// Explicit `--json`/`--output` wins; otherwise auto-Json when stdout is not a TTY (D-13).
    pub fn resolve(json_flag: bool, output: Option<&str>, stdout_is_tty: bool) -> Renderer {
        if json_flag || output == Some("json") {
            return Renderer::Json;
        }
        if output == Some("human") {
            return Renderer::Human;
        }
        if stdout_is_tty {
            Renderer::Human
        } else {
            Renderer::Json
        }
    }

    /// Render a success JSON value. Json = passthrough; Human = pretty.
    pub fn value(&self, v: &serde_json::Value) {
        match self {
            Renderer::Json => println!("{}", serde_json::to_string(v).unwrap()),
            Renderer::Human => println!("{}", serde_json::to_string_pretty(v).unwrap()),
        }
    }

    /// Render an error to stderr; surface `suggested_fix` verbatim in Human mode.
    pub fn error(&self, e: &ApiError) {
        match self {
            Renderer::Json => {
                let mut obj = serde_json::Map::new();
                obj.insert("error_code".into(), e.error_code.clone().into());
                obj.insert("message".into(), e.message.clone().into());
                if let Some(fix) = &e.suggested_fix {
                    obj.insert("suggested_fix".into(), fix.clone().into());
                }
                eprintln!(
                    "{}",
                    serde_json::to_string(&serde_json::Value::Object(obj)).unwrap()
                );
            }
            Renderer::Human => {
                eprintln!("error: {}", e.message);
                eprintln!("  code: {}", e.error_code);
                if let Some(fix) = &e.suggested_fix {
                    eprintln!("  hint: {fix}");
                }
            }
        }
    }

    /// Render rows as a table (Human) or a JSON array (Json).
    pub fn table(&self, rows: &[serde_json::Value], cols: &[&str]) {
        if let Renderer::Json = self {
            let arr = serde_json::Value::Array(rows.to_vec());
            println!("{}", serde_json::to_string(&arr).unwrap());
            return;
        }
        println!("{}", cols.join("\t"));
        for r in rows {
            let line: Vec<String> = cols
                .iter()
                .map(|c| match r.get(*c) {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(v) => v.to_string(),
                    None => String::new(),
                })
                .collect();
            println!("{}", line.join("\t"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_picks_json_when_flag_or_piped() {
        assert!(matches!(
            Renderer::resolve(true, None, true),
            Renderer::Json
        )); // --json wins on a TTY
        assert!(matches!(
            Renderer::resolve(false, Some("json"), true),
            Renderer::Json
        ));
        assert!(matches!(
            Renderer::resolve(false, None, false),
            Renderer::Json
        )); // piped → auto json
        assert!(matches!(
            Renderer::resolve(false, None, true),
            Renderer::Human
        )); // interactive default
    }
}
