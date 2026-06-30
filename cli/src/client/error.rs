//! Parsed drust error envelope: `{error_code, message, suggested_fix?, error_aliases?}`
//! (`src/error.rs` on the server). `suggested_fix`/`error_aliases` are absent keys, never null.

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub error_code: String,
    pub message: String,
    pub suggested_fix: Option<String>,
    pub error_aliases: Vec<String>,
}

impl ApiError {
    pub fn from_body(status: u16, body: &serde_json::Value) -> ApiError {
        let s = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
        ApiError {
            status,
            error_code: s("error_code").unwrap_or_else(|| format!("HTTP_{status}")),
            message: s("message").unwrap_or_else(|| "request failed".into()),
            suggested_fix: s("suggested_fix"),
            error_aliases: body
                .get("error_aliases")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// Exit code contract (spec §7.3): 1=4xx app, 2=401(→login), 3=5xx/network, 0=ok.
    pub fn exit_code(&self) -> i32 {
        match self.status {
            401 => 2,
            s if (400..500).contains(&s) => 1,
            _ => 3,
        }
    }

    /// True if the canonical code OR any alias equals `code`.
    pub fn matches(&self, code: &str) -> bool {
        self.error_code == code || self.error_aliases.iter().any(|a| a == code)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.error_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_envelope_and_maps_exit_codes() {
        let e = ApiError::from_body(
            403,
            &json!({
                "error_code": "WRITE_DENIED",
                "message": "service key required",
                "error_aliases": ["SERVICE_REQUIRED"]
            }),
        );
        assert_eq!(e.error_code, "WRITE_DENIED");
        assert_eq!(e.message, "service key required");
        assert_eq!(e.suggested_fix, None); // missing key, never null
        assert!(e.matches("WRITE_DENIED"));
        assert!(e.matches("SERVICE_REQUIRED")); // alias also matches
        assert!(!e.matches("OTHER"));
        assert_eq!(e.exit_code(), 1); // generic 4xx

        let unauth =
            ApiError::from_body(401, &json!({"error_code":"HTTP_401","message":"no token"}));
        assert_eq!(unauth.exit_code(), 2); // 401 → "run drust auth login"

        let server = ApiError::from_body(500, &json!({"error_code":"DB_ERROR","message":"boom"}));
        assert_eq!(server.exit_code(), 3); // 5xx
    }
}
