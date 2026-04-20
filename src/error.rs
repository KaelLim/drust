use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    UnknownField,
    TypeMismatch,
    UnknownCollection,
    QueryForbidden,
    QueryTimeout,
    QueryTooLarge,
    QuotaExceeded,
    RateLimited,
    TenantNotFound,
    Unauthenticated,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), details: None }
    }
    pub fn with_details(mut self, v: serde_json::Value) -> Self {
        self.details = Some(v);
        self
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ToolError {}
