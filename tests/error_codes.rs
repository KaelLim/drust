use drust::error::{ErrorCode, ToolError};

#[test]
fn codes_serialize_as_screaming_snake() {
    let e = ToolError::new(ErrorCode::Unauthenticated, "no token");
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["code"], "UNAUTHENTICATED");
    assert_eq!(json["message"], "no token");
}

#[test]
fn optional_details_round_trip() {
    let e = ToolError::new(ErrorCode::QueryForbidden, "ATTACH denied")
        .with_details(serde_json::json!({"action": "ATTACH"}));
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["code"], "QUERY_FORBIDDEN");
    assert_eq!(json["details"]["action"], "ATTACH");
}

#[test]
fn all_codes_round_trip() {
    for code in [
        ErrorCode::UnknownField,
        ErrorCode::TypeMismatch,
        ErrorCode::UnknownCollection,
        ErrorCode::QueryForbidden,
        ErrorCode::QueryTimeout,
        ErrorCode::QueryTooLarge,
        ErrorCode::QuotaExceeded,
        ErrorCode::RateLimited,
        ErrorCode::TenantNotFound,
        ErrorCode::Unauthenticated,
        ErrorCode::Internal,
    ] {
        let e = ToolError::new(code, "x");
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(&format!("\"{}\"", serde_json::to_string(&code).unwrap().trim_matches('"'))));
    }
}
