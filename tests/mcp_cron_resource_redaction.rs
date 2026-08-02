//! v1.58 P1-4 — the `cron` resource must not carry an RPC's SQL.
//!
//! `redact_cron` stripped `payload_json` but left `last_error`, and rusqlite's
//! `SqlInputError` Display embeds the whole failing statement. A cron job whose
//! RPC fails to prepare therefore leaks, through an AUTO-FETCHABLE resource,
//! exactly the SQL that the `rpcs` resource goes out of its way to strip.

#[test]
fn redact_cron_removes_last_error_but_keeps_the_signal() {
    let mut jobs = serde_json::json!({
        "jobs": [{
            "name": "nightly",
            "schedule": "0 3 * * *",
            "payload_json": "{\"token\":\"secret\"}",
            "last_error": "near \"SELEC\": syntax error in SELECT secret_col FROM users",
            "last_status": "error"
        }]
    });
    drust::mcp::resources::redact_cron_for_test(&mut jobs);

    let j = &jobs["jobs"][0];
    assert!(
        j.get("payload_json").is_none(),
        "payload must stay stripped"
    );
    assert!(
        j.get("last_error").is_none(),
        "last_error embeds the failing SQL and must not reach an auto-fetchable resource"
    );
    assert_eq!(
        j.get("last_error_present").and_then(|v| v.as_bool()),
        Some(true),
        "the resource must still say THAT it failed, just not with what SQL"
    );
    assert_eq!(j.get("last_status").and_then(|v| v.as_str()), Some("error"));
}

#[test]
fn a_healthy_job_reports_no_error() {
    let mut jobs = serde_json::json!({
        "jobs": [{ "name": "ok", "schedule": "* * * * *", "last_error": null }]
    });
    drust::mcp::resources::redact_cron_for_test(&mut jobs);
    assert_eq!(
        jobs["jobs"][0]
            .get("last_error_present")
            .and_then(|v| v.as_bool()),
        Some(false)
    );
}
