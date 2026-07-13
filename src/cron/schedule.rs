//! Pure schedule math over 5-field cron expressions (UTC). All scheduler
//! decisions route through these three functions so they stay unit-testable
//! without a clock or a tokio runtime.

use chrono::{DateTime, Utc};

#[derive(Debug)]
pub enum ScheduleError {
    NotFiveFields,
    Invalid(String),
}

fn parse(expr: &str) -> Result<croner::Cron, ScheduleError> {
    // Strict 5-field gate BEFORE croner: rejects `@aliases`, seconds and
    // year variants regardless of what croner's optional-field parser allows.
    if expr.split_whitespace().count() != 5 {
        return Err(ScheduleError::NotFiveFields);
    }
    croner::parser::CronParser::new()
        .parse(expr)
        .map_err(|e| ScheduleError::Invalid(e.to_string()))
}

pub fn validate_schedule(expr: &str) -> Result<(), ScheduleError> {
    parse(expr).map(|_| ())
}

/// Does `expr` fire at exactly this UTC minute? Fail-closed: any parse or
/// evaluation error is `false` (create-time validation is the loud gate).
pub fn is_due(expr: &str, minute_utc: DateTime<Utc>) -> bool {
    match parse(expr) {
        Ok(c) => c.is_time_matching(&minute_utc).unwrap_or(false),
        Err(_) => false,
    }
}

/// Next occurrence strictly after `after_utc`, minute resolution, or None.
pub fn next_fire(expr: &str, after_utc: DateTime<Utc>) -> Option<String> {
    let c = parse(expr).ok()?;
    let next = c.find_next_occurrence(&after_utc, false).ok()?;
    Some(next.format("%Y-%m-%dT%H:%MZ").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn m(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
    }

    #[test]
    fn validate_accepts_standard_five_field() {
        for e in [
            "* * * * *",
            "*/15 * * * *",
            "30 3 * * *",
            "0 */6 * * 1-5",
            "0 0 1 1 *",
        ] {
            assert!(validate_schedule(e).is_ok(), "{e} should be valid");
        }
    }

    #[test]
    fn validate_rejects_wrong_field_count_and_aliases() {
        for e in [
            "* * * *",
            "* * * * * *",
            "@daily",
            "",
            "  ",
            "0 0 * * * 2026",
        ] {
            assert!(validate_schedule(e).is_err(), "{e} should be rejected");
        }
    }

    #[test]
    fn validate_rejects_garbage_fields() {
        for e in [
            "61 * * * *",
            "* 25 * * *",
            "* * 32 * *",
            "* * * 13 *",
            "* * * * 8",
            "foo * * * *",
        ] {
            assert!(validate_schedule(e).is_err(), "{e} should be rejected");
        }
    }

    #[test]
    fn is_due_matches_quarter_hours() {
        assert!(is_due("*/15 * * * *", m(2026, 7, 13, 8, 0)));
        assert!(is_due("*/15 * * * *", m(2026, 7, 13, 8, 45)));
        assert!(!is_due("*/15 * * * *", m(2026, 7, 13, 8, 7)));
    }

    #[test]
    fn is_due_daily_at_0330() {
        assert!(is_due("30 3 * * *", m(2026, 7, 13, 3, 30)));
        assert!(!is_due("30 3 * * *", m(2026, 7, 13, 3, 31)));
    }

    #[test]
    fn is_due_weekday_range() {
        // 2026-07-13 is a Monday
        assert!(is_due("0 9 * * 1-5", m(2026, 7, 13, 9, 0)));
        assert!(!is_due("0 9 * * 1-5", m(2026, 7, 12, 9, 0))); // Sunday
    }

    #[test]
    fn is_due_parse_error_is_false() {
        assert!(!is_due("not a cron", m(2026, 7, 13, 0, 0)));
    }

    #[test]
    fn next_fire_formats_utc_minute() {
        assert_eq!(
            next_fire("30 3 * * *", m(2026, 7, 13, 4, 0)).as_deref(),
            Some("2026-07-14T03:30Z")
        );
        assert!(next_fire("garbage", m(2026, 7, 13, 4, 0)).is_none());
    }
}
