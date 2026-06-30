//! gh-style device flow (design §4.2). start/poll are unauthenticated; the device_code is the bearer.
use crate::client::http::DrustClient;

#[derive(Debug, PartialEq)]
pub enum PollDecision {
    Keep { interval_secs: u64 },
    SlowDown { interval_secs: u64 },
    Approved(String),
    Denied,
    Expired,
}

pub fn decide(status: &str, token: Option<&str>, interval_secs: u64) -> PollDecision {
    match status {
        "approved" => token
            .map(|t| PollDecision::Approved(t.to_string()))
            .unwrap_or(PollDecision::Expired),
        "slow_down" => PollDecision::SlowDown {
            interval_secs: interval_secs + 5,
        },
        "denied" => PollDecision::Denied,
        "expired" => PollDecision::Expired,
        _ => PollDecision::Keep { interval_secs },
    }
}

pub struct DeviceGrant {
    pub token: String,
    pub expires_at: Option<String>,
    pub consoles: Option<serde_json::Value>,
}

pub async fn run_device_flow(
    base_url: &str,
    client_name: &str,
    open_browser: bool,
) -> anyhow::Result<DeviceGrant> {
    let c = DrustClient::anonymous(base_url);
    let start = c
        .post_unauth(
            "/auth/cli/device/start",
            serde_json::json!({"client_name": client_name}),
        )
        .await
        .map_err(|e| anyhow::anyhow!("device/start failed: {e}"))?;
    let device_code = start["device_code"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no device_code"))?
        .to_string();
    let user_code = start["user_code"].as_str().unwrap_or("");
    let uri = start["verification_uri_complete"]
        .as_str()
        .or_else(|| start["verification_uri"].as_str())
        .unwrap_or("");
    let mut interval = start["interval"].as_u64().unwrap_or(5);
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(start["expires_in"].as_u64().unwrap_or(900));
    eprintln!("First copy your one-time code: {user_code}");
    eprintln!("Then open in your browser: {uri}");
    if open_browser {
        let _ = open::that(uri);
    }
    loop {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("device code expired before approval");
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        let poll = c
            .post_unauth(
                "/auth/cli/device/poll",
                serde_json::json!({"device_code": device_code}),
            )
            .await
            .map_err(|e| anyhow::anyhow!("device/poll failed: {e}"))?;
        match decide(
            poll["status"].as_str().unwrap_or("pending"),
            poll["access_token"].as_str(),
            interval,
        ) {
            PollDecision::Approved(token) => {
                return Ok(DeviceGrant {
                    token,
                    expires_at: poll["expires_at"].as_str().map(str::to_string),
                    consoles: poll.get("consoles").cloned(),
                });
            }
            PollDecision::Denied => anyhow::bail!("authorization denied"),
            PollDecision::Expired => anyhow::bail!("device code expired"),
            PollDecision::SlowDown { interval_secs } => interval = interval_secs,
            PollDecision::Keep { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_decision_covers_rfc8628() {
        use PollDecision::*;
        assert!(matches!(decide("pending", None, 5), Keep { interval_secs: 5 }));
        assert!(matches!(
            decide("slow_down", None, 5),
            SlowDown { interval_secs: 10 }
        ));
        assert!(matches!(
            decide("approved", Some("drust_pat_cli_x"), 5),
            Approved(_)
        ));
        assert!(matches!(decide("approved", None, 5), Expired)); // fail closed
        assert!(matches!(decide("denied", None, 5), Denied));
        assert!(matches!(decide("expired", None, 5), Expired));
        assert!(matches!(decide("garbage", None, 7), Keep { interval_secs: 7 }));
    }
}
