//! Thin reqwest wrapper. Joins root-relative paths onto base_url verbatim (no base_path logic).
use crate::client::error::ApiError;
use reqwest::Method;

pub struct DrustClient {
    base_url: String,
    token: String,
    inner: reqwest::Client,
}

/// Client that refuses an https→http redirect downgrade (review M5): reqwest
/// preserves the Authorization header across a same-host redirect, so a 3xx to
/// http:// would leak the bearer/PAT over cleartext. Bounded to 10 hops.
fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let downgrade = attempt
                .previous()
                .last()
                .map(|prev| prev.scheme() == "https" && attempt.url().scheme() == "http")
                .unwrap_or(false);
            if downgrade {
                attempt.error("refusing https->http redirect downgrade")
            } else if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

impl DrustClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> DrustClient {
        DrustClient {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            inner: build_client(),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn req(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.inner
            .request(method, self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .header("accept", "application/json")
    }

    async fn run(&self, rb: reqwest::RequestBuilder) -> Result<serde_json::Value, ApiError> {
        let resp = rb.send().await.map_err(net_err)?;
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if (200..300).contains(&status) {
            Ok(body)
        } else {
            Err(ApiError::from_body(status, &body))
        }
    }

    pub async fn get(&self, path: &str) -> Result<serde_json::Value, ApiError> {
        self.run(self.req(Method::GET, path)).await
    }

    pub async fn send_json(
        &self,
        method: Method,
        path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.run(self.req(method, path).json(&body)).await
    }

    /// Returns the parsed 2xx body (review M7 — callers such as `auth logout`
    /// need to inspect e.g. `{"revoked":false}`; value-ignoring callers keep
    /// using `Ok(_)`).
    pub async fn delete(&self, path: &str) -> Result<serde_json::Value, ApiError> {
        let resp = self
            .req(Method::DELETE, path)
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if (200..300).contains(&status) {
            Ok(body)
        } else {
            Err(ApiError::from_body(status, &body))
        }
    }

    pub async fn multipart(
        &self,
        path: &str,
        form: reqwest::multipart::Form,
    ) -> Result<serde_json::Value, ApiError> {
        self.run(self.req(Method::POST, path).multipart(form)).await
    }

    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>, ApiError> {
        let resp = self.req(Method::GET, path).send().await.map_err(net_err)?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(resp.bytes().await.map_err(net_err)?.to_vec())
        } else {
            let body = resp.json().await.unwrap_or(serde_json::Value::Null);
            Err(ApiError::from_body(status, &body))
        }
    }

    /// Token-less client for the device flow (the `device_code` is the pending-grant bearer).
    pub fn anonymous(base_url: impl Into<String>) -> DrustClient {
        DrustClient::new(base_url, "")
    }

    /// Device start/poll are unauthenticated (the device_code is the pending-grant bearer, RFC 8628).
    pub async fn post_unauth(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.run(
            self.inner
                .post(self.url(path))
                .header("accept", "application/json")
                .json(&body),
        )
        .await
    }

    /// Form POST that does NOT follow redirects — backups restore answers 303 → inspect?dest=…
    pub async fn post_form_capture_redirect(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<RedirectInfo, ApiError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(net_err)?;
        let resp = client
            .post(self.url(path))
            .header("authorization", format!("Bearer {}", self.token))
            .form(form)
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status().as_u16();
        if status == 302 || status == 303 {
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            Ok(RedirectInfo { status, location })
        } else if (200..300).contains(&status) {
            Ok(RedirectInfo {
                status,
                location: String::new(),
            })
        } else {
            Err(ApiError::from_body(
                status,
                &resp.json().await.unwrap_or(serde_json::Value::Null),
            ))
        }
    }
}

#[derive(Debug)]
pub struct RedirectInfo {
    pub status: u16,
    pub location: String,
}

fn net_err(e: reqwest::Error) -> ApiError {
    ApiError {
        status: 0,
        error_code: "NETWORK".into(),
        message: e.to_string(),
        suggested_fix: None,
        error_aliases: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_joins_verbatim_without_touching_base_path() {
        let c = DrustClient::new("https://tool.tzuchi-org.tw/drust", "drust_pat_cli_x");
        assert_eq!(
            c.url("/t/9f/collections"),
            "https://tool.tzuchi-org.tw/drust/t/9f/collections"
        );
        // Cloud root mode (empty base_path) must also be verbatim:
        let c2 = DrustClient::new("https://drust.com", "drust_pat_cli_x");
        assert_eq!(
            c2.url("/t/9f/collections"),
            "https://drust.com/t/9f/collections"
        );
    }

    #[test]
    fn anonymous_omits_bearer() {
        // The device-flow client carries no token; url() still joins verbatim.
        let c = DrustClient::anonymous("https://x/drust");
        assert_eq!(
            c.url("/auth/cli/device/start"),
            "https://x/drust/auth/cli/device/start"
        );
    }
}
