//! Thin reqwest wrapper. Joins root-relative paths onto base_url verbatim (no base_path logic).
use crate::client::error::ApiError;
use reqwest::Method;

pub struct DrustClient {
    base_url: String,
    token: String,
    inner: reqwest::Client,
}

impl DrustClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> DrustClient {
        DrustClient {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            inner: reqwest::Client::new(),
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

    pub async fn delete(&self, path: &str) -> Result<(), ApiError> {
        let resp = self.req(Method::DELETE, path).send().await.map_err(net_err)?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            let body = resp.json().await.unwrap_or(serde_json::Value::Null);
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
        assert_eq!(c.url("/t/9f/collections"), "https://tool.tzuchi-org.tw/drust/t/9f/collections");
        // Cloud root mode (empty base_path) must also be verbatim:
        let c2 = DrustClient::new("https://drust.com", "drust_pat_cli_x");
        assert_eq!(c2.url("/t/9f/collections"), "https://drust.com/t/9f/collections");
    }
}
