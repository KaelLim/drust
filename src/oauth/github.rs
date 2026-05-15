//! GitHub OAuth 2.0 adapter (not OIDC). Three round trips:
//! 1. exchange code for access_token
//! 2. GET /user/emails -> pick primary+verified
//! 3. GET /user -> numeric id (used as provider_user_id for v1.12)

use crate::oauth::provider::{OauthError, OauthProvider, VerifiedUser};
use serde::Deserialize;
use std::pin::Pin;

pub struct GitHubAdapter {
    client_id: String,
    client_secret: String,
    authorize_endpoint: String,
    token_endpoint: String,
    api_base: String,
    http: reqwest::Client,
}

impl GitHubAdapter {
    pub fn new(
        client_id: String,
        client_secret: String,
        authorize_endpoint: String,
        token_endpoint: String,
        api_base: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            authorize_endpoint,
            token_endpoint,
            api_base,
            http: reqwest::Client::builder()
                .user_agent("drust-oauth/1.11")
                .build()
                .expect("reqwest client build"),
        }
    }

    pub fn production(client_id: String, client_secret: String) -> Self {
        Self::new(
            client_id,
            client_secret,
            "https://github.com/login/oauth/authorize".into(),
            "https://github.com/login/oauth/access_token".into(),
            "https://api.github.com".into(),
        )
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
pub(crate) struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
    name: Option<String>,
    /// GitHub returns the user's avatar URL here on `GET /user`.
    /// Optional in serde for defence-in-depth; in practice GitHub
    /// always populates this.
    #[serde(default)]
    avatar_url: Option<String>,
}

pub(crate) fn pick_primary_verified(emails: &[GitHubEmail]) -> Option<String> {
    emails
        .iter()
        .find(|e| e.primary && e.verified)
        .map(|e| e.email.clone())
}

impl OauthProvider for GitHubAdapter {
    fn name(&self) -> &'static str {
        "github"
    }

    fn authorize_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String {
        // `url` crate not in tree; hand-build with urlencoding (in tree).
        // urlencoding::encode emits %20 for spaces, but x-www-form-urlencoded
        // (which providers accept on the query string) prefers `+`. Encode
        // each scope token separately and join with `+`.
        let scope = ["read:user", "user:email"]
            .map(|s| urlencoding::encode(s).into_owned())
            .join("+");
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.authorize_endpoint,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            scope,
            urlencoding::encode(state),
            urlencoding::encode(pkce_challenge),
        )
    }

    fn exchange<'a>(
        &'a self,
        code: &'a str,
        pkce_verifier: &'a str,
        redirect_uri: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<VerifiedUser, OauthError>> + Send + 'a>> {
        Box::pin(async move {
            // 1. code -> access_token
            let tok_resp: TokenResponse = self
                .http
                .post(&self.token_endpoint)
                .header(reqwest::header::ACCEPT, "application/json")
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("client_secret", self.client_secret.as_str()),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                    ("code_verifier", pkce_verifier),
                ])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            // 2. /user/emails -> primary verified
            let emails: Vec<GitHubEmail> = self
                .http
                .get(format!("{}/user/emails", self.api_base))
                .bearer_auth(&tok_resp.access_token)
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let email = pick_primary_verified(&emails)
                .ok_or(OauthError::EmailNotProvided)?;

            // 3. /user -> numeric id + display name
            let user: GitHubUser = self
                .http
                .get(format!("{}/user", self.api_base))
                .bearer_auth(&tok_resp.access_token)
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            Ok(VerifiedUser::new(
                "github",
                user.id.to_string(),
                &email,
                true, // GitHub primary+verified ⇒ verified
                user.name,
                user.avatar_url,
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_adapter() -> GitHubAdapter {
        GitHubAdapter::new(
            "client_gh".into(),
            "secret_gh".into(),
            "https://github.com/login/oauth/authorize".into(),
            "https://github.com/login/oauth/access_token".into(),
            "https://api.github.com".into(),
        )
    }

    #[test]
    fn authorize_url_has_required_params() {
        let a = fake_adapter();
        let url = a.authorize_url("S1", "C1", "https://example.com/cb");
        for s in [
            "client_id=client_gh",
            "redirect_uri=https%3A%2F%2Fexample.com%2Fcb",
            "scope=read%3Auser+user%3Aemail",
            "state=S1",
            "code_challenge=C1",
            "code_challenge_method=S256",
        ] {
            assert!(url.contains(s), "missing {s:?} in {url}");
        }
    }

    #[test]
    fn select_primary_verified_email() {
        let json = serde_json::json!([
            {"email": "noreply@github.com", "primary": false, "verified": true},
            {"email": "kael@example.com", "primary": true, "verified": true},
            {"email": "other@example.com", "primary": false, "verified": false},
        ]);
        let emails: Vec<GitHubEmail> = serde_json::from_value(json).unwrap();
        let picked = pick_primary_verified(&emails);
        assert_eq!(picked.as_deref(), Some("kael@example.com"));
    }

    #[test]
    fn no_verified_primary_returns_none() {
        let json = serde_json::json!([
            {"email": "x@y.com", "primary": true, "verified": false},
        ]);
        let emails: Vec<GitHubEmail> = serde_json::from_value(json).unwrap();
        assert!(pick_primary_verified(&emails).is_none());
    }
}
