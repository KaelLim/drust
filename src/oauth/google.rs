//! Google OIDC adapter. Authorization-code flow with PKCE. We obtain
//! id_token directly from the token endpoint over TLS and decode it
//! without signature verification — see spec §"Security model" for the
//! OIDC Core §3.1.3.7 rationale.

use crate::oauth::provider::{OauthError, OauthProvider, VerifiedUser};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use std::pin::Pin;

pub struct GoogleAdapter {
    client_id: String,
    client_secret: String,
    authorize_endpoint: String,
    token_endpoint: String,
    http: reqwest::Client,
}

impl GoogleAdapter {
    pub fn new(
        client_id: String,
        client_secret: String,
        authorize_endpoint: String,
        token_endpoint: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            authorize_endpoint,
            token_endpoint,
            http: reqwest::Client::new(),
        }
    }

    pub fn production(client_id: String, client_secret: String) -> Self {
        Self::new(
            client_id,
            client_secret,
            "https://accounts.google.com/o/oauth2/v2/auth".into(),
            "https://oauth2.googleapis.com/token".into(),
        )
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct IdTokenClaims {
    sub: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
    /// Standard OIDC profile claim — Google's id_token routinely carries
    /// the user's avatar URL here. Optional because not every provider
    /// (or every Google response shape) sets it.
    #[serde(default)]
    picture: Option<String>,
}

/// Decode id_token JWT (header.payload.signature). Trust the channel,
/// not the JWT signature, per OIDC Core §3.1.3.7.
pub(crate) fn decode_id_token(jwt: &str) -> Result<VerifiedUser, OauthError> {
    let mut parts = jwt.split('.');
    let _header = parts.next().ok_or_else(|| OauthError::ProviderResponse("id_token has no header".into()))?;
    let payload = parts.next().ok_or_else(|| OauthError::ProviderResponse("id_token has no payload".into()))?;
    if parts.next().is_none() {
        return Err(OauthError::ProviderResponse("id_token missing signature segment".into()));
    }
    if payload.is_empty() {
        return Err(OauthError::ProviderResponse("id_token payload empty".into()));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| OauthError::ProviderResponse(format!("id_token base64: {e}")))?;
    let claims: IdTokenClaims = serde_json::from_slice(&decoded)
        .map_err(|e| OauthError::ProviderResponse(format!("id_token json: {e}")))?;
    Ok(VerifiedUser::new(
        "google",
        claims.sub,
        &claims.email,
        claims.email_verified,
        claims.name,
        claims.picture,
    ))
}

impl OauthProvider for GoogleAdapter {
    fn name(&self) -> &'static str {
        "google"
    }

    fn authorize_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String {
        // `url` crate not in Cargo.toml; hand-build with urlencoding (which IS in tree).
        // Order of params doesn't matter to providers — keep stable for testability.
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid+email+profile&state={}&code_challenge={}&code_challenge_method=S256&access_type=online&prompt=select_account",
            self.authorize_endpoint,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
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
            let resp = self
                .http
                .post(&self.token_endpoint)
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                    ("client_id", &self.client_id),
                    ("client_secret", &self.client_secret),
                    ("code_verifier", pkce_verifier),
                ])
                .send()
                .await?
                .error_for_status()?;
            let token: TokenResponse = resp.json().await?;
            decode_id_token(&token.id_token)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn fake_adapter() -> GoogleAdapter {
        GoogleAdapter::new(
            "client123".into(),
            "secret456".into(),
            "https://accounts.google.com/o/oauth2/v2/auth".into(),
            "https://oauth2.googleapis.com/token".into(),
        )
    }

    #[test]
    fn authorize_url_has_required_params() {
        let a = fake_adapter();
        let url = a.authorize_url("STATE1", "CHALLENGE1", "https://example.com/cb");
        for s in [
            "response_type=code",
            "client_id=client123",
            "redirect_uri=https%3A%2F%2Fexample.com%2Fcb",
            "scope=openid+email+profile",
            "state=STATE1",
            "code_challenge=CHALLENGE1",
            "code_challenge_method=S256",
        ] {
            assert!(url.contains(s), "missing {s:?} in {url}");
        }
    }

    #[test]
    fn decode_id_token_extracts_claims() {
        let payload = serde_json::json!({
            "sub": "1234",
            "email": "kael@example.com",
            "email_verified": true,
            "name": "Kael Lim",
            "picture": "https://lh3.googleusercontent.com/a/AVATAR",
        });
        let b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
        let id_token = format!("header.{b64}.signature");

        let user = decode_id_token(&id_token).unwrap();
        assert_eq!(user.email, "kael@example.com");
        assert!(user.email_verified);
        assert_eq!(user.provider_user_id, "1234");
        assert_eq!(user.name.as_deref(), Some("Kael Lim"));
        assert_eq!(
            user.picture.as_deref(),
            Some("https://lh3.googleusercontent.com/a/AVATAR")
        );
    }

    #[test]
    fn decode_id_token_picture_optional() {
        // No `picture` claim — VerifiedUser carries None instead of failing.
        let payload = serde_json::json!({
            "sub": "5678",
            "email": "noavatar@example.com",
            "email_verified": true,
            "name": "X",
        });
        let b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
        let id_token = format!("header.{b64}.signature");
        let user = decode_id_token(&id_token).unwrap();
        assert!(user.picture.is_none());
    }

    #[test]
    fn decode_id_token_rejects_malformed() {
        assert!(decode_id_token("not.a.jwt-x").is_err());
        assert!(decode_id_token("only.two").is_err());
        assert!(decode_id_token("").is_err());
    }
}
