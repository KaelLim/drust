//! Google OIDC adapter. Authorization-code flow with PKCE. We obtain
//! id_token directly from the token endpoint over TLS and decode it
//! without signature verification — see spec §"Security model" for the
//! OIDC Core §3.1.3.7 rationale.

use crate::oauth::provider::{OauthError, OauthProvider, VerifiedUser};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
    // v1.32 A2: mandatory OIDC §3.1.3.7 claims (iss / aud / exp).
    iss: String,
    aud: String,
    exp: i64,
}

/// Decode id_token JWT (header.payload.signature). Trust the channel,
/// not the JWT signature, per OIDC Core §3.1.3.7. Signature verification
/// is intentionally skipped (confidential client + TLS-trusted token
/// endpoint), but iss/aud/exp checks are mandatory under the same section.
pub(crate) fn decode_id_token(jwt: &str, client_id: &str) -> Result<VerifiedUser, OauthError> {
    let mut parts = jwt.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| OauthError::ProviderResponse("id_token has no header".into()))?;
    let payload = parts
        .next()
        .ok_or_else(|| OauthError::ProviderResponse("id_token has no payload".into()))?;
    if parts.next().is_none() {
        return Err(OauthError::ProviderResponse(
            "id_token missing signature segment".into(),
        ));
    }
    if payload.is_empty() {
        return Err(OauthError::ProviderResponse(
            "id_token payload empty".into(),
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| OauthError::ProviderResponse(format!("id_token base64: {e}")))?;
    let claims: IdTokenClaims = serde_json::from_slice(&decoded)
        .map_err(|e| OauthError::ProviderResponse(format!("id_token json: {e}")))?;

    // v1.32 A2: validate iss / aud / exp per OIDC §3.1.3.7.
    // Signature verification is intentionally skipped (confidential
    // client + TLS-trusted token endpoint), but iss/aud/exp checks
    // are mandatory under the same spec section.
    const VALID_ISS: &[&str] = &["https://accounts.google.com", "accounts.google.com"];
    if !VALID_ISS.contains(&claims.iss.as_str()) {
        return Err(OauthError::ProviderResponse("id_token iss mismatch".into()));
    }
    if claims.aud != client_id {
        return Err(OauthError::ProviderResponse("id_token aud mismatch".into()));
    }
    let now = chrono::Utc::now().timestamp();
    // `<=` (not `<`): a token whose `exp` equals the current second
    // is already expired — accepting it would allow a one-second
    // replay window at the boundary.
    if claims.exp <= now {
        return Err(OauthError::ProviderResponse(format!(
            "id_token expired: exp={} now={now}",
            claims.exp
        )));
    }

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
    ) -> Pin<Box<dyn std::future::Future<Output = Result<VerifiedUser, OauthError>> + Send + 'a>>
    {
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
            decode_id_token(&token.id_token, &self.client_id)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const TEST_CLIENT_ID: &str = "client123";

    fn fake_adapter() -> GoogleAdapter {
        GoogleAdapter::new(
            TEST_CLIENT_ID.into(),
            "secret456".into(),
            "https://accounts.google.com/o/oauth2/v2/auth".into(),
            "https://oauth2.googleapis.com/token".into(),
        )
    }

    /// Build a minimal valid id_token payload (iss/aud/exp all correct).
    fn valid_payload() -> serde_json::Value {
        let exp = chrono::Utc::now().timestamp() + 3600;
        serde_json::json!({
            "sub": "1234",
            "email": "kael@example.com",
            "email_verified": true,
            "name": "Kael Lim",
            "picture": "https://lh3.googleusercontent.com/a/AVATAR",
            "iss": "https://accounts.google.com",
            "aud": TEST_CLIENT_ID,
            "exp": exp,
        })
    }

    fn make_token(payload: &serde_json::Value) -> String {
        let b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("header.{b64}.signature")
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
        let id_token = make_token(&valid_payload());
        let user = decode_id_token(&id_token, TEST_CLIENT_ID).unwrap();
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
        let mut payload = valid_payload();
        payload.as_object_mut().unwrap().remove("picture");
        let id_token = make_token(&payload);
        let user = decode_id_token(&id_token, TEST_CLIENT_ID).unwrap();
        assert!(user.picture.is_none());
    }

    #[test]
    fn decode_id_token_rejects_malformed() {
        assert!(decode_id_token("not.a.jwt-x", TEST_CLIENT_ID).is_err());
        assert!(decode_id_token("only.two", TEST_CLIENT_ID).is_err());
        assert!(decode_id_token("", TEST_CLIENT_ID).is_err());
    }

    // ---------- v1.32 A2: iss / aud / exp validation ----------

    #[test]
    fn decode_id_token_rejects_wrong_iss() {
        let mut payload = valid_payload();
        payload["iss"] = serde_json::json!("https://evil.example.com");
        let id_token = make_token(&payload);
        let err = decode_id_token(&id_token, TEST_CLIENT_ID).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("iss"),
            "expected iss mismatch error, got: {msg}"
        );
    }

    #[test]
    fn decode_id_token_rejects_wrong_aud() {
        let mut payload = valid_payload();
        payload["aud"] = serde_json::json!("attacker-client-id");
        let id_token = make_token(&payload);
        let err = decode_id_token(&id_token, TEST_CLIENT_ID).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("aud"),
            "expected aud mismatch error, got: {msg}"
        );
    }

    #[test]
    fn decode_id_token_aud_error_does_not_echo_claim_value() {
        let mut payload = valid_payload();
        payload["aud"] = serde_json::json!("attacker-secret-client-id");
        let id_token = make_token(&payload);
        let err = decode_id_token(&id_token, TEST_CLIENT_ID).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("aud"), "still names the field: {msg}");
        assert!(
            !msg.contains("attacker-secret-client-id"),
            "must not echo the untrusted claim value: {msg}"
        );
    }

    #[test]
    fn decode_id_token_rejects_expired_exp() {
        let mut payload = valid_payload();
        // exp in the past
        payload["exp"] = serde_json::json!(chrono::Utc::now().timestamp() - 1);
        let id_token = make_token(&payload);
        let err = decode_id_token(&id_token, TEST_CLIENT_ID).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exp") || msg.contains("expired"),
            "expected expiry error, got: {msg}"
        );
    }

    #[test]
    fn decode_id_token_accepts_alternate_iss() {
        // "accounts.google.com" (without https://) is also a valid issuer.
        let mut payload = valid_payload();
        payload["iss"] = serde_json::json!("accounts.google.com");
        let id_token = make_token(&payload);
        decode_id_token(&id_token, TEST_CLIENT_ID).expect("alternate iss should be accepted");
    }
}
