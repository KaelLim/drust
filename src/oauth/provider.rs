//! Actor-agnostic OAuth provider trait + normalized user struct.
//!
//! v1.11 admin OAuth and v1.12 per-tenant OAuth both consume the same
//! `VerifiedUser` shape returned by `OauthProvider::exchange`. The trait
//! has zero admin/tenant assumptions; the actor-specific glue lives in
//! `src/mgmt/oauth_login.rs` (v1.11) and `src/tenant/oauth_login.rs`
//! (v1.12).

use std::pin::Pin;
use thiserror::Error;

/// Normalized representation of a user returned from any OAuth provider.
/// `email` is always lowercased on construction so callers can compare
/// without re-lowercasing.
#[derive(Debug, Clone)]
pub struct VerifiedUser {
    pub provider: &'static str,
    pub provider_user_id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    /// Avatar URL extracted from the provider response. Google's id_token
    /// usually carries `picture`; GitHub's `/user` returns `avatar_url`.
    /// `None` when the provider omitted it. Tenant find-or-create writes
    /// this into `_system_users.profile` JSON under the `"picture"` key
    /// (spec §3.3). The admin OAuth flow currently ignores it (v1.11
    /// admin schema has no profile column); a future v1.13 may surface
    /// it.
    pub picture: Option<String>,
}

impl VerifiedUser {
    pub fn new(
        provider: &'static str,
        provider_user_id: impl Into<String>,
        email: &str,
        email_verified: bool,
        name: Option<String>,
        picture: Option<String>,
    ) -> Self {
        Self {
            provider,
            provider_user_id: provider_user_id.into(),
            email: email.to_lowercase(),
            email_verified,
            name,
            picture,
        }
    }
}

#[derive(Debug, Error)]
pub enum OauthError {
    #[error("provider http error: {0}")]
    ProviderHttp(#[from] reqwest::Error),
    #[error("provider response: {0}")]
    ProviderResponse(String),
    #[error("email not provided by provider")]
    EmailNotProvided,
    #[error("misconfigured: {0}")]
    Misconfigured(String),
}

/// Implementations return `Pin<Box<dyn Future>>` to stay `dyn`-safe
/// (RPITIT is not dyn-compatible, so we cannot use native `async fn` in
/// trait here). Callers store providers in `Arc<dyn OauthProvider>`.
pub trait OauthProvider: Send + Sync {
    fn name(&self) -> &'static str;

    fn authorize_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String;

    fn exchange<'a>(
        &'a self,
        code: &'a str,
        pkce_verifier: &'a str,
        redirect_uri: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<VerifiedUser, OauthError>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_user_lowercases_email_on_construction() {
        let u = VerifiedUser::new("google", "sub-1", "Kael@Example.COM", true, None, None);
        assert_eq!(u.email, "kael@example.com");
        assert!(u.picture.is_none());
    }

    #[test]
    fn verified_user_carries_picture_when_supplied() {
        let u = VerifiedUser::new(
            "google",
            "sub-2",
            "x@y.com",
            true,
            Some("X".into()),
            Some("https://lh3.googleusercontent.com/avatar".into()),
        );
        assert_eq!(
            u.picture.as_deref(),
            Some("https://lh3.googleusercontent.com/avatar")
        );
    }

    #[test]
    fn oauth_error_display_contains_kind() {
        let e = OauthError::EmailNotProvided;
        assert!(e.to_string().contains("email"));
    }
}
