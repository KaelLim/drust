//! Reads OAuth provider config from environment variables and builds a
//! ProviderRegistry. Partial config (one half of a client_id/secret pair
//! present) logs a warning and skips that provider.

use crate::oauth::github::GitHubAdapter;
use crate::oauth::google::GoogleAdapter;
use crate::oauth::provider::OauthProvider;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub struct ProviderRegistry {
    providers: HashMap<&'static str, Arc<dyn OauthProvider>>,
}

impl ProviderRegistry {
    pub fn from_env() -> Self {
        let mut providers: HashMap<&'static str, Arc<dyn OauthProvider>> = HashMap::new();

        // Google
        match (
            std::env::var("DRUST_OAUTH_GOOGLE_CLIENT_ID")
                .ok()
                .filter(|s| !s.is_empty()),
            std::env::var("DRUST_OAUTH_GOOGLE_CLIENT_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
        ) {
            (Some(id), Some(secret)) => {
                providers.insert("google", Arc::new(GoogleAdapter::production(id, secret)));
            }
            (Some(_), None) | (None, Some(_)) => {
                tracing::warn!("Google OAuth half-configured; skipping provider");
            }
            (None, None) => {}
        }

        // GitHub
        match (
            std::env::var("DRUST_OAUTH_GITHUB_CLIENT_ID")
                .ok()
                .filter(|s| !s.is_empty()),
            std::env::var("DRUST_OAUTH_GITHUB_CLIENT_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
        ) {
            (Some(id), Some(secret)) => {
                providers.insert("github", Arc::new(GitHubAdapter::production(id, secret)));
            }
            (Some(_), None) | (None, Some(_)) => {
                tracing::warn!("GitHub OAuth half-configured; skipping provider");
            }
            (None, None) => {}
        }

        Self { providers }
    }

    /// Returns an empty registry. Used by main.rs when OAuth is
    /// configured but DRUST_PUBLIC_URL / allowlist is missing (defensive
    /// disable to avoid accepting any email).
    pub fn from_env_empty() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    /// Build a registry from an explicit provider map. Used by integration
    /// tests that wire fake adapters pointed at a local fake-provider
    /// HTTP server.
    pub fn from_providers(providers: HashMap<&'static str, Arc<dyn OauthProvider>>) -> Self {
        Self { providers }
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn OauthProvider>> {
        self.providers.get(name).cloned()
    }

    pub fn enabled_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.providers.keys().copied().collect();
        names.sort();
        names
    }
}

pub fn parse_allowlist(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn set_env(map: &[(&str, &str)]) {
        for k in [
            "DRUST_OAUTH_GOOGLE_CLIENT_ID",
            "DRUST_OAUTH_GOOGLE_CLIENT_SECRET",
            "DRUST_OAUTH_GITHUB_CLIENT_ID",
            "DRUST_OAUTH_GITHUB_CLIENT_SECRET",
            "DRUST_ADMIN_OAUTH_ALLOWED_EMAILS",
        ] {
            unsafe {
                std::env::remove_var(k);
            }
        }
        for (k, v) in map {
            unsafe {
                std::env::set_var(k, v);
            }
        }
    }

    #[test]
    #[serial_test::serial] // mutates process-global DRUST_OAUTH_* env vars
    fn empty_env_registers_no_providers() {
        set_env(&[]);
        let r = ProviderRegistry::from_env();
        assert_eq!(r.enabled_names(), Vec::<&str>::new());
    }

    #[test]
    #[serial_test::serial] // mutates process-global DRUST_OAUTH_* env vars
    fn google_full_pair_registers_google() {
        set_env(&[
            ("DRUST_OAUTH_GOOGLE_CLIENT_ID", "gid"),
            ("DRUST_OAUTH_GOOGLE_CLIENT_SECRET", "gsec"),
        ]);
        let r = ProviderRegistry::from_env();
        assert_eq!(r.enabled_names(), vec!["google"]);
        assert!(r.get("google").is_some());
        assert!(r.get("github").is_none());
    }

    #[test]
    #[serial_test::serial] // mutates process-global DRUST_OAUTH_* env vars
    fn partial_google_pair_skipped() {
        set_env(&[("DRUST_OAUTH_GOOGLE_CLIENT_ID", "gid")]);
        let r = ProviderRegistry::from_env();
        assert!(r.enabled_names().is_empty());
    }

    #[test]
    fn allowlist_parsed_lowercase_trimmed() {
        let parsed = parse_allowlist("  Kael@Example.com , bob@x.io  ,, ");
        let want: HashSet<String> = ["kael@example.com", "bob@x.io"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(parsed, want);
    }
}
