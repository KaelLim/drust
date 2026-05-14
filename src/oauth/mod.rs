pub mod config;
pub mod github;
pub mod google;
pub mod provider;
pub mod state;

pub use config::ProviderRegistry;
pub use provider::{OauthError, OauthProvider, VerifiedUser};
