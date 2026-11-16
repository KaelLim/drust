//! MCP OAuth authorization server. Routes are mounted only when
//! `config::McpOauthConfig::enabled()`; with DRUST_MCP unset every HTTP response is
//! byte-identical to a build without this module. Tables:
//! `db::migrations::SQL_CREATE_MCP_OAUTH_IF_NOT_EXISTS`. Release notes: CHANGELOG.md.
pub mod config;
pub mod rl;
pub mod store;
pub mod tokens;
