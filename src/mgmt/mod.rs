pub mod admin_pat;
pub mod admin_profile;
pub mod admin_rooms;
pub mod admin_team;
pub mod audit;
pub mod backups;
pub mod browse;
pub mod cli_device;
pub mod collection_list;
pub mod cron_admin;
pub mod docs;
pub mod format;
pub mod frame_guard;
pub mod functions_admin;
pub mod i18n;
pub mod locale_layer;
pub mod metrics;
pub mod oauth_login;
/// #975 — the shared "which tenants does this admin's PAT reach" decision the
/// PAT-revocation sites evict over.
pub mod pat_evict;
/// Test-only: the #975/#976 structural pins over the PAT-revocation sites —
/// `clear_admin_pat` → `bus_rooms.evict` ordering, tree-wide site
/// completeness, and the #976 rule that every reach snapshot is read inside
/// its revoking critical section. Not a runtime module.
#[cfg(test)]
mod pat_evict_pin;
pub mod public_files;
pub mod quota_admin;
pub mod request_janitor;
pub mod routes;
pub mod rpc_admin;
pub mod script_json;
pub mod signed_bytes;
pub mod stats;
pub mod tenant_authz;
pub mod tenant_broadcast;
pub mod tenant_cap;
pub mod tenant_files;
pub mod tenant_settings;
pub mod tenants;
pub mod theme;
pub mod theme_layer;
pub mod tokens;
