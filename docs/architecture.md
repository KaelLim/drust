---
type: reference
name: drust source architecture index
status: production
updated: 2026-05-12
generated_by: docs/gen-architecture.py
---

# drust — source architecture index

> [!NOTE]
> **Auto-generated** from `src/**/*.rs`. Do not hand-edit — rebuild with
> `python3 drust/docs/gen-architecture.py` after code changes.
>
> Summaries come from each file's `//!` module doc. Public items come from top-level `pub` declarations. Cross-file edges come from `use crate::...` imports and `mod X;` declarations — this is **textual, not AST**, so calls through fully-qualified paths without a `use` won't appear. Good enough for orientation.

## Module overview

| group | files | public items | imports out | imports in |
|---|---:|---:|---:|---:|
| [`(root)/`](#srcroot) | 4 | 16 | 0 | 1 |
| [`auth/`](#srcauth) | 8 | 38 | 1 | 18 |
| [`bin/`](#srcbin) | 2 | 0 | 0 | 0 |
| [`db/`](#srcdb) | 2 | 7 | 0 | 0 |
| [`mcp/`](#srcmcp) | 13 | 84 | 33 | 18 |
| [`mgmt/`](#srcmgmt) | 13 | 123 | 38 | 11 |
| [`query/`](#srcquery) | 4 | 17 | 2 | 14 |
| [`rpc/`](#srcrpc) | 5 | 21 | 10 | 5 |
| [`safety/`](#srcsafety) | 5 | 14 | 0 | 5 |
| [`storage/`](#srcstorage) | 12 | 66 | 7 | 36 |
| [`tenant/`](#srctenant) | 11 | 60 | 32 | 15 |

## Group-level dependency graph

```mermaid
graph LR
  mcp --> query
  mcp --> storage
  mcp --> tenant
  mgmt --> auth
  mgmt --> query
  mgmt --> rpc
  mgmt --> safety
  mgmt --> storage
  query --> storage
  rpc --> auth
  rpc --> query
  rpc --> storage
  rpc --> tenant
  storage --> root
  storage --> auth
  storage --> tenant
  tenant --> auth
  tenant --> mcp
  tenant --> mgmt
  tenant --> query
  tenant --> safety
  tenant --> storage
```

<a id="srcroot"></a>

## `src/` (root)

### [`src/config.rs`](../src/config.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `enum ConfigError`
- `struct Config`
- `struct StorageConfig`

**Imported by:**

- [`src/storage/garage.rs`](../src/storage/garage.rs)

### [`src/error.rs`](../src/error.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `enum ErrorCode`
- `struct ToolError`

### [`src/lib.rs`](../src/lib.rs)

**Declares submodules:**

- [`src/auth/mod.rs`](../src/auth/mod.rs)
- [`src/config.rs`](../src/config.rs)
- [`src/db/mod.rs`](../src/db/mod.rs)
- [`src/error.rs`](../src/error.rs)
- [`src/mcp/mod.rs`](../src/mcp/mod.rs)
- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)
- [`src/query/mod.rs`](../src/query/mod.rs)
- [`src/rpc/mod.rs`](../src/rpc/mod.rs)
- [`src/safety/mod.rs`](../src/safety/mod.rs)
- [`src/storage/mod.rs`](../src/storage/mod.rs)
- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `mod auth`
- `mod config`
- `mod db`
- `mod error`
- `mod mcp`
- `mod mgmt`
- `mod query`
- `mod rpc`
- `mod safety`
- `mod storage`
- `mod tenant`

### [`src/main.rs`](../src/main.rs)

_(no top-level pub items)_

<a id="srcauth"></a>

## `src/auth/`

### [`src/auth/admin.rs`](../src/auth/admin.rs)

**Declared by:**

- [`src/auth/mod.rs`](../src/auth/mod.rs)

**Public items:**

- `fn hash_password`
- `fn verify_password`

**Imported by:**

- [`src/mgmt/routes.rs`](../src/mgmt/routes.rs)
- [`src/storage/meta.rs`](../src/storage/meta.rs)

### [`src/auth/bearer.rs`](../src/auth/bearer.rs)

**Declared by:**

- [`src/auth/mod.rs`](../src/auth/mod.rs)

**Public items:**

- `fn generate_token`
- `fn hash_token`
- `fn verify_token_hash`
- `fn token_hint`

**Imported by:**

- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)
- [`src/mgmt/tokens.rs`](../src/mgmt/tokens.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/auth/middleware.rs`](../src/auth/middleware.rs)

**Declared by:**

- [`src/auth/mod.rs`](../src/auth/mod.rs)

**Public items:**

- `struct AdminSessionState`
- `enum AuthCtx`
- `struct AdminId`
- `const SESSION_COOKIE`
- `fn admin_session_layer`
- `fn build_session_cookie`
- `fn clear_session_cookie`

**Imports from:**

- [`src/auth/session.rs`](../src/auth/session.rs)

**Imported by:**

- [`src/mgmt/public_files.rs`](../src/mgmt/public_files.rs)
- [`src/mgmt/routes.rs`](../src/mgmt/routes.rs)
- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)
- [`src/rpc/handler.rs`](../src/rpc/handler.rs)
- [`src/tenant/admin_user_routes.rs`](../src/tenant/admin_user_routes.rs)
- [`src/tenant/auth_routes.rs`](../src/tenant/auth_routes.rs)
- [`src/tenant/owner_field.rs`](../src/tenant/owner_field.rs)
- [`src/tenant/query_endpoint.rs`](../src/tenant/query_endpoint.rs)
- [`src/tenant/records.rs`](../src/tenant/records.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/auth/mod.rs`](../src/auth/mod.rs)

**Declares submodules:**

- [`src/auth/admin.rs`](../src/auth/admin.rs)
- [`src/auth/bearer.rs`](../src/auth/bearer.rs)
- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/auth/profile.rs`](../src/auth/profile.rs)
- [`src/auth/session.rs`](../src/auth/session.rs)
- [`src/auth/user.rs`](../src/auth/user.rs)
- [`src/auth/user_session.rs`](../src/auth/user_session.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `mod admin`
- `mod bearer`
- `mod middleware`
- `mod profile`
- `mod session`
- `mod user`
- `mod user_session`

### [`src/auth/profile.rs`](../src/auth/profile.rs)

_Profile encoding/decoding helpers shared by REST + MCP user paths._

**Declared by:**

- [`src/auth/mod.rs`](../src/auth/mod.rs)

**Public items:**

- `fn encode` — Encode a client-supplied `profile` value to the TEXT form stored in
- `fn decode` — Decode the TEXT form read from `_system_users.profile`. Returns

### [`src/auth/session.rs`](../src/auth/session.rs)

**Declared by:**

- [`src/auth/mod.rs`](../src/auth/mod.rs)

**Public items:**

- `fn create_session`
- `fn validate_session`
- `fn purge_expired`
- `fn revoke_session`

**Imported by:**

- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/mgmt/routes.rs`](../src/mgmt/routes.rs)

### [`src/auth/user.rs`](../src/auth/user.rs)

**Declared by:**

- [`src/auth/mod.rs`](../src/auth/mod.rs)

**Public items:**

- `fn dummy_hash` — argon2id PHC string for a password the attacker cannot guess. Used by login when the
- `fn hash_password`
- `fn verify_password`

**Imported by:**

- [`src/tenant/auth_routes.rs`](../src/tenant/auth_routes.rs)

### [`src/auth/user_session.rs`](../src/auth/user_session.rs)

**Declared by:**

- [`src/auth/mod.rs`](../src/auth/mod.rs)

**Public items:**

- `struct SessionInfo`
- `fn generate_token`
- `fn hash_token`
- `fn create_session`
- `fn lookup_session`
- `fn slide_expiry`
- `fn revoke_session`
- `fn revoke_session_by_hash`
- `fn revoke_all_sessions`

<a id="srcbin"></a>

## `src/bin/`

### [`src/bin/drust_session_janitor.rs`](../src/bin/drust_session_janitor.rs)

_Daily janitor for expired user sessions. Invoked by the_

_(no top-level pub items)_

### [`src/bin/set_admin_password.rs`](../src/bin/set_admin_password.rs)

_(no top-level pub items)_

<a id="srcdb"></a>

## `src/db/`

### [`src/db/migrations.rs`](../src/db/migrations.rs)

**Declared by:**

- [`src/db/mod.rs`](../src/db/mod.rs)

**Public items:**

- `const SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS`
- `const SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS`
- `fn add_column_if_missing`
- `fn migrate_tenant_db`
- `struct MigrationReport`
- `fn run_migrations`

### [`src/db/mod.rs`](../src/db/mod.rs)

**Declares submodules:**

- [`src/db/migrations.rs`](../src/db/migrations.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `mod migrations`

<a id="srcmcp"></a>

## `src/mcp/`

### [`src/mcp/handler.rs`](../src/mcp/handler.rs)

_rmcp Streamable HTTP handler that exposes the 13 drust tools._

**Declared by:**

- [`src/mcp/mod.rs`](../src/mcp/mod.rs)

**Public items:**

- `struct DescribeCollectionArgs`
- `struct SampleRowsArgs`
- `struct CountRowsArgs`
- `struct QueryArgs`
- `struct ExplainArgs`
- `struct CreateCollectionArgs`
- `struct AddFieldArgs`
- `struct DropFieldArgs`
- `struct DropCollectionArgs`
- `struct CreateIndexArgs`
- `struct DropIndexArgs`
- `struct SetAnonCapsArgs`
- `struct InsertRecordArgs`
- `struct UpdateRecordArgs`
- `struct DeleteRecordArgs`
- `struct CreateRpcParams`
- `struct UpdateRpcParams`
- `struct NameOnly`
- `struct EmptyParams`
- `struct CallRpcParams`
- `struct CreateUserArgs`
- `struct ListUsersArgs`
- `struct UserIdArgs`
- `struct UpdateUserArgs`
- `struct SetOwnerFieldArgs`
- `struct ClearOwnerFieldArgs`
- `struct SetSelfRegisterArgs`
- `struct DrustMcpService`

**Imports from:**

- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/mcp/tools/exploration.rs`](../src/mcp/tools/exploration.rs)
- [`src/mcp/tools/files.rs`](../src/mcp/tools/files.rs)
- [`src/mcp/tools/owner_field.rs`](../src/mcp/tools/owner_field.rs)
- [`src/mcp/tools/read.rs`](../src/mcp/tools/read.rs)
- [`src/mcp/tools/schema.rs`](../src/mcp/tools/schema.rs)
- [`src/mcp/tools/user.rs`](../src/mcp/tools/user.rs)
- [`src/mcp/tools/write.rs`](../src/mcp/tools/write.rs)

**Imported by:**

- [`src/mcp/http_registry.rs`](../src/mcp/http_registry.rs)

### [`src/mcp/http_registry.rs`](../src/mcp/http_registry.rs)

_Per-tenant cache of `StreamableHttpService` instances._

**Declared by:**

- [`src/mcp/mod.rs`](../src/mcp/mod.rs)

**Public items:**

- `type TenantMcpService`
- `struct McpHttpRegistry`

**Imports from:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)
- [`src/mcp/server.rs`](../src/mcp/server.rs)

**Imported by:**

- [`src/tenant/mcp_dispatch.rs`](../src/tenant/mcp_dispatch.rs)
- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

### [`src/mcp/mod.rs`](../src/mcp/mod.rs)

**Declares submodules:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)
- [`src/mcp/http_registry.rs`](../src/mcp/http_registry.rs)
- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `mod handler`
- `mod http_registry`
- `mod server`
- `mod tools`

### [`src/mcp/server.rs`](../src/mcp/server.rs)

**Declared by:**

- [`src/mcp/mod.rs`](../src/mcp/mod.rs)

**Public items:**

- `struct DrustMcpInner`
- `struct DrustMcp`
- `struct McpRegistry` — Lazy cache of per-tenant MCP services. Entries are evicted when a tenant is

**Imports from:**

- [`src/storage/garage.rs`](../src/storage/garage.rs)
- [`src/storage/pool.rs`](../src/storage/pool.rs)
- [`src/tenant/events.rs`](../src/tenant/events.rs)

**Imported by:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)
- [`src/mcp/http_registry.rs`](../src/mcp/http_registry.rs)
- [`src/mcp/tools/exploration.rs`](../src/mcp/tools/exploration.rs)
- [`src/mcp/tools/files.rs`](../src/mcp/tools/files.rs)
- [`src/mcp/tools/read.rs`](../src/mcp/tools/read.rs)
- [`src/mcp/tools/schema.rs`](../src/mcp/tools/schema.rs)
- [`src/mcp/tools/write.rs`](../src/mcp/tools/write.rs)

### [`src/mcp/tools/exploration.rs`](../src/mcp/tools/exploration.rs)

**Declared by:**

- [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Public items:**

- `fn list_collections`
- `fn describe_collection`
- `fn sample_rows`
- `fn count_rows`
- `fn whoami` — Return the calling tenant's identity, both bearer tokens (plaintext),

**Imports from:**

- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/query/authorizer.rs`](../src/query/authorizer.rs)
- [`src/query/executor.rs`](../src/query/executor.rs)
- [`src/query/filter.rs`](../src/query/filter.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)

**Imported by:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)

### [`src/mcp/tools/files.rs`](../src/mcp/tools/files.rs)

_Y-scope MCP file tools — list / delete / get_file_url._

**Declared by:**

- [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Public items:**

- `struct ListFilesArgs`
- `fn list_files`
- `struct DeleteFileArgs`
- `fn delete_file`
- `struct GetFileUrlArgs`
- `fn get_file_url`

**Imports from:**

- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/storage/files.rs`](../src/storage/files.rs)

**Imported by:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)

### [`src/mcp/tools/index.rs`](../src/mcp/tools/index.rs)

**Declared by:**

- [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Public items:**

- `fn create_index` — Create a (possibly unique) index on one or more fields of a collection.
- `fn create_index_with_threshold` — Create a (possibly unique) index on one or more fields of a collection.
- `fn drop_index`
- `fn explain_select` — Run `EXPLAIN QUERY PLAN <sql>` under the read connection.
- `fn derive_index_name`

**Imports from:**

- [`src/mcp/tools/schema.rs`](../src/mcp/tools/schema.rs)
- [`src/storage/pool.rs`](../src/storage/pool.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)

### [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Declares submodules:**

- [`src/mcp/tools/exploration.rs`](../src/mcp/tools/exploration.rs)
- [`src/mcp/tools/files.rs`](../src/mcp/tools/files.rs)
- [`src/mcp/tools/index.rs`](../src/mcp/tools/index.rs)
- [`src/mcp/tools/owner_field.rs`](../src/mcp/tools/owner_field.rs)
- [`src/mcp/tools/read.rs`](../src/mcp/tools/read.rs)
- [`src/mcp/tools/schema.rs`](../src/mcp/tools/schema.rs)
- [`src/mcp/tools/user.rs`](../src/mcp/tools/user.rs)
- [`src/mcp/tools/write.rs`](../src/mcp/tools/write.rs)

**Declared by:**

- [`src/mcp/mod.rs`](../src/mcp/mod.rs)

**Public items:**

- `mod exploration`
- `mod files`
- `mod index`
- `mod owner_field`
- `mod read`
- `mod schema`
- `mod user`
- `mod write`

### [`src/mcp/tools/owner_field.rs`](../src/mcp/tools/owner_field.rs)

_Pure async helpers for T25 MCP owner-field + set_self_register tools._

**Declared by:**

- [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Public items:**

- `fn set_owner_field` — Validate then persist the owner-field for `collection`.
- `fn clear_owner_field`
- `fn set_self_register` — Update `tenants.allow_self_register` for this tenant in meta.sqlite.

**Imports from:**

- [`src/storage/pool.rs`](../src/storage/pool.rs)

**Imported by:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)

### [`src/mcp/tools/read.rs`](../src/mcp/tools/read.rs)

**Declared by:**

- [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Public items:**

- `fn query`
- `fn explain`

**Imports from:**

- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/query/authorizer.rs`](../src/query/authorizer.rs)
- [`src/query/executor.rs`](../src/query/executor.rs)

**Imported by:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)

### [`src/mcp/tools/schema.rs`](../src/mcp/tools/schema.rs)

**Declared by:**

- [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Public items:**

- `const SYSTEM_COLUMNS` — Columns drust maintains automatically; users cannot drop them.
- `struct FieldSpec`
- `const SQL_DEFAULT_ALLOWLIST` — Allowlist of SQL expressions that may appear as a field default.
- `fn identifier`
- `fn create_collection`
- `fn add_field`
- `fn drop_field` — Drop a user-defined column via `ALTER TABLE … DROP COLUMN`.
- `fn drop_collection` — Drop an entire collection (table + its `<name>_updated_at` trigger).
- `fn set_anon_caps` — Replace the anon-role DML capability set for one collection.

**Imports from:**

- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)

**Imported by:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)
- [`src/mcp/tools/index.rs`](../src/mcp/tools/index.rs)

### [`src/mcp/tools/user.rs`](../src/mcp/tools/user.rs)

_Pure async helpers for T24 MCP user-management tools._

**Declared by:**

- [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Public items:**

- `fn create_user`
- `fn list_users`
- `fn get_user`
- `fn update_user`
- `fn delete_user`
- `fn revoke_user_sessions`

**Imports from:**

- [`src/storage/pool.rs`](../src/storage/pool.rs)

**Imported by:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)

### [`src/mcp/tools/write.rs`](../src/mcp/tools/write.rs)

**Declared by:**

- [`src/mcp/tools/mod.rs`](../src/mcp/tools/mod.rs)

**Public items:**

- `fn insert_record`
- `fn update_record`
- `fn delete_record`

**Imports from:**

- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)
- [`src/tenant/events.rs`](../src/tenant/events.rs)

**Imported by:**

- [`src/mcp/handler.rs`](../src/mcp/handler.rs)

<a id="srcmgmt"></a>

## `src/mgmt/`

### [`src/mgmt/audit.rs`](../src/mgmt/audit.rs)

_Admin-UI audit log viewer._

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `enum Window`
- `enum AuditScope`
- `struct ScanResult`
- `struct FilterSpec`
- `struct Overview`
- `struct TopTenant`
- `const MAX_ENTRIES` — Hard cap on entries returned per scan_window call.
- `fn enumerate_audit_files` — Enumerate audit files under `dir` whose date falls inside `window` relative
- `fn scan_window` — Scan all audit files in `dir` whose date falls in `window`. Returns parsed
- `fn parse_jsonl_line` — Parse a single JSONL line into an `AuditEntry`. Returns `None` for empty
- `fn aggregate` — Compute summary stats over `entries`. `window` is used only for RPS denom
- `fn filter` — Apply filter spec. Result preserves input order (caller scan_window
- `struct AuditQuery`
- `struct WindowChoice`
- `struct BodyCtx` — Precomputed view-model fed to the body partial. Both shell templates
- `fn build_body_ctx`
- `fn audit_host_page`
- `fn audit_tenant_page`

**Imports from:**

- [`src/safety/audit.rs`](../src/safety/audit.rs)

### [`src/mgmt/backups.rs`](../src/mgmt/backups.rs)

_Admin-UI handlers for `drust-backup` snapshot inspection + download._

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct BackupsState`
- `struct BackupRow`
- `struct TenantInBackup`
- `struct RestoreFlash`
- `struct RestoreForm`
- `struct InspectQs`
- `fn list_page`
- `fn inspect` — `GET /admin/backups/{filename}/inspect` — open the archive on a blocking
- `fn restore_tenant` — `POST /admin/backups/{filename}/restore` — extract the named tenant's
- `fn download_one`

**Imports from:**

- [`src/mgmt/format.rs`](../src/mgmt/format.rs)

### [`src/mgmt/browse.rs`](../src/mgmt/browse.rs)

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct BrowseQs`
- `fn collections_page`
- `fn collection_rows_page`
- `struct AnonCapsForm`
- `fn update_anon_caps` — POST `/admin/tenants/{tenant}/collections/{coll}/anon-caps`.
- `struct AdminCreateIndexBody`
- `fn create_index_admin` — POST `/admin/tenants/{id}/collections/{coll}/_indexes`
- `fn drop_index_admin` — DELETE `/admin/tenants/{id}/collections/{coll}/_indexes/{name}`
- `fn explain_admin` — POST `/admin/tenants/{id}/collections/{coll}/_explain`

**Imports from:**

- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)
- [`src/query/authorizer.rs`](../src/query/authorizer.rs)
- [`src/query/executor.rs`](../src/query/executor.rs)
- [`src/query/filter.rs`](../src/query/filter.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)
- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

### [`src/mgmt/docs.rs`](../src/mgmt/docs.rs)

_Admin-UI handler for the on-disk CHANGELOG viewer._

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct NavItem`
- `fn changelog_page`

### [`src/mgmt/format.rs`](../src/mgmt/format.rs)

_Small formatting helpers shared across the admin UI._

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `fn humanize_bytes` — Format a byte count as `"NNN B"` / `"N.N KB"` / `"N.N MB"` / `"N.NN GB"`.

**Imported by:**

- [`src/mgmt/backups.rs`](../src/mgmt/backups.rs)
- [`src/mgmt/public_files.rs`](../src/mgmt/public_files.rs)
- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)

### [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Declares submodules:**

- [`src/mgmt/audit.rs`](../src/mgmt/audit.rs)
- [`src/mgmt/backups.rs`](../src/mgmt/backups.rs)
- [`src/mgmt/browse.rs`](../src/mgmt/browse.rs)
- [`src/mgmt/docs.rs`](../src/mgmt/docs.rs)
- [`src/mgmt/format.rs`](../src/mgmt/format.rs)
- [`src/mgmt/public_files.rs`](../src/mgmt/public_files.rs)
- [`src/mgmt/routes.rs`](../src/mgmt/routes.rs)
- [`src/mgmt/rpc_admin.rs`](../src/mgmt/rpc_admin.rs)
- [`src/mgmt/signed_bytes.rs`](../src/mgmt/signed_bytes.rs)
- [`src/mgmt/tenant_files.rs`](../src/mgmt/tenant_files.rs)
- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)
- [`src/mgmt/tokens.rs`](../src/mgmt/tokens.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `mod audit`
- `mod backups`
- `mod browse`
- `mod docs`
- `mod format`
- `mod public_files`
- `mod routes`
- `mod rpc_admin`
- `mod signed_bytes`
- `mod tenant_files`
- `mod tenants`
- `mod tokens`

### [`src/mgmt/public_files.rs`](../src/mgmt/public_files.rs)

_Admin UI for the host-level public bucket. Provides list, upload, delete,_

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct PublicFilesState`
- `struct PublicFileRow`
- `struct Counts` — File counts broken down by visibility.
- `struct DiskView`
- `struct ListQs`
- `struct PendingRevokeRow`
- `struct OrphanBucketRow`
- `fn build_disk_view` — Build a `DiskView` for the Garage data volume. If `/var/lib/garage` is
- `fn list_page`
- `struct UploadFields`
- `fn parse_upload_fields` — Parse and validate the multipart fields from an admin upload form.
- `fn upload_submit`
- `fn delete_submit`
- `fn reconcile_page`
- `struct ReconcileForm`
- `fn reconcile_apply`
- `fn admin_stream_bytes` — GET /drust/admin/files/<key>/bytes
- `struct AdminSignRequest`
- `struct AdminSignResponse`
- `fn admin_sign_url` — POST /drust/admin/files/<key>/sign

**Imports from:**

- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/mgmt/format.rs`](../src/mgmt/format.rs)
- [`src/storage/files.rs`](../src/storage/files.rs)
- [`src/storage/garage.rs`](../src/storage/garage.rs)

**Imported by:**

- [`src/mgmt/routes.rs`](../src/mgmt/routes.rs)
- [`src/mgmt/tenant_files.rs`](../src/mgmt/tenant_files.rs)

### [`src/mgmt/routes.rs`](../src/mgmt/routes.rs)

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct MgmtState`
- `fn build_mgmt_router`

**Imports from:**

- [`src/auth/admin.rs`](../src/auth/admin.rs)
- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/auth/session.rs`](../src/auth/session.rs)
- [`src/mgmt/public_files.rs`](../src/mgmt/public_files.rs)
- [`src/mgmt/tenant_files.rs`](../src/mgmt/tenant_files.rs)
- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)

### [`src/mgmt/rpc_admin.rs`](../src/mgmt/rpc_admin.rs)

_Admin-UI handlers for the `_rpc` virtual collection page._

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct RpcListQs`
- `fn rpc_index` — `GET /admin/tenants/{id}/_rpc` — list stored RPCs for the tenant.
- `fn rpc_new_form` — `GET /admin/tenants/{id}/_rpc/new` — render the empty create form.
- `fn rpc_edit_form` — `GET /admin/tenants/{id}/_rpc/{name}/edit` — render the form pre-filled
- `struct RpcFormBody`
- `fn rpc_save` — `POST /admin/tenants/{id}/_rpc/new` (create) and
- `struct RpcTestRunForm`
- `fn rpc_test_form` — `GET /admin/tenants/{id}/_rpc/{name}/test` — render the test playground
- `fn rpc_test_run` — `POST /admin/tenants/{id}/_rpc/{name}/test/run` — execute the RPC with
- `fn rpc_delete` — `POST /admin/tenants/{id}/_rpc/{name}/delete` — drop a stored RPC.

**Imports from:**

- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)
- [`src/rpc/params.rs`](../src/rpc/params.rs)
- [`src/rpc/registry.rs`](../src/rpc/registry.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)
- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

### [`src/mgmt/signed_bytes.rs`](../src/mgmt/signed_bytes.rs)

_Public (unauth) GET handlers that serve a drust-signed download URL._

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct SignedBytesState`
- `struct SigQs`
- `fn admin_signed_bytes` — GET /drust/s/admin/{key}?e=<expires>&t=<token>&d=<0|1>
- `fn tenant_signed_bytes` — GET /drust/s/t/{tenant}/{key}?e=<expires>&t=<token>&d=<0|1>

**Imports from:**

- [`src/storage/files.rs`](../src/storage/files.rs)
- [`src/storage/garage.rs`](../src/storage/garage.rs)
- [`src/storage/signed_url.rs`](../src/storage/signed_url.rs)

### [`src/mgmt/tenant_files.rs`](../src/mgmt/tenant_files.rs)

_Tenant-side file handlers (private bytes proxy, upload/list/get/delete, sign)._

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct SignRequest`
- `struct SignResponse`
- `struct TenantFilesState`
- `fn stream_bytes` — GET /drust/t/<tenant>/files/<key>/bytes
- `fn sign_url` — POST /drust/t/<tenant>/files/<key>/sign
- `struct UploadResponse`
- `struct ListResponse`
- `fn upload` — POST /drust/t/<tenant>/files
- `fn list` — GET /drust/t/<tenant>/files
- `fn get_one` — GET /drust/t/<tenant>/files/<key>
- `fn delete_one` — DELETE /drust/t/<tenant>/files/<key>

**Imports from:**

- [`src/mgmt/public_files.rs`](../src/mgmt/public_files.rs)
- [`src/storage/files.rs`](../src/storage/files.rs)
- [`src/storage/garage.rs`](../src/storage/garage.rs)

**Imported by:**

- [`src/mgmt/routes.rs`](../src/mgmt/routes.rs)
- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

### [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct TenantsState`
- `struct CreateTenantJson`
- `struct CreateTenantForm`
- `struct CreatedResp`
- `struct InitialTokens`
- `struct TenantInfo`
- `fn valid_slug`
- `fn list_page_axum`
- `fn create_tenant_json` — Roll back everything `make_tenant_inner` did for `id`: delete token rows,
- `fn create_tenant_form`
- `fn soft_delete_tenant`
- `fn soft_delete_tenant_form`
- `struct ToggleSelfRegisterBody`
- `fn toggle_self_register` — `POST /admin/tenants/{id}/allow-self-register`
- `struct TenantFilesPerPageOption`
- `struct TenantFilesListQs`
- `fn tenant_files_admin_page` — GET /admin/tenants/{id}/files

**Imports from:**

- [`src/auth/bearer.rs`](../src/auth/bearer.rs)
- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/mgmt/format.rs`](../src/mgmt/format.rs)
- [`src/storage/garage.rs`](../src/storage/garage.rs)
- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

**Imported by:**

- [`src/mgmt/browse.rs`](../src/mgmt/browse.rs)
- [`src/mgmt/routes.rs`](../src/mgmt/routes.rs)
- [`src/mgmt/rpc_admin.rs`](../src/mgmt/rpc_admin.rs)
- [`src/mgmt/tokens.rs`](../src/mgmt/tokens.rs)

### [`src/mgmt/tokens.rs`](../src/mgmt/tokens.rs)

**Declared by:**

- [`src/mgmt/mod.rs`](../src/mgmt/mod.rs)

**Public items:**

- `struct TokenSlotInfo`
- `struct RerollResp`
- `fn reroll_token_json`
- `struct RerollForm`
- `fn reroll_token_form`
- `fn detail_redirect` — `GET /admin/tenants/{id}` — preserved as a 302 to `/_api_keys`. The old
- `fn api_keys_page` — `GET /admin/tenants/{id}/_api_keys` — virtual collection that renders the

**Imports from:**

- [`src/auth/bearer.rs`](../src/auth/bearer.rs)
- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)
- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

<a id="srcquery"></a>

## `src/query/`

### [`src/query/authorizer.rs`](../src/query/authorizer.rs)

**Declared by:**

- [`src/query/mod.rs`](../src/query/mod.rs)

**Public items:**

- `fn detach_authorizer` — Replace the connection's authorizer with a permissive allow-all callback.
- `fn attach_readonly_authorizer` — Attach the read-only authorizer. Every SQL action is inspected; anything

**Imports from:**

- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

**Imported by:**

- [`src/mcp/tools/exploration.rs`](../src/mcp/tools/exploration.rs)
- [`src/mcp/tools/read.rs`](../src/mcp/tools/read.rs)
- [`src/mgmt/browse.rs`](../src/mgmt/browse.rs)
- [`src/rpc/prepare.rs`](../src/rpc/prepare.rs)
- [`src/tenant/records.rs`](../src/tenant/records.rs)

### [`src/query/executor.rs`](../src/query/executor.rs)

**Declared by:**

- [`src/query/mod.rs`](../src/query/mod.rs)

**Public items:**

- `struct QueryResult`
- `enum ExecError`
- `fn sql_hash`
- `fn execute_read_query`
- `fn execute_read_query_admin` — Like [`execute_read_query`] but skips the read-only authorizer. Only
- `fn execute_read_query_with_named` — Same as [`execute_read_query`] but binds `:name`-style placeholders from a
- `struct InterruptGuard` — Spawn a task that interrupts the connection if a deadline passes.

**Imports from:**

- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

**Imported by:**

- [`src/mcp/tools/exploration.rs`](../src/mcp/tools/exploration.rs)
- [`src/mcp/tools/read.rs`](../src/mcp/tools/read.rs)
- [`src/mgmt/browse.rs`](../src/mgmt/browse.rs)
- [`src/rpc/handler.rs`](../src/rpc/handler.rs)
- [`src/tenant/query_endpoint.rs`](../src/tenant/query_endpoint.rs)
- [`src/tenant/records.rs`](../src/tenant/records.rs)

### [`src/query/filter.rs`](../src/query/filter.rs)

**Declared by:**

- [`src/query/mod.rs`](../src/query/mod.rs)

**Public items:**

- `enum SortDir`
- `struct ListParams`
- `fn parse_sort`
- `fn build_list_sql`
- `fn build_count_sql`

**Imported by:**

- [`src/mcp/tools/exploration.rs`](../src/mcp/tools/exploration.rs)
- [`src/mgmt/browse.rs`](../src/mgmt/browse.rs)
- [`src/tenant/records.rs`](../src/tenant/records.rs)

### [`src/query/mod.rs`](../src/query/mod.rs)

**Declares submodules:**

- [`src/query/authorizer.rs`](../src/query/authorizer.rs)
- [`src/query/executor.rs`](../src/query/executor.rs)
- [`src/query/filter.rs`](../src/query/filter.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `mod authorizer`
- `mod executor`
- `mod filter`

<a id="srcrpc"></a>

## `src/rpc/`

### [`src/rpc/handler.rs`](../src/rpc/handler.rs)

_REST handler for `POST /t/{tenant}/rpc/{name}`._

**Declared by:**

- [`src/rpc/mod.rs`](../src/rpc/mod.rs)

**Public items:**

- `fn call_rpc`

**Imports from:**

- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/query/executor.rs`](../src/query/executor.rs)
- [`src/rpc/params.rs`](../src/rpc/params.rs)
- [`src/rpc/registry.rs`](../src/rpc/registry.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/rpc/mod.rs`](../src/rpc/mod.rs)

_RPC subsystem: stored Supabase-style named SQL functions._

**Declares submodules:**

- [`src/rpc/handler.rs`](../src/rpc/handler.rs)
- [`src/rpc/params.rs`](../src/rpc/params.rs)
- [`src/rpc/prepare.rs`](../src/rpc/prepare.rs)
- [`src/rpc/registry.rs`](../src/rpc/registry.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `mod handler`
- `mod params`
- `mod prepare`
- `mod registry`

### [`src/rpc/params.rs`](../src/rpc/params.rs)

_RPC parameter schema and request validation._

**Declared by:**

- [`src/rpc/mod.rs`](../src/rpc/mod.rs)

**Public items:**

- `enum ParamType`
- `struct ParamSpec`
- `enum ParamError`
- `fn parse_params_json`
- `fn validate_and_bind` — Validate an incoming JSON body against a declared param list and
- `enum BoundValue`

**Imported by:**

- [`src/mgmt/rpc_admin.rs`](../src/mgmt/rpc_admin.rs)
- [`src/rpc/handler.rs`](../src/rpc/handler.rs)
- [`src/rpc/registry.rs`](../src/rpc/registry.rs)

### [`src/rpc/prepare.rs`](../src/rpc/prepare.rs)

_Prepare-time SQL safety: reject anything the read-only authorizer_

**Declared by:**

- [`src/rpc/mod.rs`](../src/rpc/mod.rs)

**Public items:**

- `enum PrepareError`
- `fn validate_rpc_sql` — Open a read-only-style preparation: attach the authorizer, prepare

**Imports from:**

- [`src/query/authorizer.rs`](../src/query/authorizer.rs)
- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

### [`src/rpc/registry.rs`](../src/rpc/registry.rs)

_Persistence wrapper around the `_system_rpc` table._

**Declared by:**

- [`src/rpc/mod.rs`](../src/rpc/mod.rs)

**Public items:**

- `struct StoredRpc`
- `enum RegistryError`
- `fn lookup`
- `fn list`
- `fn create`
- `fn update`
- `fn delete`
- `fn increment` — Bump the appropriate counter and `last_called_at`. Bypasses the

**Imports from:**

- [`src/rpc/params.rs`](../src/rpc/params.rs)
- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

**Imported by:**

- [`src/mgmt/rpc_admin.rs`](../src/mgmt/rpc_admin.rs)
- [`src/rpc/handler.rs`](../src/rpc/handler.rs)

<a id="srcsafety"></a>

## `src/safety/`

### [`src/safety/audit.rs`](../src/safety/audit.rs)

**Declared by:**

- [`src/safety/mod.rs`](../src/safety/mod.rs)

**Public items:**

- `struct AuditExtra`
- `struct DefaultAuditExtra`
- `struct AuditEntry`
- `fn should_log_body` — Spec S6: path whitelist gating future body logging. Auth bodies must never be persisted.
- `struct AuditLog` — Audit-log writer. Non-blocking append: callers send entries through
- `struct AuditWriterHandle` — Returned by `AuditLog::start`. Holding the handle lets graceful

**Imported by:**

- [`src/mgmt/audit.rs`](../src/mgmt/audit.rs)
- [`src/tenant/auth_routes.rs`](../src/tenant/auth_routes.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/safety/ip.rs`](../src/safety/ip.rs)

**Declared by:**

- [`src/safety/mod.rs`](../src/safety/mod.rs)

**Public items:**

- `fn client_ip` — Returns the verified client IP behind a known proxy chain.

### [`src/safety/mod.rs`](../src/safety/mod.rs)

**Declares submodules:**

- [`src/safety/audit.rs`](../src/safety/audit.rs)
- [`src/safety/ip.rs`](../src/safety/ip.rs)
- [`src/safety/rate_limit.rs`](../src/safety/rate_limit.rs)
- [`src/safety/rate_limit_ip.rs`](../src/safety/rate_limit_ip.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `mod audit`
- `mod ip`
- `mod rate_limit`
- `mod rate_limit_ip`

### [`src/safety/rate_limit.rs`](../src/safety/rate_limit.rs)

**Declared by:**

- [`src/safety/mod.rs`](../src/safety/mod.rs)

**Public items:**

- `struct RateLimiter` — Token-bucket rate limiter, keyed on caller-supplied opaque strings
- `struct RateLimitedError`

**Imported by:**

- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/safety/rate_limit_ip.rs`](../src/safety/rate_limit_ip.rs)

**Declared by:**

- [`src/safety/mod.rs`](../src/safety/mod.rs)

**Public items:**

- `struct IpRateLimit`

**Imported by:**

- [`src/tenant/router.rs`](../src/tenant/router.rs)

<a id="srcstorage"></a>

## `src/storage/`

### [`src/storage/disk.rs`](../src/storage/disk.rs)

_Filesystem statistics helper used by upload handlers to enforce the_

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `struct DiskStats`
- `fn disk_stats`

### [`src/storage/files.rs`](../src/storage/files.rs)

_Shared file-storage helpers used by both admin and tenant upload flows._

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `enum Owner`
- `enum Visibility`
- `enum Disposition`
- `fn bucket_for` — Bucket for the given visibility. Only two buckets exist host-wide:
- `fn compose_key` — Build the object key for a new upload. Admin uploads land at the
- `fn bucket_for_upload` — Backward-compat shim: some call sites ask for just the bucket based
- `fn build_public_url`
- `fn default_cache_control`
- `struct FileRow`
- `fn map_file_row`

**Imported by:**

- [`src/mcp/tools/files.rs`](../src/mcp/tools/files.rs)
- [`src/mgmt/public_files.rs`](../src/mgmt/public_files.rs)
- [`src/mgmt/signed_bytes.rs`](../src/mgmt/signed_bytes.rs)
- [`src/mgmt/tenant_files.rs`](../src/mgmt/tenant_files.rs)

### [`src/storage/garage.rs`](../src/storage/garage.rs)

_Garage S3 client. Thin wrapper over `object_store::aws::AmazonS3` for the_

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `struct GarageClient`
- `struct BucketInfo`
- `struct BucketUsage`
- `struct ObjectSummary`
- `fn ascii_fallback_filename` — ASCII-safe fallback for the plain `filename="..."` token in

**Imports from:**

- [`src/config.rs`](../src/config.rs)

**Imported by:**

- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/mgmt/public_files.rs`](../src/mgmt/public_files.rs)
- [`src/mgmt/signed_bytes.rs`](../src/mgmt/signed_bytes.rs)
- [`src/mgmt/tenant_files.rs`](../src/mgmt/tenant_files.rs)
- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)

### [`src/storage/janitor.rs`](../src/storage/janitor.rs)

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `fn sweep_expired_sessions` — Sweep expired sessions across every active tenant. Returns the total

### [`src/storage/meta.rs`](../src/storage/meta.rs)

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `fn open_meta`
- `fn bootstrap_admin`

**Imports from:**

- [`src/auth/admin.rs`](../src/auth/admin.rs)

### [`src/storage/mod.rs`](../src/storage/mod.rs)

**Declares submodules:**

- [`src/storage/disk.rs`](../src/storage/disk.rs)
- [`src/storage/files.rs`](../src/storage/files.rs)
- [`src/storage/garage.rs`](../src/storage/garage.rs)
- [`src/storage/janitor.rs`](../src/storage/janitor.rs)
- [`src/storage/meta.rs`](../src/storage/meta.rs)
- [`src/storage/pool.rs`](../src/storage/pool.rs)
- [`src/storage/quota.rs`](../src/storage/quota.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)
- [`src/storage/schema_cache.rs`](../src/storage/schema_cache.rs)
- [`src/storage/signed_url.rs`](../src/storage/signed_url.rs)
- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `mod disk`
- `mod files`
- `mod garage`
- `mod janitor`
- `mod meta`
- `mod pool`
- `mod quota`
- `mod schema`
- `mod schema_cache`
- `mod signed_url`
- `mod tenant_db`

### [`src/storage/pool.rs`](../src/storage/pool.rs)

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `struct TenantPool`
- `type SharedTenantPool`
- `struct TenantRegistry`

**Imports from:**

- [`src/storage/schema_cache.rs`](../src/storage/schema_cache.rs)
- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

**Imported by:**

- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/mcp/tools/index.rs`](../src/mcp/tools/index.rs)
- [`src/mcp/tools/owner_field.rs`](../src/mcp/tools/owner_field.rs)
- [`src/mcp/tools/user.rs`](../src/mcp/tools/user.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/storage/quota.rs`](../src/storage/quota.rs)

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `enum QuotaError`
- `fn check_file_size`
- `fn check_row_count`

### [`src/storage/schema.rs`](../src/storage/schema.rs)

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `fn is_protected_collection` — System-managed collections are drop-protected. Any name starting with
- `enum DmlVerb`
- `fn default_anon_caps` — Default capability set — anon may SELECT only. Used when a row is
- `fn parse_anon_caps_json` — Parse a JSON array of lowercase verb strings into a `BTreeSet`.
- `fn anon_caps_to_json` — Serialise a capability set as a sorted JSON array (deterministic).
- `struct Collection`
- `struct Field`
- `struct IndexInfo`
- `struct CollectionSchema`
- `fn list_collections`
- `fn describe_collection`
- `fn collection_exists`
- `fn find_fk_referrers` — Find every other user-table that has a foreign-key column pointing at
- `fn write_anon_caps` — Insert / replace the anon_caps row for a collection. Caller must
- `fn set_owner_field` — Set or clear `owner_field` + `read_scope` for a collection. Pass `None`
- `fn read_owner_field` — Read the current `(owner_field, read_scope)` pair. Returns `(None, None)`
- `fn delete_collection_meta` — Drop the metadata row for a collection. Called from drop_collection.
- `fn has_dml_cap` — Returns true if the caller's role is permitted to perform `verb` on

**Imports from:**

- [`src/tenant/router.rs`](../src/tenant/router.rs)

**Imported by:**

- [`src/mcp/tools/exploration.rs`](../src/mcp/tools/exploration.rs)
- [`src/mcp/tools/index.rs`](../src/mcp/tools/index.rs)
- [`src/mcp/tools/schema.rs`](../src/mcp/tools/schema.rs)
- [`src/mcp/tools/write.rs`](../src/mcp/tools/write.rs)
- [`src/mgmt/browse.rs`](../src/mgmt/browse.rs)
- [`src/mgmt/rpc_admin.rs`](../src/mgmt/rpc_admin.rs)
- [`src/mgmt/tokens.rs`](../src/mgmt/tokens.rs)
- [`src/storage/schema_cache.rs`](../src/storage/schema_cache.rs)
- [`src/tenant/collections.rs`](../src/tenant/collections.rs)
- [`src/tenant/records.rs`](../src/tenant/records.rs)

### [`src/storage/schema_cache.rs`](../src/storage/schema_cache.rs)

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `struct SchemaCache`

**Imports from:**

- [`src/storage/schema.rs`](../src/storage/schema.rs)
- [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

**Imported by:**

- [`src/storage/pool.rs`](../src/storage/pool.rs)

### [`src/storage/signed_url.rs`](../src/storage/signed_url.rs)

_Drust-minted, drust-served signed URLs for private file downloads._

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `enum Owner`
- `fn mint`
- `fn verify`
- `fn build_url` — Build the drust-public URL for a signed download. The URL format is:

**Imported by:**

- [`src/mgmt/signed_bytes.rs`](../src/mgmt/signed_bytes.rs)

### [`src/storage/tenant_db.rs`](../src/storage/tenant_db.rs)

**Declared by:**

- [`src/storage/mod.rs`](../src/storage/mod.rs)

**Public items:**

- `enum TenantIdError`
- `fn validate_tenant_id`
- `fn tenant_dir`
- `fn tenant_data_path`
- `fn open_write`
- `fn open_read`

**Imported by:**

- [`src/mgmt/browse.rs`](../src/mgmt/browse.rs)
- [`src/mgmt/rpc_admin.rs`](../src/mgmt/rpc_admin.rs)
- [`src/mgmt/tenants.rs`](../src/mgmt/tenants.rs)
- [`src/mgmt/tokens.rs`](../src/mgmt/tokens.rs)
- [`src/query/authorizer.rs`](../src/query/authorizer.rs)
- [`src/query/executor.rs`](../src/query/executor.rs)
- [`src/rpc/prepare.rs`](../src/rpc/prepare.rs)
- [`src/rpc/registry.rs`](../src/rpc/registry.rs)
- [`src/storage/pool.rs`](../src/storage/pool.rs)
- [`src/storage/schema_cache.rs`](../src/storage/schema_cache.rs)

<a id="srctenant"></a>

## `src/tenant/`

### [`src/tenant/admin_user_routes.rs`](../src/tenant/admin_user_routes.rs)

_Service-only admin endpoints for managing users within a tenant._

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `struct CreateUserBody`
- `struct UpdateUserBody`
- `struct ListQuery`
- `fn create_user_handler`
- `fn list_users_handler`
- `fn get_user_handler`
- `fn update_user_handler`
- `fn delete_user_handler`
- `fn revoke_sessions_handler`

**Imports from:**

- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/tenant/auth_routes.rs`](../src/tenant/auth_routes.rs)

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `struct RegisterBody`
- `fn register_handler`
- `struct LoginBody`
- `fn login_handler`
- `fn logout_handler`
- `fn logout_all_handler`
- `fn me_get_handler`
- `struct PatchMeBody`
- `fn me_patch_handler`
- `struct ChangePasswordBody`
- `fn me_password_handler`

**Imports from:**

- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/auth/user.rs`](../src/auth/user.rs)
- [`src/safety/audit.rs`](../src/safety/audit.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/tenant/collections.rs`](../src/tenant/collections.rs)

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `fn list_handler`
- `fn describe_handler`
- `struct CreateIndexBody`
- `fn create_index_handler`
- `fn drop_index_handler`

**Imports from:**

- [`src/storage/schema.rs`](../src/storage/schema.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/tenant/events.rs`](../src/tenant/events.rs)

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `enum Event`
- `struct EventBus`

**Imported by:**

- [`src/mcp/server.rs`](../src/mcp/server.rs)
- [`src/mcp/tools/write.rs`](../src/mcp/tools/write.rs)
- [`src/tenant/records.rs`](../src/tenant/records.rs)
- [`src/tenant/sse.rs`](../src/tenant/sse.rs)

### [`src/tenant/mcp_dispatch.rs`](../src/tenant/mcp_dispatch.rs)

_Axum handler that forwards `/t/:tenant/mcp` traffic to the_

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `fn dispatch`

**Imports from:**

- [`src/mcp/http_registry.rs`](../src/mcp/http_registry.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Declares submodules:**

- [`src/tenant/admin_user_routes.rs`](../src/tenant/admin_user_routes.rs)
- [`src/tenant/auth_routes.rs`](../src/tenant/auth_routes.rs)
- [`src/tenant/collections.rs`](../src/tenant/collections.rs)
- [`src/tenant/events.rs`](../src/tenant/events.rs)
- [`src/tenant/mcp_dispatch.rs`](../src/tenant/mcp_dispatch.rs)
- [`src/tenant/owner_field.rs`](../src/tenant/owner_field.rs)
- [`src/tenant/query_endpoint.rs`](../src/tenant/query_endpoint.rs)
- [`src/tenant/records.rs`](../src/tenant/records.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)
- [`src/tenant/sse.rs`](../src/tenant/sse.rs)

**Declared by:**

- [`src/lib.rs`](../src/lib.rs)

**Public items:**

- `mod admin_user_routes`
- `mod auth_routes`
- `mod collections`
- `mod events`
- `mod mcp_dispatch`
- `mod owner_field`
- `mod query_endpoint`
- `mod records`
- `mod router`
- `mod sse`
- `struct TenantStack`
- `fn build_tenant_router`

**Imports from:**

- [`src/mcp/http_registry.rs`](../src/mcp/http_registry.rs)
- [`src/mgmt/tenant_files.rs`](../src/mgmt/tenant_files.rs)

### [`src/tenant/owner_field.rs`](../src/tenant/owner_field.rs)

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `struct SetOwnerFieldBody`
- `fn set_owner_field_handler`
- `fn clear_owner_field_handler`

**Imports from:**

- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/tenant/query_endpoint.rs`](../src/tenant/query_endpoint.rs)

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `struct QueryBody`
- `fn query_handler`
- `struct ExplainBody`
- `fn explain_handler`

**Imports from:**

- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/query/executor.rs`](../src/query/executor.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/tenant/records.rs`](../src/tenant/records.rs)

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `struct ListQs`
- `fn list_handler`
- `fn get_handler`
- `struct DataBody`
- `fn create_handler`
- `fn update_handler`
- `fn delete_handler`

**Imports from:**

- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/query/authorizer.rs`](../src/query/authorizer.rs)
- [`src/query/executor.rs`](../src/query/executor.rs)
- [`src/query/filter.rs`](../src/query/filter.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)
- [`src/tenant/events.rs`](../src/tenant/events.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

### [`src/tenant/router.rs`](../src/tenant/router.rs)

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `struct TenantAuthState`
- `enum TokenRole`
- `struct TenantRef`
- `fn bearer_auth_layer`
- `fn require_service`

**Imports from:**

- [`src/auth/bearer.rs`](../src/auth/bearer.rs)
- [`src/auth/middleware.rs`](../src/auth/middleware.rs)
- [`src/safety/audit.rs`](../src/safety/audit.rs)
- [`src/safety/rate_limit.rs`](../src/safety/rate_limit.rs)
- [`src/safety/rate_limit_ip.rs`](../src/safety/rate_limit_ip.rs)
- [`src/storage/pool.rs`](../src/storage/pool.rs)

**Imported by:**

- [`src/rpc/handler.rs`](../src/rpc/handler.rs)
- [`src/rpc/registry.rs`](../src/rpc/registry.rs)
- [`src/storage/schema.rs`](../src/storage/schema.rs)
- [`src/tenant/admin_user_routes.rs`](../src/tenant/admin_user_routes.rs)
- [`src/tenant/auth_routes.rs`](../src/tenant/auth_routes.rs)
- [`src/tenant/collections.rs`](../src/tenant/collections.rs)
- [`src/tenant/mcp_dispatch.rs`](../src/tenant/mcp_dispatch.rs)
- [`src/tenant/owner_field.rs`](../src/tenant/owner_field.rs)
- [`src/tenant/query_endpoint.rs`](../src/tenant/query_endpoint.rs)
- [`src/tenant/records.rs`](../src/tenant/records.rs)
- [`src/tenant/sse.rs`](../src/tenant/sse.rs)

### [`src/tenant/sse.rs`](../src/tenant/sse.rs)

**Declared by:**

- [`src/tenant/mod.rs`](../src/tenant/mod.rs)

**Public items:**

- `fn subscribe_handler`

**Imports from:**

- [`src/tenant/events.rs`](../src/tenant/events.rs)
- [`src/tenant/router.rs`](../src/tenant/router.rs)

