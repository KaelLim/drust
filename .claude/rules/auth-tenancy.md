---
paths:
  - "src/auth/**"
  - "src/oauth/**"
  - "src/mgmt/tenant_authz.rs"
  - "src/mgmt/admin_team.rs"
  - "src/mgmt/cli_device.rs"
  - "src/mgmt/oauth_login.rs"
  - "src/mgmt/quota_admin.rs"
  - "src/mgmt/tenant_cap.rs"
  - "src/mgmt/tenants/**"
  - "src/mgmt/mcp_oauth/**"
  - "src/tenant/auth_cache.rs"
  - "src/tenant/oauth_routes.rs"
  - "src/tenant/admin_user_routes.rs"
---

# Auth, roles, and tenant ownership — mechanism

Fires when you touch the auth plane. The *obligations* (the six ownership sites, the
auth-cache eviction hook list, the `sees_all_tenants` lockstep rule) live in `CLAUDE.md`
because they bind writes across `mgmt/`, `tenant/`, `auth/` and `mcp/` and no honest glob
covers them. This file is the **how**.

## Bearer resolution and the auth cache

Per-tenant anon + service tokens live in `meta.sqlite`, hashed **and** stored plaintext
alongside (so the admin UI can echo the key and MCP `whoami` the anon key — this is why a
backup archive is a secret store). Resolution happens in `bearer_auth_layer`, which also
wires rate-limiting and audit; denials get `error_code: HTTP_<status>`.

`src/tenant/auth_cache.rs` is a process-local invalidate-on-write `DashMap<token_hash,
CachedAuth>` consulted **after** the rate-limit probe, so a hit skips the global `meta`
mutex and the bearer CTE. **Negatives are never cached.** A per-entry 10 s safety TTL
(`safety_ttl`, injectable in tests) bounds any missed invalidation hook to ≤ 10 s — which
is also why the out-of-process `set_admin_role` break-glass CLI takes effect on the data
plane within 10 s without any eviction call.

Because the hit path skips the CTE, it skips the only `deleted_at IS NULL` filter in the
request — so **all three arms — both cache arms and the DB arm — open the pool with
`get_if_live`, never `get_or_create`**, and 404 on `None`. The DB arm needs it too: the CTE
proves `deleted_at IS NULL` but releases the `meta` lock before the open, and
`soft_delete_tenant`'s UPDATE + rename + pool evict can all land in between.
`soft_delete_tenant` renames the tenant directory and evicts the pool *before* it clears
the cache, and a request that read its entry earlier can arrive at the open at any later
point; creating on open there rebuilds `tenants/<id>` outside `_trash`,
where the janitor never sweeps, and then serves the request against the fresh database.

The bearer CTE's column numbering is load-bearing and **must not be renumbered**: cols 8/9
carry the file caps, cols 11/12 the PAT admin `role` and the tenant `owner_admin_id`, col
13 the `quota_tier`. Both `CachedAuth` variants carry `quota_tier`; the hit path
reconstructs it.

The PAT deny in that CTE is a **fail-closed allow-list**: resolve as `Service` only if the
PAT admin's role is in the sees-all set OR the admin owns this tenant — else
`403 PAT_TENANT_DENIED` (alias `WRITE_DENIED`). Written as an allow-list so a future
fourth role cannot fail open. Cache-safe because a `CachedAuth::Bearer` hit is bound to one
tenant and falls through on mismatch.

## Roles

Three tiers, `owner > admin > member`. Helpers live in `tenant_authz`:
`sees_all_tenants` (owner|admin), `can_manage_members` (owner|admin),
`can_manage_privileged` (owner only), `sees_team_page` (owner|admin).
`tenant_access_for` is the single ownership predicate.

> [!WARNING]
> A new tenant-visibility decision reads `sees_all_tenants`, never a bare `is_owner`. A new
> privileged-role mutation requires `can_manage_privileged`. Host-wide surfaces with no
> `{id}` in the path get `require_owner_layer` — the ownership route guard cannot see them,
> which is exactly how `/admin/files*` stayed ungated until the 2026-07-29 audit.

Management-plane answers for a non-visible tenant are **404, never 403** — the admin plane
must not be an existence oracle. The data-plane PAT deny is 403.

Immutability: `change_role`'s last-owner guard fires on `owner → any non-owner`, and
`remove_admin` guards the last owner, so the system can never reach zero owners through the
UI or API. Break-glass is the `set_admin_role` binary.

`admin_team.rs` invitations create OAuth-only rows (`$oauth-only$` sentinel) because drust
has no mail transport — an "invite" is really "allowlist this email to OAuth-login with
this role". `validate_email` rejects display-name, bracketed, multi-`@` and dotless forms
so an address-book paste cannot create junk rows. The batch face runs the whole list in one
`meta.sqlite` transaction and silently dedupes.

## End-user auth

Per-tenant `_system_users` + `_system_sessions`; tokens are `drust_user_*`, SHA-256-hashed,
sliding 30 d. argon2id verification runs against a fixed `DUMMY_HASH` when the user does not
exist, to equalize timing. Brute-force defense is per-IP: 5/min on login, 3/min on register,
with the IP taken as `XFF[len - DRUST_TRUSTED_PROXIES]` (default 2 = `XFF[-2]`, the bare-metal
nginx → Caddy chain; Compose 1; the image 0 = the TCP peer; the chain is every
`X-Forwarded-For` field line concatenated in order) through `safety::ip::ClientIp` —
never a hand-rolled `X-Forwarded-For` / `X-Real-IP` / `Forwarded` read, a direct
`client_ip_with` call, or a literal fallback address (the source pin
`safety::ip::tests::every_client_ip_consumer_keys_on_the_real_peer` enforces the header and
call rules and the common loopback-peer spellings in any consumer file; `ClientIp`/`peer_addr` themselves are held by
behavioural tests in `auth_login.rs` and `admin_login_rate_limit.rs`; the fallback is the real
TCP peer from `ConnectInfo`, which `main` serves with). Self-registration is opt-in per tenant.

`password_hash = "$oauth-only$"` is a sentinel that blocks password login and `/me/password`
(`409 OAUTH_ONLY_NO_PASSWORD`).

## OAuth

Two independent flows share `src/oauth/` (an `OauthProvider` trait plus Google and GitHub
adapters): **admin** login into the management plane, and **per-tenant** login for a
tenant's own end users. The per-tenant flow returns to the frontend as
`<cb>#access_token=drust_user_xxx` — the Supabase/Auth0 URL-fragment pattern.

Google's `id_token` is base64-decoded **without signature verification**, which is correct
here per OIDC Core §3.1.3.7: confidential client, token endpoint reached over TLS.

Allowlisted redirect URIs are exact-match and **re-checked at callback**, TOCTOU-safe.
Both callbacks are per-IP rate-limited at 5/min. The per-tenant start and callback also
validate that the tenant exists in `meta` **before** opening the pool, and open it with the
create-free `get_if_live` — the meta check prevents the disk-fill DoS from arbitrary ids, the
accessor closes the soft-delete race after it. `register` filters `deleted_at IS NULL` in the
same `allow_self_register` read, so a deleted tenant answers like an unknown id, and `login`
opens with `get_if_live` too.

The admin **password** login (`login_submit`, `mgmt/routes.rs`) refuses
`Sec-Fetch-Site: cross-site` with `403 LOGIN_CROSS_SITE` before its per-IP limiter and
before touching `meta` (login CSRF). **Never add that check to the admin OAuth
callback**: the callback is a cross-site navigation from the IdP by construction, and its
login-CSRF defence is the state and PKCE cookies set at start and verified at callback.
No CSRF field on `/login`, on purpose — see AGENTS.md Adjudicated verdicts.

## CLI device flow

`POST /auth/cli/device/{start,poll}` is public and implements RFC-8628. `poll` returns
**HTTP 200 with a `{status}` body**, and the token exactly once, on `approved` — not a 4xx
state machine. The approval page sits behind `admin_session_layer`.

Approve/deny carry **double-submit CSRF**: a `drust_cli_csrf` cookie plus a hidden field,
HMAC-bound to **both `admin_id` and `user_code`** under a per-process secret, so a
cookie-tossed token cannot drive another admin's approval. Comparison is constant-time.

Approve mints a labeled `drust_pat_cli_*` PAT for the **approving session's** admin — never
a caller-supplied id. These are a labeled, expiring sub-namespace of admin PATs: the
`uniq_admin_tokens_active` index was relaxed so one unlabeled UI PAT and N labeled CLI PATs
coexist per admin, and expiry is enforced at **both** the admin-plane resolver and the
data-plane bearer CTE. They carry **no new privilege** — they resolve to
`AuthCtx::Service{admin_id}`, which is already cross-tenant. Both admin-PAT resolution arms
of `bearer_auth_layer` — cache hit and DB — also hand that expiry forward as the
`PatDeadline` request extension (v1.66.0, #976), because a
per-request gate alone let an ALREADY-OPEN rooms socket or SSE stream outlive the credential
— see `.claude/rules/background-jobs.md` §Realtime for what the realtime faces do with it.
The `AdminId` extension those same two arms insert is also what `ws_baseline_capture` keys
the E2′ `PatRevocation` on (the per-admin signal that ends a revoked admin's SSE streams).
A new credential source that resolves to `AuthCtx::Service{admin_id: Some(..)}` must insert
`AdminId` as well, or its SSE streams fall outside that signal.

Lifecycle routes live on the **public** router via a self-contained `resolve_cli_caller`
that returns JSON 401 and never a 302.

`admin_session_layer` is cookie-**or**-PAT. It tags each arm with an `AuthMethod`
extension (`Cookie` / `Pat`); a handler that must tell them apart reads it: MCP consent
to refuse a PAT, and the MCP revoke UI handlers (`ui::settings_revoke`,
`settings_revoke_all`, `team_revoke_mcp`) for the audit `auth_method`. The browser-302 invariant is preserved: no
bearer plus `Accept: text/html` still redirects to `/login`; only a present bearer or
`Accept: application/json` gets a JSON 401.

## MCP OAuth authorization server

### Grants, revocation and cleanup

The unit of revocation is the **grant** (`_mcp_oauth_grants`). Every revoke goes through
`mcp_oauth::store::revoke_mcp_grant(tx, &GrantOwner, grant_id, RevokeReason)`, which
revokes the grant, its refresh and access rows and upload tickets, and DELETEs its
unredeemed codes, all in the caller's transaction. The owner is bound in the SQL
(`WHERE id = ? AND admin_id = ?`); `GrantOwner` has no public field and no `Default`, and
is minted only by `GrantOwner::caller`, `GrantOwner::holder` (a `GrantRef`, which only
`store.rs` constructs; pinned to that one grant, so it can never revoke a sibling grant of
the same admin) and `GrantOwner::managed` (team-page authority; it takes a `ui::TeamAuthority`,
which only `ui::team_authority` builds — see Revoke UI below). Absent, not
yours and already revoked all return the same `RevokedGrant::NotFound` — the management
plane answers one 404. **The owner is bound in SQL; the type only forces you to name one.**
`GrantOwner::caller` trusts the `AdminId` it is handed — take it only from the request's
`Extension<AdminId>`, never construct one from a path or form value.

**No post-commit step**, as long as all three hold: MCP OAuth tokens are not in
`tenant::auth_cache` or any other cache; they cannot open SSE or rooms streams; and no MCP
request holds a connection or session open past a single request. The account-level endpoint
keeps all three: it is stateless (no GET stream, no rmcp session), every request is
authorized through `find_grant_by_access`, an MCP access token gets 401 on every other plane
(`mcp_access_is_refused_on_every_other_plane`), and a tus upload bound to a ticket re-checks
the ticket and its grant on every request. A feature that breaks any of them gives every
`revoke_mcp_grant` caller and `remove_admin` an eviction duty (CLAUDE.md invariants 4 and
5). `change_role`, owner transfer, tenant soft-delete and id recycling deliberately do NOT
revoke grants: visibility is decided on every call.

**Child rows never vouch for themselves.** Every read of `_mcp_oauth_codes`,
`_mcp_oauth_refresh`, `_mcp_oauth_access` or `_mcp_upload_tickets` that decides validity
INNER JOINs `_mcp_oauth_grants` AND `admins` on `id` + `created_at`; a child row's own
columns (including the ticket's copied `admin_id`) never prove the grant exists. A
connection without `PRAGMA foreign_keys = ON` that deletes a grant leaves its children
behind, and this join is what keeps them dead until the sweep removes them.

**Upload tickets.** Tickets are issued only by the account-level endpoint's
`create_upload_url` tool, after its tenant check and a re-check under the same meta lock it
issues with; they are read only by the ticket layer in front of the tus routes;
`revoke_mcp_grant` revokes a grant's tickets and the sweep removes them. The contract,
written above the DDL in `db/migrations.rs`:
a ticket is issued with `INSERT … SELECT …, t.created_at FROM tenants t WHERE t.id = ? AND
t.deleted_at IS NULL`, so `tenant_created_at` is copied in SQL, and every ticket read joins
`tenants` on `id`, `created_at` and `deleted_at IS NULL` in addition to the grant and admin
join. A tenant id is recyclable (the id-recycle branch of `make_tenant_inner` hard-deletes
the soft-deleted row), and `tenant_created_at` is what keeps a ticket from resolving to the
new tenant, the way `admin_created_at` does for admins.
Like that layer, it does not hold for an id recycled within the same second (`created_at` is
second precision), which is why the id-recycle branch of `make_tenant_inner` also deletes
that tenant id's `_mcp_upload_tickets` rows, as it purges `quota_requests`. Accepted
residual: a ticket carries `grant_id` only, so cutting one refresh branch (branch b below)
does not reach a ticket minted through that branch; what survives is one upload, capped by
the ticket's `max_bytes` and the tenant's quota, until the ticket's `create_by` (15 minutes
after issue) or, once bound, its upload session's expiry. Revoking the grant reaches it.
Redemption is described in `.claude/rules/storage-files.md` §Upload tickets.

**Three layers against `admins` rowid recycling**, in this order of strength:
(1) `remove_admin` deletes the grants explicitly in its transaction; (2) the FK
`ON DELETE CASCADE`, which needs `PRAGMA foreign_keys = ON` on the connection; (3) every
lookup matches `admins.created_at` against the grant's `admin_created_at`. Layer 3 does
NOT hold when the top rowid is recycled within the same second (`created_at` is second
precision) — never remove layer 1 on the grounds that the FK "already cascades".

**Lookup strengths.** `find_grant_by_access` is the only authorization-strength lookup:
access unrevoked and unexpired, grant unrevoked and inside both its idle and absolute
deadlines, admin id AND created_at matching. `find_grant_by_refresh` applies the same row,
grant and admin checks but deliberately ignores the refresh's `rotated_at` and
`superseded_at`, so it is a validity probe, NOT authorization strength: its `GrantRef`
identifies the grant a refresh belongs to and proves nothing about whether the presented
token may be exchanged. Rotation, the grace window and reuse are `refresh::rotate`'s
decision alone; no exchange or authorization is ever gated on `find_grant_by_refresh`.
`find_grant_for_revocation` is revocation strength, for `/oauth/revoke` only: the access or
refresh row merely has to exist (revoked, expired, rotated or superseded all count) and its
grant must be unrevoked with a matching admin — so a client revoking with a just-expired
access token really ends the grant instead of getting a 200 that changed nothing.
**`find_grant_by_access` returns an `AccessGrant`, not a `GrantRef`, and an `AccessGrant` is
the only value an MCP call may be authorized from**; only that function builds one, and the
request identity `mcp_oauth::caller::McpCaller` is built only from one, in `from_access`
(source pins hold both). Every `GrantRef` (revocation lookup, refresh probe, code replay,
refresh reuse) may only feed `GrantOwner::holder`. A wrong prefix or length answers `None`
without touching SQL.

**Sweep.** `mcp_oauth::sweep::sweep_mcp_oauth` runs in the hourly device-code reaper loop
in `main.rs`, unconditionally (whether or not `DRUST_MCP` is on), in one transaction:
expired codes, access, refresh and upload tickets; grants whose
`COALESCE(revoked_at, MIN(idle_expires_at, absolute_expires_at))` is more than 30 days
old; grants that can never be redeemed any more (`authorization_code`, never used, no code
and no refresh left — a double-clicked or abandoned approval); and orphan grants whose
admin id/created_at no longer match. A rotated refresh is kept until its own `expires_at` —
reuse detection needs the row. Not on the boot path: the reaper's first tick is one hour
after boot and ticks restart with the process, so an expired row is removed at the first
hourly tick after its expiry, not "within the hour". Turning `DRUST_MCP` off pauses MCP
OAuth and revokes nothing: grants still inside their limits work again when it is turned
back on.

**Backup restore** brings back every grant revoked after the snapshot AND re-arms every
refresh token rotated after it (the restored row is unrotated again, so the rotated token
the client already replaced is live once more, and the reuse evidence is gone). After a
restore, revoke all MCP connections (Revoke all on each account's settings card, or Revoke
MCP on the team page) and let the clients re-authorize.

**Refresh-row growth** is bounded only by the per-grant budget, an accepted cost of the
trusted tier (the holder is a signed-in account's own client): one credential holder can add
a refresh and an access row on every charged rotation (branches c and d-2, 10 per 60 s per
grant), access rows go at their own expiry, and every rotated refresh stays until its own
`expires_at` (the grant's `MIN(idle, absolute)` when it was issued).

`remove_admin`'s audit field `revoked_mcp_grants` counts the removed admin's grants that
were still live at removal, not the rows its DELETE removed.

### Endpoints: metadata, token, revoke

`mcp_oauth::public_routes` merges into the admin plane's `public` router (inside
`frame_guard_layers`) only when `McpOauthConfig::enabled()`; disabled, its paths answer
exactly like a path that never existed.

- **Error format.** `/oauth/token` and `/oauth/revoke` sit under `oauth_error_layer`, mounted
  with `route_layer` (never `layer` — `Router::layer` also wraps the sub-router's 404 fallback,
  and `merge` keeps that fallback). Only a response built by `OAuthError` (it carries the
  module-private `OAuthErrorMark` extension) passes through as an error; every other non-2xx —
  axum's 405, the 16 KiB `DefaultBodyLimit` 413, extractor rejections, and any JSON body that
  did not come from `OAuthError` — is rewritten to `{"error": …}`, keeping a 4xx status, and a
  5xx or any 3xx becomes 500 `server_error` with no `Location`. Every response gets
  `Cache-Control: no-store`. `Retry-After` is carried over by the rewrite; `Allow` on a 405 is
  added by axum's top-level route future *outside* the layer, not by the layer.
  `error_description` is never set from caller input or i18n.
- **Credentials come from the form body only.** No cookie, no query parameter. The
  `Content-Type` check runs first (anything but `application/x-www-form-urlencoded` is 400
  `invalid_request`, header or not); with a form body, an `Authorization` header is 401
  `invalid_client` with a matching-scheme `WWW-Authenticate`, so a front proxy that injects
  HTTP auth must not forward it to `/oauth/*`.
  Repeating a defined parameter is `invalid_request`, judged on the decoded key; an empty
  value counts as absent; unknown parameters are ignored even when repeated.
- **Metadata** is pure (no lock, no I/O, no request header read) and carries
  `Cache-Control: public, max-age=300`, so it must never be derived from `Host` or
  `X-Forwarded-*`. `scopes_supported` lists `mcp` and `offline_access`, while every token
  response says `"scope":"mcp"` by design: a grant's scope is always `mcp`, `offline_access`
  is accepted and a refresh token is always issued.
- **Token** validates and dispatches; `authorization_code` is the code exchange and
  `refresh_token` the refresh rotation, both below.
- **Revoke is per grant and not rate-limited.** Any genuine access or refresh token of an
  unrevoked grant — even one that is expired, revoked or rotated — revokes the whole grant
  (`store::lookup_for_revoke` over `find_grant_for_revocation`, then `revoke_mcp_grant` with
  the owner bound in SQL via `GrantOwner::holder`). An expired access row is swept at the first
  hourly tick after its expiry, after which it no longer maps to its grant. `token_type_hint` is ignored; `client_id`
  is optional, an unknown one is `invalid_client`, a mismatching one `unauthorized_client`.
  Unknown token, foreign prefix and already-revoked grant are all 200 with an empty body, and
  no per-IP budget is read: the lookup runs first, so a budget would save nothing, and the
  token is a 256-bit secret. A foreign prefix (PAT, tenant key, code shape) is answered
  before the `meta` lock. Audit (`mcp_oauth.grant.revoke`, owner in `extra.admin_id`, no
  top-level actor — the presenter is not strongly authenticated) is written only when a
  grant was actually revoked. No cache, bus or PAT eviction follows the commit — MCP tokens
  are not in the auth cache and cannot open SSE or rooms; a cache added for MCP tokens later
  makes every `revoke_mcp_grant` caller responsible for evicting it.

### Authorize (`GET /oauth/authorize`)

`mcp_oauth::authorize` sits in `public_routes` **outside** the token/revoke sub-router's
`route_layer`s: its answers are an HTML page or a 303, and `oauth_error_layer` would rewrite
both to OAuth JSON (pinned by `error_page_is_html_not_oauth_json`).

- **Check order and the error split.** The whole query (≤ 4 KiB) is form-decoded once by
  `params::parse_pairs`; then `client_id` (missing, repeated, not in `KNOWN_CLIENTS`), then
  `redirect_uri` (missing, repeated, `redirect_uri_allowed` refuses). Every failure up to
  here is a 400 HTML page (`mcp_oauth_error.html`, standalone, no script, no `Location`,
  no `Set-Cookie`) — an unvalidated redirect is never followed, and an unknown `client_id`
  is never echoed. Every later failure is a 303 to the validated redirect with `error`,
  `error_description`, `state` (only when sent and at most 512 bytes, first value verbatim)
  and `iss`
  (`cfg.issuer()`, byte-identical to the metadata `issuer`): `response_type` (missing or
  repeated `invalid_request`, another value `unsupported_response_type`), PKCE (`S256`
  only, a 43-character challenge), `scope` (only `mcp` / `offline_access`, else
  `invalid_scope`), `resource` (none, or exactly one that `is_our_resource`, else
  `invalid_target`), `state` (≤ 512 bytes). `prompt` and unknown parameters are never read.
- **Redirect: raw string, never re-parsed.** Accepted language:
  `http://` + `localhost` | `127.0.0.1` + optional `:` 1–65535 (ASCII digits, no leading
  zero) + a path that must equal a pinned `redirect_uris` entry byte for byte; ≤ 64 bytes.
  `RedirectTarget.raw` is the input itself (an explicit `:80` is kept), and every later
  redirect uses only it. `[::1]` is not accepted: the pinned document does not list it.
- **Pinned client.** `KNOWN_CLIENTS` holds only Claude Code, copied from its CIMD on
  `pinned_on`; there is no runtime fetch (invariant 6 untouched). Re-fetch and compare at
  every release (`.claude/rules/build-deploy.md` per-release checklist).
- **Envelope.** `envelope::seal` packs version, `exp` (+600 s), a 16-byte nonce and five
  length-prefixed fields (`client_id`, `redirect_uri`, `state`, `code_challenge`,
  `resource`; `scope` is never stored — a grant is always `mcp`) under HMAC-SHA256 with a
  domain tag and the per-process `envelope_key`; `open` checks structure, then the MAC in
  constant time, then expiry, so a tampered expired envelope is `BadMac` and `Expired`
  carries a trustworthy request. Both keys are per process: a restart invalidates in-flight
  consents. The whole envelope rides both the consent `req` query value and the
  `drust_mcp_oauth_resume` cookie (`Path=cookie_path("")`, `HttpOnly`, `SameSite=Lax`,
  `Max-Age=600`, `Secure` unless `DRUST_DEV_NO_SECURE_COOKIES`).
- **No database, no lock, no limiter, no audit.** The handler reads `MgmtState.mcp_oauth`
  only. Two of the four are pinned: `authorize_writes_nothing` (the row counts of the five
  `_mcp_*` tables, `sessions` and `admins` do not move) and `authorize_never_takes_the_meta_lock`; no limiter and no
  audit row hold by reading the handler.
  `error_description` values are English ASCII constants, never i18n or caller input.
- **Log hygiene**: authorize and consent logs may carry only the reason, `client_id`,
  `pinned_on` and the `display_received` form of a rejected `redirect_uri`. Never log
  `state`, `code_challenge`, `resource`, the raw query or an envelope. A rejected redirect
  from the pinned client warns at most once per 60 s per process, carrying a `suppressed`
  count; the others log at `debug`.
- **`SameSite=Lax` is required**: the resume cookie must survive the cross-site top-level
  return from Google/GitHub login; `Strict` breaks the consent flow after sign-in. Do not
  "harden" it to `Strict` (same reason as the session cookie, `src/auth/middleware.rs`
  `session_cookie_is_samesite_lax`).
- **The resume cookie selects which request resumes after login, and consent requires it
  to equal `req`; it is not the CSRF defence**: anyone who can steer a browser into the
  consent page with a given `req` can first steer it through authorize. Forged approvals are
  stopped by the consent CSRF token (the HMAC token below), which must never be dropped on
  the strength of the cookie.
- **Clock failure fails closed**: `envelope::now_unix()` returns `Option`; authorize
  answers `server_error` on `None`, and every `open` caller passes
  `now_unix().unwrap_or(u64::MAX)`. Never map a clock failure to 0.

### Consent (`/oauth/consent`, `/approve`, `/deny`)

`mcp_oauth::session_routes` merges into `protected` (inside `admin_session_layer`, the
profile and inner theme layers, and `frame_guard_layers`) only when `enabled()`.

- **Cookie arm only.** Each handler's first statement reads `Option<Extension<AuthMethod>>`;
  anything but `Some(Cookie)` — `Pat`, or no tag at all — is 403 JSON
  `MCP_CONSENT_COOKIE_REQUIRED`. `AuthMethod` has no `Default`, so a missing tag can never
  read as `Cookie`. approve/deny take the body as `Bytes` and parse it AFTER that check (a
  `Form` extractor would answer a PAT's bad body with 422 first). A PAT must never become a
  long-lived MCP grant (90 days by default, up to 365 with `DRUST_MCP_OAUTH_MAX_DAYS`), and
  revoking the PAT would not reach the grant.
- **Admin session writers.** The only places that create an admin session are
  `login_submit` and the admin OAuth callback (the two `auth::session::create_session`
  callers). A new one must not accept a PAT or any bearer as its authentication, or
  consent's cookie-only rule is void — and the consent tests would not notice.
- **Request binding.** The resume cookie (set only by `/oauth/authorize`) must be present
  and byte-equal to the `req` shown (GET) or submitted (approve/deny); a query-only `req`
  is refused. This picks the request; the CSRF token below is what stops a forgery. The envelope is re-opened on every step and re-validated with `find_client`
  and the SAME `redirect_uri_allowed` authorize uses. Client name, `client_id` and the
  return host:port on the page come from the opened envelope and the pinned list only.
- **CSRF.** Double submit: `drust_mcp_oauth_csrf` cookie (`HttpOnly`, `SameSite=Lax`,
  `Path=cookie_path("")`, `Max-Age=600`, `Secure` unless `DRUST_DEV_NO_SECURE_COOKIES`)
  plus a hidden field. Expected value
  `HMAC-SHA256(csrf_key, "drust-mcp-csrf-v1\0" || admin_id (i64 LE) || ":" ||
  SHA-256(req))`, base64url. Three constant-time checks, all required: field non-empty,
  cookie == field, field == expected. Bound to the admin (another admin's token fails) and
  to the request (a token cannot approve a different envelope). The CLI device token uses a
  different key (`McpOauthConfig::csrf_key` versus `cli_device`'s own per-process secret);
  the domain tag is defence in depth on top (`check_csrf_rejects_a_cli_device_token`).
  Known residual, denial only: a same-site attacker (a sibling subdomain) can plant a
  longer-`Path` CSRF cookie that the browser sends first, and make approve and deny fail
  until it expires; it cannot forge an approval, which needs the HMAC of this admin and
  this `req`.
- **Identity.** The page reads `COALESCE(email, username), role` from `admins` itself and
  counts visible live tenants with `tenant_authz::visibility_where`; it never trusts
  `AdminProfileExt`, whose fallback is a placeholder member. A missing row is
  `consent_admin_missing`; approve re-reads the row inside the grant INSERT (`INSERT …
  SELECT … FROM admins`), so a row deleted between page and approve writes nothing.
- **Cookie clearing.** Cleared only when the request proves the cookie belongs to this
  `req` AND the flow cannot finish with it: approve/deny success (both), an envelope that
  no longer opens or re-validates with cookie == `req` (both on POST, resume only on GET —
  `ClientChanged` included, because `resume_target` only opens and would otherwise bring
  every login back to the error page for 10 minutes), and on approve, after the CSRF check
  passed, a missing admin row or an internal failure of the grant write (both). A mismatch,
  a CSRF failure, a missing admin row on GET and any form-level error clear nothing: the
  browser holds ONE csrf cookie, written by the latest consent GET, most likely for a newer
  tab.
- **Login resume.** `envelope::resume_target` is asked by `login_submit` (after the
  cross-site refusal and the password check) and `oauth_callback`, after the session is
  created. Its first statement is the `enabled()` check, so a disabled host never reads the
  cookie (source pin). A cookie that opens yields the fixed `base("/oauth/consent")` — never
  a URL from the cookie; a dead one yields `ClearStale`, appended (never inserted, which
  would drop the session cookie). Clock failure passes `u64::MAX`: every envelope opens as
  `Expired` and every resume cookie is `ClearStale`.
- **Approve** writes one grant (`kind='authorization_code'`, scope `mcp`, absolute = now +
  max days, idle = MIN(now + idle days, absolute)) and one code (hash only, 300 s, the raw
  `redirect_uri` and the challenge/resource from the envelope) in one transaction, audits
  after the lock is dropped, and 303s with exactly `code`, `state` (when sent) and `iss`.
  The plaintext code goes into that `Location` and nowhere else — no log, no audit field.
  The source pin `mcp_oauth::source_pins::plaintext_code_never_reaches_logs_or_audit`
  scans the comment-stripped code of `consent.rs`, `token.rs`, `refresh.rs` and `revoke.rs`
  for log and audit sites naming a credential (its scanner is checked by
  `the_hygiene_scanner_flags_planted_leaks`). Not rate-limited: the caller is a signed-in
  admin. The `mcp_oauth.grant.create` and `mcp_oauth.consent.deny` audit rows carry the
  admin as top-level actor with `actor_email_snapshot` = `COALESCE(email, username)`.

### Code redemption (`POST /oauth/token`, `grant_type=authorization_code`)

- **Before any lock**, in error-priority order: `client_id` missing → `invalid_request`,
  not in `KNOWN_CLIENTS` → `invalid_client` (400: an `Authorization` header was already
  refused); `code` missing → `invalid_request`; `code` not 43 characters → a miss, never
  queried. A 43-character string proves nothing — an admin session cookie has that shape —
  only the hash lookup decides whether it is a code.
- **One read, every check, then the only writes.** `store::redeem_code` reads the code, its
  grant and the admin id + `created_at` match in one INNER JOIN (so a code whose grant row
  is gone is a miss), then checks in a fixed order: code live, grant unrevoked and inside
  idle and absolute, admin matching, `client_id`, `redirect_uri` byte for byte (missing is a
  failure; no case or percent-decoding normalisation), `resource` (when sent: our resource
  and equal to the code row's, or the row has none), verifier shape (RFC 7636 §4.1),
  S256. **Every check failure returns `Invalid` before the first write**, so a failed
  attempt never consumes the code. Only after every check passed is `redeemed_at` looked
  at: set → `Replay`; unset → `UPDATE … WHERE redeemed_at IS NULL AND expires_at > now`
  (the SQL itself is a single-use gate) and `issue_token_pair`. The handler holds the meta
  mutex across the whole read-mark-issue sequence, which is what serialises concurrent
  redemptions; `concurrent_valid_exchanges_issue_at_most_once` pins the observable result.
  Do not move the read to another connection or put an `.await` inside that transaction.
- **The handler never commits `Miss` or `Invalid`.** One `Invalid` comes after the
  `redeemed_at` mark — the grant's deadline crossing its second between the SELECT and the
  refresh INSERT — and only dropping the transaction rolls that mark back.
- **Replay = a second request that passed every check.** The handler revokes the whole
  grant in the same transaction (`GrantOwner::holder`, `code_replay`), commits, and answers
  `invalid_grant`. One grant has exactly one code (`insert_grant_and_code`), so that is
  exactly "revoke every token issued from this code" (OAuth 2.1 §4.1.3); changing the
  one-code-per-grant shape means redesigning this scope. The primary reason a failed second
  request does NOT revoke is OAuth 2.1 §7.5.3 (no revocation on a replayed code with invalid
  parameters — otherwise whoever holds a code without its verifier could turn the real
  client's valid request into a revocation trigger). A replay after the code expired is
  refused without revoking: the replayer gets nothing.
- **Rate limits read failures only.** A valid exchange (and a replay) reads no bucket;
  `Miss` charges `miss_ip` (`rl::client_ip_key` on the handler's `ClientIp`), `Invalid`
  charges `per_code` (`rl::code_key`); an exhausted bucket turns that failure into
  `429 temporarily_unavailable` with `Retry-After`.
- **Issued tokens.** `issue_token_pair` inserts one refresh (`expires_at` = the grant's
  `MIN(idle, absolute)`; a parent must belong to the same grant, but parent liveness is the
  caller's job) and one access whose `refresh_id` is that refresh, and sets the grant's
  `last_used_at`. The sweep's abandoned rule deletes only a never-used grant with no code
  and no refresh row left, so a fresh refresh row spares an exchanged grant too, but
  `last_used_at` is what still spares it once its code and refresh rows have been swept
  (`an_exchanged_grant_is_not_swept_as_abandoned`).
  The access `expires_at` is now + TTL and is **not** capped by the grant's absolute
  deadline: `find_grant_by_access` checks the grant on every use, so the MCP resource server
  must authorize through it, never through the access row alone.
- **Audit and logs.** `mcp_oauth.token.code` and the replay's `mcp_oauth.grant.revoke`
  (`code_replay`) carry the grant owner as top-level `actor_admin_id` /
  `actor_email_snapshot` (a request that passed every check presented the code and its
  verifier), written after the guard is dropped; `Miss` / `Invalid` write none. The replay
  `warn` carries `grant_id` and `admin_id` only. `server_error` logs the stage and
  `sqlite_error_without_sql`, never a request parameter.
- **Requiring `redirect_uri` is compatibility, not a security boundary.** OAuth 2.1 drops it
  from the token request but lets clients send it; Claude Code's SDK does. If it stops, the
  fallback is "accept absent, compare when present" — PKCE still stops code injection. A
  missing `redirect_uri` or `code_verifier` is `invalid_grant`, like every other mismatch.
- `CodeRedeemRequest`, `IssuedTokens` and `RedeemOutcome` hold plaintext credentials and
  derive no `Debug` (pin `credential_types_do_not_derive_debug`); tests use `matches!`.
  `verify_s256` uses `ct_eq` (pin `verify_s256_compares_in_constant_time`) — convention and
  defence in depth only, the challenge is not a secret.

### Refresh rotation (`POST /oauth/token`, `grant_type=refresh_token`)

`mcp_oauth::refresh::rotate` is the whole decision, including which branches read the
per-grant budget; `token.rs::grant_refresh` only checks the request, does the hit/miss
lookup, opens the transaction, hands `rotate` the budget as a closure and writes audit after
the guard is dropped. The state machine reads ONE snapshot (`store::load_refresh_for_rotate`, an INNER
JOIN on the grant, so an orphan refresh is refused) and decides, in this order, with `G` =
`DRUST_MCP_OAUTH_REFRESH_GRACE_SECS`:

| Branch | Condition | Writes (same tx) | Answer |
|---|---|---|---|
| a) dead / foreign | refresh revoked or expired, grant revoked or past idle/absolute, admin id + `created_at` mismatch, or a sent `client_id` ≠ the grant's | nothing | `invalid_grant` |
| b) losing sibling | `superseded_at` set | `store::revoke_mcp_refresh_branch`: this refresh + the access issued with it (`sibling_superseded`), grant `sibling_rejected_at` | `invalid_grant` |
| c) first use | `rotated_at` NULL | mark rotated, supersede its unrotated siblings (same parent), slide idle, issue a child | 200 |
| d-1) in grace, decided | rotated, within `G`, a child already rotated | grant `sibling_rejected_at` only | `invalid_grant` |
| d-2) in grace, undecided | rotated, within `G`, no child rotated | slide idle, issue another child; invalidate nothing | 200 |
| e) reuse | rotated, past `G` | `revoke_mcp_grant(GrantOwner::holder, refresh_reuse)` | `invalid_grant` |

- **b before c is load-bearing**: a superseded row has `rotated_at IS NULL`, so checking c
  first would send a losing sibling into first use; `mark_rotated`'s `superseded_at IS
  NULL` is the second layer (it then refuses and the tx rolls back, but the branch is never
  cut). b vs d/e is exclusive. Pinned by `the_first_sibling_used_wins_and_the_loser_is_cut_alone`
  and `mark_rotated_refuses_a_superseded_row`.
- **A superseded sibling never has children** (c supersedes only unrotated rows; d-2 issues
  only under a rotated one), so a branch revoke is one refresh plus its access, no
  recursion. In d-1 the audit's `refresh_id` is the re-presented PARENT, not a sibling.
- **The grace counts from the parent's FIRST rotation.** d-2 never touches `rotated_at`, so
  holding the parent cannot keep the grace open (`a_sibling_issued_in_grace_does_not_extend_the_grace`).
  Time is second precision: the window is (G−1, G] seconds; `G = 0` sends every second
  presentation to e).
- **Deliberate deviation from the strict reading of OAuth 2.1 §4.3.1**: inside the grace
  siblings coexist and the loser is cut alone (owner decision, 2026-11-14) — several
  Claude Code processes on one machine share one credential and race refreshes. Its cost: a
  thief who wins an in-grace race keeps a branch until the grant's deadline (the
  settings card shows `sibling_rejected_at` for manual revocation). Do not "tighten" b) into a grant
  revoke without re-asking the owner.
- **`GrantRef` for e) only**: `RefreshState::holder` is `Some` only for a rotated,
  unsuperseded, live refresh of a live grant with a matching admin; e) fails closed on
  `None`. `revoke_mcp_refresh_branch` takes no `GrantOwner`: it is `pub(crate)`, its only
  caller passes the ids of the presented token's own row from the same snapshot, and every
  UPDATE also binds `grant_id`.
- **Error codes.** Every failure is `invalid_grant` because the SDK only re-authorizes on
  that code. Two deliberate code deviations: a foreign `resource` is `invalid_grant`, not
  RFC 8707's `invalid_target` (after a `DRUST_PUBLIC_URL` change, Claude Code refreshing with
  the old resource is sent to re-authorize instead of getting stuck); rate limiting answers
  429 `temporarily_unavailable`, which is not a standard token-endpoint code, on purpose:
  the client discards its tokens and re-authorizes only on `invalid_grant`, so a 429 must
  not look like a dead grant.
  The exceptions are a missing `refresh_token` (`invalid_request`) and a `scope` item other
  than `mcp` / `offline_access` (`invalid_scope`, via `authorize::scope_items_ok`, the same
  function authorize uses; an empty `scope` counts as not sent). While budgets remain, all
  rejections are byte identical (`every_refresh_rejection_is_byte_identical`): never add an
  `error_description` that tells a losing sibling from a dead token. Once the caller's own
  per-IP miss budget is spent, an unknown token answers 429 while a known dead one may still
  answer `invalid_grant` (it charges its grant's bucket instead), and `Retry-After` differs
  by bucket. That reveals only that a token the caller already holds, a 256-bit secret,
  exists. A full per-grant bucket splits the answers the same way: branches b) and e) are
  never charged and still answer `invalid_grant`, while a), c) and d) answer 429, so the
  holder of a token can tell a superseded or past-grace one from the rest. Only a holder
  sees this, and presenting a b) or e) token ends it (the branch is cut, or the grant is
  revoked).
- **Check order and budgets.** `scope`, `resource` and the token's prefix + length are pure
  checks before the lock and before any budget (an access token presented as a refresh is
  refused here). Under the lock, `refresh::lookup_grant_id` looks the hash up ignoring
  liveness: unknown → `miss_ip`; known (revoked and rotated rows included) → never
  `miss_ip`. For a known hash the grant's `per_grant` bucket (`rl::grant_key`, 10 per 60 s)
  is read inside the transaction, only after the snapshot has decided the branch
  (`rotate`'s `charge` closure; `try_acquire` is synchronous, so no await under the guard):
  a), c), d-1) and d-2) are charged and answer 429 on a full bucket with the transaction
  dropped; **b) and e) never read it**. They are terminal and self-limiting (e revokes the
  grant once, b cuts one row once), and a full bucket must never stop them: charged, a
  thief holding a dead token of the grant (a sibling it got in the grace and then cut)
  could keep the bucket full, so the legitimate client's past-grace presentation would only
  ever get 429 instead of e) and the thief would keep a live chain
  (`a_dead_siblings_flood_cannot_suppress_reuse_detection`,
  `only_the_bounded_branches_read_the_budget`).
- **A wrong `client_id` is branch a) even with real reuse evidence**, so it revokes nothing:
  the Claude Code `client_id` is a public URL, a thief can always send the right one, and the
  order only affects callers that send a wrong one (`reuse_with_a_wrong_client_id_does_not_revoke`).
- **Lookup is by hash as the UNIQUE index key; there is deliberately no Rust-side
  constant-time compare.** B-tree timing can only leak a prefix of a hash of a 256-bit
  secret; do not "fix" it into fetch-then-compare.
- **No post-commit step** after b) or e): no cache, bus or `clear_admin_pat` (MCP tokens are
  in no cache and open no SSE or rooms). Demoting the grant's owner revokes nothing either
  (`demoting_the_owner_does_not_touch_the_grant`): visibility is decided per MCP call.
- **Audit**, written after the guard is dropped: `mcp_oauth.refresh.sibling_rejected`
  (`grant_id`, `refresh_id`, `admin_id`, `branch_revoked`) for b) and d-1);
  `mcp_oauth.grant.revoke` (`reason=refresh_reuse`, plus `refresh_id`, `admin_id`,
  `rotated_secs_ago`, `revoked`) for e). The owner is `extra.admin_id` with no top-level
  actor — the presenter is unknown, unlike the code exchange's. A success writes none; no
  row carries a token, a hash or a request field.
- **Operator note**: a grant revoked with `refresh_reuse` that its user reports as "I just
  opened my laptop" — check the audit row's `rotated_secs_ago` first. Thousands of seconds is
  a process that slept past the grace (an accepted cost); just past the
  grace looks like a race or a theft.
- `RotateOutcome` holds `IssuedTokens` and derives no `Debug` (pin
  `rotate_outcome_does_not_derive_debug` in `refresh.rs`); tests use `matches!`.

### The account-level endpoint (`/mcp`)

`mcp_oauth_auth_layer` (`rs_layer.rs`) is the endpoint's whole authentication, inside
`mcp_route_layer` and outside `mcp_body_buffer`:

- It reads the first `Authorization` value only, checks its shape (`drust_mcpat_`, exact
  length) before taking the `meta` lock, and makes ONE lookup, `store::find_grant_by_access`.
  `None` — no header, a tenant key, an admin PAT, a user or anon token, an upload ticket, an
  unknown or expired access token — is always `401 MCP_OAUTH_REQUIRED` with a
  `WWW-Authenticate: Bearer resource_metadata="<prm_url>"…` challenge, never 429, and reads
  no per-IP bucket: the hourly sweep deletes an expired access row, so an idle client's
  expired token cannot be told from one never issued, and Claude Code refreshes only on a 401.
- A valid token spends its grant's `rs_grant` budget (600 per 60 s; over it `429
  RATE_LIMITED`) first and only then touches `last_used_at`, on the same `meta` guard, which
  is released before rmcp runs.
- Every `Authorization` value, `Cookie` and `Proxy-Authorization` is removed before the
  request reaches rmcp, and the `McpCaller` built by `McpCaller::from_access` is inserted.
  Refusals write no audit row; their logs are sampled.
- Tenant resolution after that is `account::resolve_tenant` (CLAUDE.md invariants 7 and 21):
  the grant-anchored `tenant_authz::tenant_access_for_admin` before the tenant is opened and
  again after, requiring the same (owner, created_at). Known residual: an id soft-deleted and
  recycled to the SAME owner within the same second passes both checks (`created_at` is
  second precision). It has no authorization consequence — that caller may see both
  incarnations — and the cached old-incarnation pool residual under "Admin request queues"
  applies to it.

### Revoke UI (settings card, team page)

`mcp_oauth::settings_routes` merges into `settings_router` and `mcp_oauth::team_routes` into
`team_router`, each after that router's `.with_state`, only when `enabled()`; both ride
`protected` (cookie or `drust_pat_*`, `AuthMethod` read for the audit `auth_method`
`admin_cookie` / `admin_pat`). Handlers are in `mcp_oauth::ui`, never in `admin_team.rs`
(that file is a `pat_evict_pin` site).

- **Settings (`POST /admin/settings/mcp-grants/{id}/revoke`, `…/revoke-all`)** act on the
  caller's own grants only, whatever the role: `GrantOwner::caller`, fed ONLY from the
  request's `Extension<AdminId>`. Under `src/mgmt/mcp_oauth/`, `AdminId(` appears only in an
  extractor's destructuring pattern — never built from a path, form or query value (pinned
  by `admin_id_is_only_ever_destructured_from_the_extension`).
  Foreign, unknown and already-revoked ids are one `404 MCP_GRANT_NOT_FOUND`; success and an
  empty revoke-all are a 303 to `base("/admin/settings")`. `settings_page` reads the grant
  list only when `enabled()`; a failed read renders an error line AND the Revoke all form
  (which finds live ids itself), never an "empty" card. Revoke-all's count can exceed the
  rows the card showed: the list also matches `admin_created_at`, `revoke_all_mcp_grants`
  matches `admin_id` only.
- **Team (`DELETE /admin/team/{id}/mcp-grants`)**: `{id}` is an admin id.
  `require_sees_team_layer` gates only GET, so the authority is in the handler:
  `ui::team_authority` = `remove_admin`'s matrix — not `can_manage_members` →
  `403 NOT_A_MANAGER` (before any lookup, so a member learns nothing about ids); target
  missing → `404 ADMIN_NOT_FOUND`; target role other than `member` and caller not
  `can_manage_privileged` → `403 PRIVILEGED_ROLE_REQUIRED` (an allow-list on the target role,
  so an unknown stored role fails closed). An `admin`-role account revoking its OWN grants
  here therefore gets 403, exactly like removing itself, and the settings page is its way;
  an owner may act on its own row, as `remove_admin` lets it. The `{"revoked": n}` count
  (and the audit row's `revoked`) is every unrevoked grant under that admin id: it includes
  expired grants and grants left by a previous holder of a recycled admin id, which the
  target's own settings card does not list. The target's
  role is read on the same meta guard the revoke runs under; the caller's role comes from
  `admin_profile_layer` (an earlier lock — the same shape as `remove_admin`).
  `TeamAuthority`'s field is private and `GrantOwner::managed` is its only consumer: a
  reminder not to skip the gate, not a security boundary (`AdminProfileExt` is all-pub).
- **No post-commit step**: no auth-cache clear, no bus eviction, no `clear_admin_pat` — the
  three conditions under "Grants, revocation and cleanup" hold. A cache added for MCP tokens
  later must be evicted by these three handlers and every other `revoke_mcp_grant` caller.
- **`DRUST_MCP` off is a pause, not a revocation**: the card, the connect page and the OAuth
  routes disappear (`/mcp` stays mounted and answers 404 `MCP_DISABLED`), the grants stay
  live and work again when it is turned back on. To cut a connection off, revoke it
  before turning MCP off or right after turning it back on. There is no boot-time revoke
  (invariant 1).

## Tenant creation cap and quota tier

Both are **admin-plane only**, deliberately: a tenant's own service key must never be able
to raise its own storage tier or its owner's tenant allowance.

`admins.tenant_cap_bonus` stores a **delta, not an absolute ceiling** —
`effective_cap = max(0, DRUST_MEMBER_TENANT_CAP + bonus)`. Storing an absolute would strand
previously-adjusted admins when the global default rises. Every API face speaks absolute
numbers because that is what a person means; the handler converts.

The cap gate is the **first statement** of `make_tenant_inner` — before `validate_tenant_id`
and before the id-recycle branch's hard delete — so a refused create destroys nothing. Both
entry points hold the `meta.sqlite` mutex across the call, so the count-read and the INSERT
are one critical section. The signature takes the role from the DB and `owner_admin_id` as a
plain `i64` (not `Option`), because two review rounds showed that every parameter which
*could* be wrong eventually was.

A live id and a soft-deleted id the caller may not recycle both answer `400
TENANT_ID_UNAVAILABLE` with one handler-built message (`make_tenant_inner` bails with the
same `TENANT_ID_UNAVAILABLE:`-prefixed literal in both places, and `create_tenant_json`
maps it — and any `UNIQUE` failure — to a single arm). Keep them a single arm, or the
create route becomes an ownership oracle.

Approve paths on both the quota and the cap queue must re-validate that the target is still
an increase (`409 …_NOT_INCREASE`) and must 404 a vanished requester — `admins.id` is
`INTEGER PRIMARY KEY` **without** AUTOINCREMENT, so SQLite reuses a deleted top rowid and the
next invited teammate could otherwise inherit an orphaned request.

A `quota_tier` change **must** evict the tenant's auth-cache entries. A `tenant_cap_bonus`
change must not — it never rides the bearer CTE.

## Admin request queues

There are **two**, same shape, and every lifetime rule below applies to both — the cap queue
was written from the quota one, and each round of "fix the request queue" that touched only
one left a live hole in the other.

| Table | Subject | Pending gate keyed on |
|---|---|---|
| `tenant_cap_requests` | an admin's tenant allowance | the **admin** (`409 TENANT_CAP_REQUEST_PENDING`) |
| `quota_requests` | a tenant's storage tier | the **tenant** (`409 QUOTA_REQUEST_PENDING`) |

**Inbound**: the 409 stops two *open* requests at once, never the request → rejected →
request loop. A daily budget does that — `DRUST_TENANT_CAP_DAILY_SUBMIT_LIMIT` /
`DRUST_QUOTA_DAILY_SUBMIT_LIMIT` (both default 5; `0` unlimited), each keyed like its own
409, each counting **decided rows too** (a rejection is what the loop produces), each
`429 …_RATE_LIMITED`, each failing **closed** on an unreadable count.

**Outbound**: `request_janitor::spawn_request_retention_task` sweeps both at boot and daily
at 03:00 UTC, deleting **decided** rows older than
`DRUST_TENANT_CAP_REQUEST_RETENTION_DAYS` / `DRUST_QUOTA_REQUEST_RETENTION_DAYS` (default 90;
`0` keeps forever). It is one task over both queues on purpose: a janitor named after one
table is how the other gets forgotten. It is also its own task and not a call inside
`record_history::spawn_retention_task`, which returns early when its own knob is `0`.

> [!CAUTION]
> Retention is measured from **`COALESCE(decided_at, created_at)`**, never `created_at`.
> drust has no mail transport, so a request surfaces only when an owner opens the queue and
> can sit pending for months. Anchored on `created_at`, a request filed 135 days ago and
> decided this morning is destroyed by the next 03:00 pass — zero retention where the knob
> says 90 days, and for an approval that leaves a raised allowance with no record of who
> granted it.

**`pending` rows are never auto-pruned** — open work, not a record.

**Nothing may outlive the id it points at.** Both queues carry a bare `requester_admin_id`
with no FK, and `admins.id` is `INTEGER PRIMARY KEY` *without* AUTOINCREMENT, so `remove_admin`
deletes the removed admin's rows in **both** tables or the next invited teammate inherits the
rowid and the review page renders their address as the author. Tenant ids are caller-supplied
and explicitly recyclable, so the id-recycle hard purge in `mgmt::tenants::crud` deletes that
tenant's `quota_requests` too — `decide_quota_request` resolves the stored `tenant_id` live,
so a survivor would raise the *new* tenant's tier. The same rule covers process memory: a
create that recycled an id runs `crud::evict_tenant_everywhere` after the meta lock is
released, which drops the old incarnation's pool cache entry, its MCP registry cache entry,
the SSE and rooms bus channels for the id, its auth-cache entries, its cron index entry, and
bumps its egress-allowlist version. One residual window
remains (the crud.rs doc on that function): between releasing the lock and the first
evictions, an admin PAT request can already reach the id, and if a request racing the
soft-delete had left an old-incarnation pool cached, it can see that pool and, at worst,
re-insert it into the MCP cache after the sweep — two races and a trusted caller.
The same rule covers MCP OAuth grants: `remove_admin` deletes `_mcp_oauth_grants` for the
removed admin explicitly, inside the same transaction, before `DELETE FROM admins`.

## Provenance

Extracted from CLAUDE.md §Auth, §Per-tenant quota and §Per-member tenant creation cap during
the 2026-08-02 restructure.
