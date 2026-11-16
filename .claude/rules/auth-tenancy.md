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
alongside (so `whoami` and the admin UI can echo the key — this is why a backup archive is
a secret store). Resolution happens in `bearer_auth_layer`, which also wires rate-limiting
and audit; denials get `error_code: HTTP_<status>`.

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
before touching `meta` (login CSRF, MA0-1). **Never add that check to the admin OAuth
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
extension (`Cookie` / `Pat`); a handler that must tell them apart (today only MCP consent)
reads it. The browser-302 invariant is preserved: no
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
the same admin) and, from MA0-9, `GrantOwner::managed` (team-page authority). Absent, not
yours and already revoked all return the same `RevokedGrant::NotFound` — the management
plane answers one 404. **The owner is bound in SQL; the type only forces you to name one.**
`GrantOwner::caller` trusts the `AdminId` it is handed — take it only from the request's
`Extension<AdminId>`, never construct one from a path or form value.

**No post-commit step**, as long as all three hold: MCP OAuth tokens are not in
`tenant::auth_cache` or any other cache; they cannot open SSE or rooms streams; and no MCP
request holds a connection or session open past a single request (the account MCP
endpoint is stateless — no GET stream, no rmcp session — and a tus upload bound to a
ticket re-checks the ticket and its grant on every PATCH). A phase that breaks any of them
gives every `revoke_mcp_grant` caller and `remove_admin` an eviction duty (CLAUDE.md
invariants 4 and 5). `change_role`, owner transfer, tenant soft-delete and id recycling
deliberately do NOT revoke grants: visibility is decided on every call.

**Child rows never vouch for themselves.** Every read of `_mcp_oauth_codes`,
`_mcp_oauth_refresh`, `_mcp_oauth_access` or `_mcp_upload_tickets` that decides validity
INNER JOINs `_mcp_oauth_grants` AND `admins` on `id` + `created_at`; a child row's own
columns (including the ticket's copied `admin_id`) never prove the grant exists. A
connection without `PRAGMA foreign_keys = ON` that deletes a grant leaves its children
behind, and this join is what keeps them dead until the sweep removes them.

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
access token really ends the grant instead of getting a 200 that changed nothing. **Only a
`GrantRef` from `find_grant_by_access` may authorize an MCP call**; every other `GrantRef`
(revocation lookup, refresh probe, code replay, refresh reuse) may only feed
`GrantOwner::holder`. A wrong prefix or length answers `None` without touching SQL.

**Sweep.** `mcp_oauth::sweep::sweep_mcp_oauth` runs in the hourly device-code reaper loop
in `main.rs`, unconditionally (whether or not `DRUST_MCP` is on), in one transaction:
expired codes, access, refresh and upload tickets; grants whose
`COALESCE(revoked_at, MIN(idle_expires_at, absolute_expires_at))` is more than 30 days
old; grants that can never be redeemed any more (`authorization_code`, never used, no code
and no refresh left — a double-clicked or abandoned approval); and orphan grants whose
admin id/created_at no longer match. A rotated refresh is kept until its own `expires_at` —
reuse detection needs the row. Not on the boot path. Restoring a backup resurrects grants
revoked after the snapshot. Turning `DRUST_MCP` off pauses MCP OAuth and revokes nothing:
grants still inside their limits work again when it is turned back on.

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
- **Credentials come from the form body only.** No cookie, no query parameter. An
  `Authorization` header is always 401 `invalid_client` with a matching-scheme
  `WWW-Authenticate`, so a front proxy that injects HTTP auth must not forward it to `/oauth/*`.
  Repeating a defined parameter is `invalid_request`, judged on the decoded key; an empty
  value counts as absent; unknown parameters are ignored even when repeated.
- **Metadata** is pure (no lock, no I/O, no request header read) and carries
  `Cache-Control: public, max-age=300`, so it must never be derived from `Host` or
  `X-Forwarded-*`.
- **Token** validates and dispatches only: both grant types answer `unsupported_grant_type`
  until the code exchange and refresh rotation land. It touches no table.
- **Revoke is per grant and not rate-limited.** Any genuine access or refresh token of an
  unrevoked grant — even one that is expired, revoked or rotated — revokes the whole grant
  (`store::lookup_for_revoke` over `find_grant_for_revocation`, then `revoke_mcp_grant` with
  the owner bound in SQL via `GrantOwner::holder`). An expired access row is swept within the
  hour, after which it no longer maps to its grant. `token_type_hint` is ignored; `client_id`
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
  `error_description`, `state` (only when sent, first value verbatim) and `iss`
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
  only (pinned by `authorize_writes_nothing` and `authorize_never_takes_the_meta_lock`).
  `error_description` values are English ASCII constants, never i18n or caller input.
- **Log hygiene**: authorize and consent logs may carry only the reason, `client_id`,
  `pinned_on` and the `display_received` form of a rejected `redirect_uri`. Never log
  `state`, `code_challenge`, `resource`, the raw query or an envelope.
- **`SameSite=Lax` is required**: the resume cookie must survive the cross-site top-level
  return from Google/GitHub login; `Strict` breaks the consent flow after sign-in. Do not
  "harden" it to `Strict` (same reason as the session cookie, `src/auth/middleware.rs`
  `session_cookie_is_samesite_lax`).
- **The resume cookie is login continuation, not a CSRF or browser-binding defence**:
  anyone who can steer a browser into the consent page with a given `req` can first steer it
  through authorize. Forged approvals are stopped by the consent CSRF token, which must
  never be dropped on the strength of the cookie.
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
  90-day grant, and revoking the PAT would not reach the grant.
- **Admin session writers.** The only places that create an admin session are
  `login_submit` and the admin OAuth callback (the two `auth::session::create_session`
  callers). A new one must not accept a PAT or any bearer as its authentication, or
  consent's cookie-only rule is void — and the consent tests would not notice.
- **Browser binding.** The resume cookie (set only by `/oauth/authorize`) must be present
  and byte-equal to the `req` shown (GET) or submitted (approve/deny); a query-only `req`
  is refused. The envelope is re-opened on every step and re-validated with `find_client`
  and the SAME `redirect_uri_allowed` authorize uses. Client name, `client_id` and the
  return host:port on the page come from the opened envelope and the pinned list only.
- **CSRF.** Double submit: `drust_mcp_oauth_csrf` cookie (`HttpOnly`, `SameSite=Lax`,
  `Path=cookie_path("")`, `Max-Age=600`) plus a hidden field. Expected value
  `HMAC-SHA256(csrf_key, "drust-mcp-csrf-v1\0" || admin_id (i64 LE) || ":" ||
  SHA-256(req))`, base64url. Three constant-time checks, all required: field non-empty,
  cookie == field, field == expected. Bound to the admin (another admin's token fails) and
  to the request (a token cannot approve a different envelope); the domain tag keeps it
  apart from the CLI device token under the same key.
- **Identity.** The page reads `COALESCE(email, username), role` from `admins` itself and
  counts visible live tenants with `tenant_authz::visibility_where`; it never trusts
  `AdminProfileExt`, whose fallback is a placeholder member. A missing row is
  `consent_admin_missing`; approve re-reads the row inside the grant INSERT (`INSERT …
  SELECT … FROM admins`), so a row deleted between page and approve writes nothing.
- **Cookie clearing.** Cleared only when the request proves the cookie belongs to this
  `req` AND the flow cannot finish with it: approve/deny success (both), an envelope that
  no longer opens or re-validates with cookie == `req` (both on POST, resume only on GET —
  `ClientChanged` included, because `resume_target` only opens and would otherwise bring
  every login back to the error page for 10 minutes). A mismatch, a CSRF failure, a missing
  admin row on GET and any form-level error clear nothing: the browser holds ONE csrf cookie,
  written by the latest consent GET, most likely for a newer tab.
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
  The plaintext code goes into that `Location` and nowhere else — no log, no audit field
  (source pin `plaintext_code_never_reaches_logs_or_audit`). Not rate-limited: the caller
  is a signed-in admin.

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
released, which drops the old incarnation's pool cache entry, both MCP cache layers and
their live rmcp sessions, the SSE and rooms bus channels for the id, its auth-cache
entries, its cron index entry, and bumps its egress-allowlist version. One residual window
remains (the crud.rs doc on that function): between releasing the lock and the first
evictions, an admin PAT request can already reach the id, and if a request racing the
soft-delete had left an old-incarnation pool cached, it can see that pool and, at worst,
re-insert it into the MCP cache after the sweep — two races and a trusted caller.
The same rule covers MCP OAuth grants: `remove_admin` deletes `_mcp_oauth_grants` for the
removed admin explicitly, inside the same transaction, before `DELETE FROM admins`.

## Provenance

Extracted from CLAUDE.md §Auth, §Per-tenant quota and §Per-member tenant creation cap during
the 2026-08-02 restructure.
