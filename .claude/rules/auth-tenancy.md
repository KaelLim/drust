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
request — so **both cache arms open the pool with `get_if_live`, never `get_or_create`**,
and 404 on `None`. `soft_delete_tenant` renames the tenant directory and evicts the pool
*before* it clears the cache, and a request that read its entry earlier can arrive at the
open at any later point; creating on open there rebuilds `tenants/<id>` outside `_trash`,
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
with the IP taken as `XFF[-2]`. Self-registration is opt-in per tenant.

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
Both callbacks are per-IP rate-limited at 5/min. The per-tenant callback also validates that
the tenant exists in `meta` **before** `get_or_create`, which is what prevents a disk-fill DoS.

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
`AuthCtx::Service{admin_id}`, which is already cross-tenant.

Lifecycle routes live on the **public** router via a self-contained `resolve_cli_caller`
that returns JSON 401 and never a 302.

`admin_session_layer` is cookie-**or**-PAT. The browser-302 invariant is preserved: no
bearer plus `Accept: text/html` still redirects to `/login`; only a present bearer or
`Accept: application/json` gets a JSON 401.

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

Approve paths on both the quota and the cap queue must re-validate that the target is still
an increase (`409 …_NOT_INCREASE`) and must 404 a vanished requester — `admins.id` is
`INTEGER PRIMARY KEY` **without** AUTOINCREMENT, so SQLite reuses a deleted top rowid and the
next invited teammate could otherwise inherit an orphaned request.

A `quota_tier` change **must** evict the tenant's auth-cache entries. A `tenant_cap_bonus`
change must not — it never rides the bearer CTE.

`tenant_cap_requests` is bounded on both ends. Inbound: the one-pending-per-admin 409 plus a
per-admin daily budget (`DRUST_TENANT_CAP_DAILY_SUBMIT_LIMIT`, default 5; `0` unlimited) that
counts **decided rows too**, because the loop it exists to stop is request → rejected →
request; over budget is `429 CAP_REQUEST_RATE_LIMITED`, and an unreadable count fails closed.
Outbound: `tenant_cap::spawn_request_retention_task` prunes **decided** rows older than
`DRUST_TENANT_CAP_REQUEST_RETENTION_DAYS` (default 90; `0` keeps forever) at boot and daily at
03:00 UTC. **`pending` rows are never auto-pruned** — a pending request is open work, and it is
already bounded by the 409. The prune is its own task and not a call inside
`record_history::spawn_retention_task`, which returns early when its own knob is `0`.

## Provenance

Extracted from CLAUDE.md §Auth, §Per-tenant quota and §Per-member tenant creation cap during
the 2026-08-02 restructure.
