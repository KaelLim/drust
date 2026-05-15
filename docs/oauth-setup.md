---
type: doc
service: drust
topic: oauth-setup
status: production
updated: 2026-05-15
---

# OAuth setup

drust supports OAuth at two layers: **admin OAuth** (v1.11+, host-level
admin login for the management UI) and **per-tenant OAuth** (v1.12+,
end-user login for each tenant's `_system_users`). They share the
`src/oauth/` library but have separate config surfaces. Read the section
that matches your use case.

- [Admin OAuth setup](#admin-oauth-setup) — for whoever runs the drust host
- [Per-tenant OAuth](#per-tenant-oauth-v112) — for each tenant's end-user
  application

## Admin OAuth setup

drust v1.11+ admin login can authenticate via Google or GitHub OAuth in
addition to the built-in username + password. This guide walks through
registering OAuth applications and wiring drust's `.env`.

## Prerequisites

- drust deployed and reachable on an externally-resolvable HTTPS URL.
- `DRUST_PUBLIC_URL` env var set to that base **with no path suffix**.
  Example: `DRUST_PUBLIC_URL=https://drust.example.com` — drust appends
  `/drust/admin/oauth/{provider}/callback` itself to match its Caddy
  `handle_path /drust/*` mount.

> [!IMPORTANT]
> The provider-side redirect URI you register MUST include the `/drust/`
> path segment. The env var must NOT. See the Google / GitHub steps
> below for the exact strings to paste.

## Google

1. Open Google Cloud Console → APIs & Services → Credentials
   <https://console.cloud.google.com/apis/credentials>
2. **Create OAuth client ID** → Application type: **Web application**
3. **Authorized redirect URIs**: add
   `${DRUST_PUBLIC_URL}/drust/admin/oauth/google/callback`
   (e.g. `https://drust.example.com/drust/admin/oauth/google/callback`)
4. Copy **Client ID** and **Client secret** into `.env`:
   ```
   DRUST_OAUTH_GOOGLE_CLIENT_ID=...
   DRUST_OAUTH_GOOGLE_CLIENT_SECRET=...
   ```
5. **OAuth consent screen**: add scopes `openid`, `email`, `profile`.

## GitHub

1. Open GitHub → Settings → Developer settings → OAuth Apps
   <https://github.com/settings/developers>
2. **New OAuth App**
3. **Application name**: anything (e.g. "drust admin")
4. **Homepage URL**: `${DRUST_PUBLIC_URL}/drust/`
5. **Authorization callback URL**:
   `${DRUST_PUBLIC_URL}/drust/admin/oauth/github/callback`
6. After creating, click **Generate a new client secret**
7. Copy **Client ID** and **Client secret** into `.env`:
   ```
   DRUST_OAUTH_GITHUB_CLIENT_ID=...
   DRUST_OAUTH_GITHUB_CLIENT_SECRET=...
   ```

## Admin allowlist

```
DRUST_ADMIN_OAUTH_ALLOWED_EMAILS=you@example.com
```

Multiple admins comma-separated:

```
DRUST_ADMIN_OAUTH_ALLOWED_EMAILS=alice@example.com,bob@example.com
```

Parsing lowercases each entry, so case doesn't matter on either side.

## Populate the admin email column

Your existing admin record needs its `email` column set so OAuth can
look it up. drust v1.11 ships a `set_admin_password` binary that
accepts an `--email` flag:

```bash
# binary lives wherever you installed drust; on systemd hosts:
sudo /opt/drust/bin/set_admin_password --username admin --email you@example.com
# stdin still receives the password — pass the EXISTING password to keep it.
```

## Reload

```bash
sudo systemctl restart drust
```

Visit `/drust/login` — Google and GitHub buttons should appear next to
the password form (only when both `CLIENT_ID` and `CLIENT_SECRET` of a
provider are set).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Buttons don't appear | env partial (one half of pair missing) | Set both `CLIENT_ID` and `CLIENT_SECRET`, or unset both |
| `oauth_misconfigured` redirect | `DRUST_PUBLIC_URL` or `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS` empty | Set them in `.env` and restart |
| `oauth_admin_email_missing` redirect | Admin row has no `email` column value | Run `set_admin_password --email` |
| `oauth_not_allowed` redirect | Verified provider email not in allowlist | Add to `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS` |
| `oauth_email_unverified` redirect | Provider returned `email_verified: false` | Verify the email on the provider side |
| `oauth_state_mismatch` redirect | Stale browser tab / cleared cookies during flow | Start over from `/drust/login` |
| `redirect_uri_mismatch` from provider | Registered URI doesn't match what drust sends | Re-check the `/drust/` path segment is in the provider-side URI |

---

## Per-tenant OAuth (v1.12+)

drust v1.12 lets each tenant register its OWN Google/GitHub OAuth apps for
its end users (`_system_users`). The flow mirrors Supabase **Project Auth
providers**: end users sign in with the tenant's OAuth app and receive a
`drust_user_*` bearer token via a URL fragment, which the frontend reads
and uses on subsequent API calls.

This section is independent of the admin OAuth setup above — the two use
the same `src/oauth/` library but separate config surfaces, separate
sessions, and separate audit rows.

### Provider-side redirect URI

When you register the OAuth app at Google or GitHub, the **Authorized
redirect URI** is the per-tenant callback:

```
${DRUST_PUBLIC_URL}/drust/t/<tenant-id>/oauth/<provider>/callback
```

Where `<provider>` is `google` or `github`. Example:

```
https://drust.example.com/drust/t/87a3e9c2-1f4b-4c5d-9e8a-0123456789ab/oauth/google/callback
```

> [!IMPORTANT]
> This is the **drust callback**, not your frontend callback. drust handles
> the OAuth handshake, then 302s the browser to your frontend URL with a
> `#access_token=...` fragment. Your frontend URL goes in
> `allowed_redirect_uris` (next section).

### Configure in drust

Three equivalent surfaces — pick whichever fits your workflow.

**Admin UI** (recommended): visit
`/drust/admin/tenants/<tenant-id>/_oauth_providers` and use the form to
add the provider with its `client_id`, `client_secret`, and the list of
`allowed_redirect_uris` (one per line — these are the FRONTEND URLs you
redirect users back to after login, e.g.
`https://app.example.com/auth/callback`).

**REST** (service-key auth):

```bash
# upsert (PUT is idempotent — same call creates or updates)
curl -X PUT https://drust.example.com/drust/t/<tid>/admin/oauth-providers/google \
  -H "Authorization: Bearer <service_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "1234.apps.googleusercontent.com",
    "client_secret": "GOCSPX-...",
    "allowed_redirect_uris": ["https://app.example.com/auth/callback"]
  }'

# list (client_secret always redacted as "***")
curl https://drust.example.com/drust/t/<tid>/admin/oauth-providers \
  -H "Authorization: Bearer <service_token>"

# delete a provider
curl -X DELETE https://drust.example.com/drust/t/<tid>/admin/oauth-providers/google \
  -H "Authorization: Bearer <service_token>"
```

**MCP** (service-key, via Claude Code or any rmcp client):

```
set_oauth_provider(
  provider="google",
  client_id="1234.apps.googleusercontent.com",
  client_secret="GOCSPX-...",
  allowed_redirect_uris=["https://app.example.com/auth/callback"]
)

list_oauth_providers()
delete_oauth_provider(provider="google")
```

### Auto-register policy

The per-tenant `allow_self_register` flag (set on the tenant's
`/admin/tenants/<id>/_api_keys` page, or via the `set_self_register` MCP
tool) controls whether previously-unknown OAuth emails are allowed to
create a new `_system_users` row:

- `allow_self_register=1` → first OAuth login auto-creates a
  `_system_users` row with `verified=1`, profile JSON from the provider,
  and `password_hash="$oauth-only$"` sentinel (user can never log in
  with a password — only via OAuth on this provider).
- `allow_self_register=0` → only emails already in `_system_users` can
  OAuth in; new emails get `#error=oauth_not_allowed` on the frontend
  redirect.
- Either way, an existing `_system_users` row with a matching email
  (provider must return `email_verified=true`) is **auto-linked** — the
  user signs in to the existing account; profile JSON is NOT overwritten.

### Frontend integration

Kick off the flow with a regular link or `window.location.assign`:

```html
<a href="https://drust.example.com/drust/t/<tid>/oauth/google/start?redirect_uri=https://app.example.com/auth/callback">
  Continue with Google
</a>
```

After the user authenticates with the provider, drust 302s the browser
to the registered frontend callback URL with the token as a URL fragment:

```
https://app.example.com/auth/callback#access_token=drust_user_xxx&token_type=Bearer&expires_in=2592000
```

Read the fragment client-side, store the token, and use it as
`Authorization: Bearer drust_user_xxx` for subsequent drust API calls:

```js
const params = new URLSearchParams(window.location.hash.substring(1));
const token = params.get("access_token");
if (token) {
  localStorage.setItem("drust_token", token);
  window.location.replace("/");  // strip the fragment from the URL bar
}
```

> [!IMPORTANT]
> The token lives in the URL **fragment** (after `#`), which browsers do
> NOT send to the server. This is the Supabase / Auth0 / OAuth-implicit
> convention and is the reason drust does not need a public PKCE round
> trip with the frontend — the secret stays in the user agent.

### Error codes on frontend redirect

If any of the 10 callback steps fails, drust 302s to the frontend
callback with `#error=<code>` instead of `#access_token=...`. Codes:

| Code | Cause |
|---|---|
| `oauth_misconfigured` | Provider not configured for this tenant (no `_system_oauth_providers` row) |
| `oauth_state_mismatch` | Stale browser tab, cookies cleared, or CSRF attempt |
| `oauth_invalid_redirect` | Frontend `redirect_uri` not in `allowed_redirect_uris` |
| `oauth_provider_error` | Provider token endpoint failed (network / bad client_secret / etc.) |
| `oauth_email_unverified` | Provider returned `email_verified=false` |
| `oauth_not_allowed` | New user but `allow_self_register=0` |

The corresponding audit row in `/admin/tenants/<id>/_logs` carries
`auth_method=oauth_<provider>`, `oauth_email=<addr>`,
`oauth_error_code=<code>` — useful for diagnosing "the button doesn't
work" reports.

### Cross-tenant isolation

Each tenant's `_system_oauth_providers` table is in its own
`tenants/<tid>/data.sqlite`. Tenant A's service token cannot read,
write, or call OAuth for tenant B (the admin-REST routes are scoped by
path; service-token bearer auth is per-tenant). Audit, sessions, and
auto-created `_system_users` rows are all per-tenant.
