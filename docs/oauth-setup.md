---
type: doc
service: drust
topic: oauth-setup
status: production
updated: 2026-05-15
---

# Admin OAuth setup

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
