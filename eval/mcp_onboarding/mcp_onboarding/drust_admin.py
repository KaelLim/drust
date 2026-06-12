"""Minimal admin client for the live drust at 127.0.0.1:47826.

Talks to drust DIRECTLY (not through Caddy), so paths are UN-prefixed:
`/login`, `/admin/api/tenants`. (Through Caddy at :8793 they'd carry a
`/drust` prefix; drust itself binds 127.0.0.1:47826 with no prefix.)

The service token is read straight from the tenant-create response
(`initial_tokens.service`) — no whoami, no meta.sqlite.
"""
from __future__ import annotations

import uuid

import requests


class DrustAdmin:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._login(username, password)

    def _login(self, username: str, password: str) -> None:
        # login_submit takes a urlencoded form and sets the `drust_session`
        # cookie via a 302 redirect.
        resp = self._session.post(
            f"{self.base_url}/login",
            data={"username": username, "password": password},
            allow_redirects=False,
            timeout=10,
        )
        if "drust_session" not in self._session.cookies:
            raise RuntimeError(
                f"admin login failed (status {resp.status_code}); check "
                "DRUST_ADMIN_USERNAME / DRUST_ADMIN_PASSWORD"
            )

    def create_tenant(self, name: str | None = None) -> tuple[str, str]:
        """Create a throwaway tenant; return (tenant_id, service_token)."""
        name = name or f"eval-{uuid.uuid4().hex[:8]}"
        resp = self._session.post(
            f"{self.base_url}/admin/api/tenants",
            json={"name": name},
            timeout=15,
        )
        if resp.status_code != 201:
            raise RuntimeError(f"create_tenant failed: {resp.status_code} {resp.text}")
        body = resp.json()
        # CreatedResp { tenant{id,...}, initial_tokens{anon,service}, initial_token }
        return body["tenant"]["id"], body["initial_tokens"]["service"]

    def delete_tenant(self, tenant_id: str) -> None:
        """Soft-delete the tenant (204). Best-effort; never raises."""
        try:
            self._session.delete(
                f"{self.base_url}/admin/api/tenants/{tenant_id}", timeout=15
            )
        except requests.RequestException:
            pass
