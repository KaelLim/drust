//! Per-identity invoke gate for `POST /t/{tenant}/functions/{name}/invoke` (T6).
//!
//! The functions REST surface is split: CRUD + `/logs` stay service-only under
//! `require_service_layer`, but the **invoke** route runs under this layer,
//! which mirrors `file_caps::file_caps_layer`. Service is always allowed
//! (`Privileged`); anon/user are allowed iff the function's `invoke_anon` /
//! `invoke_user` flag is set (default 0 = service-only — every existing
//! function is unchanged), else `403 FN_INVOKE_ANON_DENIED` /
//! `FN_INVOKE_USER_DENIED`. On allow for a non-service caller a per-IP
//! rate-limit (`fn_invoke_rl`, mirrors `file_upload_rl`) bounds the public
//! anon-key DoS vector → `429 RATE_LIMITED_IP`.
//!
//! This is HTTP DiD layer 1. Layer 2 lives in the executor, which re-reads the
//! row before running and refuses a non-`Privileged` caller whose matching flag
//! is 0 — so flipping a flag off after the gate admitted a request still fails
//! closed. MCP `invoke_function` stays service-only by MCP dispatch.

use crate::tenant::router::{TenantAuthState, TenantRef, TokenRole};

/// Extract the `{name}` segment from `/…/functions/{name}/invoke`. Returns
/// `None` for any other shape (fail-closed at the caller). `{name}` is the
/// segment immediately following the literal `functions` marker; `invoke` is
/// never a function name (it sits one past `{name}`).
fn function_name_from_path(path: &str) -> Option<&str> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // Route shape is fixed: …/functions/{name}/invoke — `invoke` is ALWAYS the
    // terminal segment, `{name}` second-to-last, and the literal `functions`
    // marker third-to-last. Anchor from the END, not the first segment named
    // `functions`: a tenant id may itself be `functions` (not a reserved id),
    // and a function may be named `functions` OR `invoke` — any of which shifts
    // a forward scan onto the wrong segment. Only one segment can be terminal,
    // so end-anchoring is unambiguous for every (tenant, name) combination.
    let n = segs.len();
    if n >= 3 && segs[n - 1] == "invoke" && segs[n - 3] == "functions" {
        Some(segs[n - 2])
    } else {
        None
    }
}

/// Gate the invoke route per caller identity. Mounted INNER to
/// `bearer_auth_layer`, so `TenantRef` + `AuthCtx` are present — absence is
/// fail-closed 403.
pub async fn invoke_gate_layer(
    axum::extract::State(auth): axum::extract::State<TenantAuthState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let role = match req.extensions().get::<TenantRef>() {
        Some(t) => t.role,
        None => {
            return crate::error::json_error(
                axum::http::StatusCode::FORBIDDEN,
                "WRITE_DENIED",
                "service key or invoke permission required",
            );
        }
    };

    // Service is unrestricted (Privileged) by design — short-circuit before
    // touching the row or the rate-limit. Granting/revoking is service-only
    // config (T5); this gate only governs the data-plane invoke.
    if role == TokenRole::Service {
        return next.run(req).await;
    }

    // anon/user: load the function row and consult its invoke flag. The pool
    // ride-along on TenantRef is the tenant's own pool — no cross-tenant reach.
    let pool = match req.extensions().get::<TenantRef>() {
        Some(t) => t.pool.clone(),
        None => unreachable!("TenantRef checked above"),
    };
    let Some(name) = function_name_from_path(req.uri().path()) else {
        // Unknown shape behind this layer — fail closed.
        return crate::error::json_error(
            axum::http::StatusCode::FORBIDDEN,
            "WRITE_DENIED",
            "invoke permission required",
        );
    };
    let name = name.to_string();

    // Per-role deny response. A non-service caller must NOT be able to tell
    // "no such function" apart from "exists but its invoke flag is off": a
    // distinct 404-vs-403 is a function-name enumeration oracle for a public
    // anon key. Both the missing-row arm and the flag-off arm return this.
    let deny = |role: TokenRole| {
        let (code, msg) = match role {
            TokenRole::Anon => (
                "FN_INVOKE_ANON_DENIED",
                "anon invoke not enabled for this function",
            ),
            TokenRole::User => (
                "FN_INVOKE_USER_DENIED",
                "user invoke not enabled for this function",
            ),
            TokenRole::Service => unreachable!("service short-circuited above"),
        };
        crate::error::json_error_with_aliases(
            axum::http::StatusCode::FORBIDDEN,
            code,
            &["WRITE_DENIED"],
            msg,
        )
    };

    let row = match crate::functions::schema::get_function(&pool, &name).await {
        Ok(Some(r)) => r,
        // Do NOT 404 here — that would leak function existence to anon/user.
        Ok(None) => return deny(role),
        Err(e) => {
            return crate::error::json_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "FN_IO",
                &e.to_string(),
            );
        }
    };

    let allowed = match role {
        TokenRole::Anon => row.invoke_anon,
        TokenRole::User => row.invoke_user,
        TokenRole::Service => unreachable!("service short-circuited above"),
    };
    if !allowed {
        return deny(role);
    }

    // Allowed non-service invoke: per-IP rate-limit (cap already satisfied).
    // IP via XFF, loopback fallback (prod is always behind nginx→Caddy).
    let ip = crate::safety::ip::client_ip(
        req.headers(),
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
    );
    if !auth.fn_invoke_rl.check(ip) {
        return crate::error::json_error(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED_IP",
            "function invoke rate limit exceeded; retry shortly",
        );
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_function_name() {
        assert_eq!(
            function_name_from_path("/t/x/functions/myfn/invoke"),
            Some("myfn")
        );
        // base_path-prefixed shape (Caddy strips it, but be robust).
        assert_eq!(
            function_name_from_path("/drust/t/x/functions/abc/invoke"),
            Some("abc")
        );
        // A tenant whose id is literally `functions` (not a reserved id): the
        // parser must lock onto the `functions/{name}/invoke` triple, not the
        // first `functions` segment (which here is the tenant id).
        assert_eq!(
            function_name_from_path("/t/functions/functions/f1/invoke"),
            Some("f1")
        );
        // A function literally named `functions` resolves too.
        assert_eq!(
            function_name_from_path("/t/x/functions/functions/invoke"),
            Some("functions")
        );
        // Double edge case: tenant id `functions` AND a function named `invoke`
        // (both individually valid). End-anchoring resolves the terminal triple
        // correctly — a forward scan would mis-pick the tenant segment here.
        assert_eq!(
            function_name_from_path("/t/functions/functions/invoke/invoke"),
            Some("invoke")
        );
        // A function named `invoke` on an ordinary tenant.
        assert_eq!(
            function_name_from_path("/t/x/functions/invoke/invoke"),
            Some("invoke")
        );
    }

    #[test]
    fn rejects_non_invoke_shapes() {
        assert_eq!(function_name_from_path("/t/x/functions"), None);
        assert_eq!(function_name_from_path("/t/x/functions/myfn"), None);
        assert_eq!(function_name_from_path("/t/x/functions/myfn/logs"), None);
        assert_eq!(function_name_from_path("/t/x/files/abc"), None);
    }
}
