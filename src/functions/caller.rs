//! `CallerCtx` — the execution identity of a function invocation.
//!
//! Threaded through `Invocation` → executor → `HostState` (spec §1). It tells
//! the function host *whose* authorization to enforce on each data-plane host
//! op: `Privileged` runs god-mode (service/event/cron), while `Anon` / `User`
//! run capability-gated through the reusable enforcement core (anon_caps /
//! user_caps + owner_field + RLS + file caps).
//!
//! **Load-bearing invariant:** `CallerCtx` deliberately has NO `Default` and no
//! fallback that yields `Privileged`. A bug that lets an anon/user invocation
//! reach `Privileged` (god-mode) is a CRITICAL cross-privilege escalation, so
//! the type system refuses to construct an identity by accident — every site
//! must name the variant explicitly. Do NOT add `#[derive(Default)]` or a
//! `Default` impl.

use crate::auth::middleware::AuthCtx;
use crate::tenant::router::TokenRole;

/// Who an edge-function invocation runs as. No `Default` by design (see module
/// docs): the privileged variant must always be chosen explicitly.
#[derive(Clone, Debug)]
pub enum CallerCtx {
    /// Service invoke, event triggers, cron (phase 2) — god-mode, unchanged.
    Privileged,
    /// Anon invoke (opt-in) — `anon_caps` per op; owner_field denies anon.
    Anon,
    /// End-user (`drust_user_*`) invoke (opt-in) — `user_caps` per op;
    /// owner_field stamp/filter by `read_scope`; user RLS.
    User { user_id: String },
}

impl CallerCtx {
    /// The `AuthCtx` an enforcement-core call should see for this identity.
    ///
    /// - `Privileged` → `Service { admin_id: None }` (the shared-service power
    ///   level; no admin attribution for a function host call).
    /// - `Anon` → `Anon`.
    /// - `User` → `User { user_id, token_hash: "" }` — the function host carries
    ///   no bearer token, so `token_hash` is empty; enforcement keys on
    ///   `user_id` (owner_field / RLS `$auth`), never on the hash.
    pub fn to_auth_ctx(&self) -> AuthCtx {
        match self {
            CallerCtx::Privileged => AuthCtx::Service { admin_id: None },
            CallerCtx::Anon => AuthCtx::Anon,
            CallerCtx::User { user_id } => AuthCtx::User {
                user_id: user_id.clone(),
                token_hash: String::new(),
            },
        }
    }

    /// The `TokenRole` the cap-gate should apply for this identity.
    pub fn role(&self) -> TokenRole {
        match self {
            CallerCtx::Privileged => TokenRole::Service,
            CallerCtx::Anon => TokenRole::Anon,
            CallerCtx::User { .. } => TokenRole::User,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CallerCtx` has NO `Default` — there is intentionally no way to
    /// construct an identity without naming a variant. This test documents the
    /// invariant and constructs each variant explicitly; if someone adds a
    /// `Default` impl that yields `Privileged`, the design review (and the
    /// escalation tests in later tasks) must catch it. (A `Default` impl cannot
    /// be asserted-absent at runtime, so this test's role is to pin the
    /// explicit-construction contract and host the rationale.)
    #[test]
    fn caller_ctx_has_no_default() {
        let _privileged = CallerCtx::Privileged;
        let _anon = CallerCtx::Anon;
        let _user = CallerCtx::User {
            user_id: "u1".into(),
        };
        // Compile-time guarantee: `CallerCtx::default()` does not exist. We do
        // not call it here precisely because it must not compile.
    }

    #[test]
    fn to_auth_ctx_maps_each_variant() {
        assert!(matches!(
            CallerCtx::Privileged.to_auth_ctx(),
            AuthCtx::Service { admin_id: None }
        ));
        assert!(matches!(CallerCtx::Anon.to_auth_ctx(), AuthCtx::Anon));
        let user_ctx = CallerCtx::User {
            user_id: "abc".into(),
        };
        match user_ctx.to_auth_ctx() {
            AuthCtx::User {
                user_id,
                token_hash,
            } => {
                assert_eq!(user_id, "abc");
                assert!(
                    token_hash.is_empty(),
                    "function host call carries no bearer token"
                );
            }
            other => panic!("expected AuthCtx::User, got {other:?}"),
        }
    }

    #[test]
    fn role_maps_each_variant() {
        assert_eq!(CallerCtx::Privileged.role(), TokenRole::Service);
        assert_eq!(CallerCtx::Anon.role(), TokenRole::Anon);
        assert_eq!(
            CallerCtx::User {
                user_id: "x".into()
            }
            .role(),
            TokenRole::User
        );
    }
}
