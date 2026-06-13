//! Row-level security policy engine. A `Policy` is a per-operation pair of
//! bounded `FilterAst` expressions: `using` (which existing rows) and
//! `check` (is the new row allowed). Two evaluators share the grammar —
//! `compile_policy_using` (→ SQL) and `eval_policy` (→ bool in memory).
//! See `docs/superpowers/specs/2026-06-12-drust-rls-policies-design.md`.

use crate::auth::middleware::AuthCtx;
use crate::query::vector_filter::FilterAst;
use crate::storage::schema::DmlVerb;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// One operation's policy: a `using` predicate (which existing rows) and/or
/// a `check` predicate (is the new/post-image row allowed). Both are
/// optional; a `None` clause means "no predicate for that direction".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub using: Option<FilterAst>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub check: Option<FilterAst>,
}

/// The four per-operation policies for a collection. All `None` = the
/// collection has no explicit policy (governed by tier rules + owner_field).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectionPolicies {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub select: Option<Policy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insert: Option<Policy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<Policy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<Policy>,
}

impl CollectionPolicies {
    pub fn get(&self, op: DmlVerb) -> Option<&Policy> {
        match op {
            DmlVerb::Select => self.select.as_ref(),
            DmlVerb::Insert => self.insert.as_ref(),
            DmlVerb::Update => self.update.as_ref(),
            DmlVerb::Delete => self.delete.as_ref(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.select.is_none()
            && self.insert.is_none()
            && self.update.is_none()
            && self.delete.is_none()
    }
}

/// Evaluation context: the caller's identity and (for CHECK) the row under
/// test. `auth_id` is `None` for anon. `data` is the row map for `eval_policy`
/// (CHECK); `None` for USING compilation.
#[derive(Debug, Clone, Default)]
pub struct PolicyCtx {
    pub auth_id: Option<String>,
    pub data: Option<serde_json::Map<String, Json>>,
}

impl PolicyCtx {
    pub fn from_auth(ctx: &AuthCtx) -> Self {
        Self {
            auth_id: ctx.user_id().map(|s| s.to_string()),
            data: None,
        }
    }
    pub fn with_row(ctx: &AuthCtx, row: serde_json::Map<String, Json>) -> Self {
        Self {
            auth_id: ctx.user_id().map(|s| s.to_string()),
            data: Some(row),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::schema::DmlVerb;

    #[test]
    fn policy_roundtrips_json() {
        let raw = r#"{"using":{"status":"published"},"check":{"author":{"$eq":{"$auth":"id"}}}}"#;
        let p: Policy = serde_json::from_str(raw).unwrap();
        assert!(p.using.is_some());
        assert!(p.check.is_some());
        let back = serde_json::to_string(&p).unwrap();
        let p2: Policy = serde_json::from_str(&back).unwrap();
        assert!(p2.using.is_some() && p2.check.is_some());
    }

    #[test]
    fn collection_policies_get_by_verb() {
        let cp = CollectionPolicies {
            select: Some(Policy::default()),
            ..Default::default()
        };
        assert!(cp.get(DmlVerb::Select).is_some());
        assert!(cp.get(DmlVerb::Insert).is_none());
    }

    #[test]
    fn policy_ctx_from_anon_has_no_auth_id() {
        let ctx = crate::auth::middleware::AuthCtx::Anon;
        let pc = PolicyCtx::from_auth(&ctx);
        assert!(pc.auth_id.is_none());
    }
}
