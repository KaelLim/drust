//! Test-only STRUCTURAL PIN (#975): at every admin-PAT revocation site, the
//! auth-cache clear happens BEFORE the rooms eviction.
//!
//! ## Why this exists
//!
//! Eviction is only half of the #975 fix. Closing a socket makes the kicked
//! client reconnect IMMEDIATELY, and the reconnect goes through
//! `bearer_auth_layer`, which answers from the auth cache without a meta
//! lookup on a hit. So the two statements at each site are a pair with a
//! direction: clear the cache, THEN close the sockets. Inverted, a revoked PAT
//! can be re-admitted from the cache entry that the clear had not yet removed,
//! and the 10 s safety TTL — a bound, never the mechanism (CLAUDE.md invariant
//! 4) — is all that ends it. That is the second half of the spec's
//! defence-in-depth argument (spec §隔離與資安不變量 2, "絕不顛倒") and the
//! plan's per-site ordering invariant.
//!
//! ## Why it is pinned structurally rather than behaviourally
//!
//! Both calls are infallible in-memory operations with no observable
//! interleaving — nothing between them can be scheduled, so no test can watch
//! a caller land in the gap. A T2 quality reviewer MEASURED the consequence:
//! reversing the pair at `admin_pat.rs::reroll` and `admin_team.rs::remove_admin`
//! left `cargo test --test admin_pat_reroll` (4 passed), `cargo test --test
//! g_admin admin_team_crud` (12 passed) and `cargo test --lib rooms::` (59
//! passed) all GREEN with the invariant inverted. That is exactly the
//! condition #955 answered with a source-text pin, and this file is the same
//! answer for the seven sites that #975 created.
//!
//! ## What it does and does not claim
//!
//! It reads each handler's own comment-stripped source
//! ([`crate::tenant::rooms::srcpin`]) and asserts that the LAST
//! `clear_admin_pat(` precedes the FIRST `bus_rooms.evict` — i.e. every clear
//! before any evict, not merely the first pair in order. Both needles are
//! required, so deleting either call, or hiding either behind a helper with a
//! different name, fails CLOSED (the `expect` fires) rather than silently
//! passing — the escape that defeated three successive cuts of the sibling pin
//! in `bus.rs`.
//!
//! It does NOT check the CONDITION each evict sits under (`n > 0`, `changed >
//! 0`, the demotion-only predicate, `old_owner != new_owner`) or which evict
//! variant is used. Those are behaviourally observable through the eviction
//! epoch and are covered both-directions by the integration tests in
//! `tests/{admin_pat_reroll,admin_team_crud,cli_auth_endpoints,
//! tenant_ownership_transfer}.rs`. This pin covers only the part those tests
//! cannot see.

use crate::tenant::rooms::srcpin::{code_only, prod_fn_body, production_half};

/// The auth-cache clear. Deliberately the loose form rather than
/// `auth_cache.clear_admin_pat(`: [`the_pinned_site_list_is_the_whole_site_list`]
/// counts with the same needle, and for a completeness check the looser needle
/// is the safer one — it also sees a site that reaches the cache through some
/// other binding.
const CLEAR: &str = "clear_admin_pat(";

/// The rooms eviction — matches both variants in use
/// (`evict_all_tenants()` for the PAT family, `evict_tenant(&tid)` for the
/// owner transfer).
const EVICT: &str = "bus_rooms.evict";

/// `(display path, file source, handler heads)` from ONE file literal, so the
/// path in a failure message cannot drift from the file actually scanned.
macro_rules! site {
    ($file:literal, $($head:literal),+ $(,)?) => {
        (
            concat!("src/mgmt/", $file),
            include_str!($file),
            &[$($head),+] as &[&str],
        )
    };
}

/// Every site where a revocation clears the PAT auth cache and must then close
/// rooms sockets, grouped by file. `include_str!` resolves relative to this
/// file, so all three live in `src/mgmt/`.
///
/// This list is also the enumeration itself — CLAUDE.md's standing warning is
/// that these invariants are "enforced by enumeration across parallel sites",
/// so [`the_pinned_site_list_is_the_whole_site_list`] proves the list is
/// complete instead of asking a reader to trust it.
const SITES: &[(&str, &str, &[&str])] = &[
    site!(
        "admin_pat.rs",
        "pub async fn reroll(",
        "pub async fn cli_token_refresh(",
        "pub async fn cli_token_logout(",
        "pub async fn cli_token_revoke(",
    ),
    site!(
        "admin_team.rs",
        "pub async fn change_role(",
        "pub async fn remove_admin(",
    ),
    site!("tenant_settings.rs", "pub async fn patch_tenant_owner("),
];

/// #975 — the per-site ordering invariant, one assertion per site.
#[test]
fn every_revocation_site_clears_the_pat_cache_before_evicting_rooms_sockets() {
    for (path, raw, heads) in SITES {
        let stripped = code_only(raw);
        for head in *heads {
            let body = prod_fn_body(&stripped, head);

            // LAST clear vs FIRST evict: "every clear before any evict". The
            // owner-transfer site clears inside a loop over both sides, so a
            // first-vs-first comparison would pass with the evict wedged
            // between the two clears.
            let clear = body.rfind(CLEAR).unwrap_or_else(|| {
                panic!(
                    "{path} `{head}`: no `{CLEAR}` call. Either this handler stopped revoking \
                     PATs — in which case its rooms eviction should go too, and it should leave \
                     this list — or the clear moved behind a helper, which puts the ordering \
                     back out of this pin's sight. Do not just drop the site."
                )
            });
            let evict = body.find(EVICT).unwrap_or_else(|| {
                panic!(
                    "{path} `{head}`: no `{EVICT}` call. This handler revokes a PAT, so it must \
                     close the rooms sockets that PAT may still hold (#975); a revoked admin PAT \
                     otherwise keeps an `AuthCtx::Service` socket open indefinitely."
                )
            });

            assert!(
                clear < evict,
                "ORDER LOAD-BEARING (#975, spec §隔離與資安不變量 2): in {path} `{head}` the \
                 auth-cache clear must come BEFORE the rooms eviction, and here it does not. \
                 Evicting first closes the socket while the revoked PAT is still cached, and \
                 the kicked client reconnects immediately — `bearer_auth_layer` then serves it \
                 from that stale entry with NO meta lookup, so the revocation is defeated until \
                 the 10 s safety TTL expires. The TTL is a bound, not the mechanism (CLAUDE.md \
                 invariant 4). This ordering is invisible to every behavioural test — measured \
                 in the T2 review, which inverted two sites and watched every touched target \
                 stay green — which is why it is pinned here."
            );
        }
    }
}

/// #975 — the list above must BE the site list, not a sample of it.
///
/// Without this, adding an eighth revocation path that clears the cache and
/// evicts in the wrong order would be invisible: the pin would happily verify
/// the seven it knows. Counting both needles across the whole production half
/// of each file and requiring the pinned bodies to account for every one of
/// them turns "someone remembered to add the site here" into a build failure
/// when they did not.
#[test]
fn the_pinned_site_list_is_the_whole_site_list() {
    for (path, raw, heads) in SITES {
        let stripped = code_only(raw);
        let prod = production_half(&stripped);

        for needle in [CLEAR, EVICT] {
            let in_file = prod.matches(needle).count();
            let in_pinned: usize = heads
                .iter()
                .map(|head| prod_fn_body(&stripped, head).matches(needle).count())
                .sum();
            assert_eq!(
                in_pinned, in_file,
                "{path} has {in_file} `{needle}` call(s) but only {in_pinned} of them are inside \
                 a pinned handler — a revocation site was added, moved or renamed without \
                 joining `SITES` in this file, so its clear/evict ordering is unpinned. Add the \
                 handler's `pub async fn …(` head to `SITES` (and give it an integration test \
                 for the eviction itself)."
            );
        }
    }
}
