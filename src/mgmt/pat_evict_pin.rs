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
//! `clear_admin_pat(` precedes the FIRST eviction call — i.e. every clear
//! before any evict, not merely the first pair in order. Both needles are
//! required, so deleting either call, or hiding either behind a helper with a
//! different name, fails CLOSED (the `expect` fires) rather than silently
//! passing — the escape that defeated three successive cuts of the sibling pin
//! in `bus.rs`. "Eviction call" is [`EVICTS`], a small closed set of accepted
//! spellings, because since the T2 review the four `admin_pat.rs` sites reach
//! the bus through the shared reach-scoped `mgmt::pat_evict` decision instead
//! of calling it directly.
//!
//! It does NOT check the CONDITION each evict sits under (`n > 0`, `changed >
//! 0`, the demotion-only predicate, `old_owner != new_owner`), which evict
//! variant is used, or WHICH TENANTS the eviction covers. Those are
//! behaviourally observable through the eviction
//! epoch — the reach decision additionally has unit tests in
//! `mgmt::pat_evict` — and are covered both-directions by the integration
//! tests in
//! `tests/{admin_pat_reroll,admin_team_crud,cli_auth_endpoints,
//! tenant_ownership_transfer}.rs`. This pin covers only the part those tests
//! cannot see.
//!
//! ## Three tests, three scopes
//!
//! The three below are a ladder, and the top rung was missing for one commit:
//!
//! 1. [`every_revocation_site_clears_the_pat_cache_before_evicting_rooms_sockets`]
//!    — per HANDLER: the ordering itself.
//! 2. [`the_pinned_site_list_is_the_whole_site_list`] — per FILE: inside each
//!    of the three pinned files, every needle is accounted for by a pinned
//!    handler, so an unpinned handler in `admin_pat.rs` is a build failure.
//! 3. [`no_revocation_site_hides_outside_the_pinned_files`] — TREE-wide: no
//!    OTHER file under `src/` reaches the PAT cache at all. Without it (2)
//!    was one scope narrower than the invariant it claimed to encode, and a
//!    T2 quality reviewer MEASURED the consequence: an eighth revocation site
//!    added to `src/mgmt/tokens.rs` — a file that already evicts, with the
//!    clear placed AFTER the evict, i.e. exactly the inversion these pins
//!    exist to forbid — left `cargo test --lib pat_evict_pin` at 2 passed / 0
//!    failed. The spec grounds the site set with a TREE-wide grep ("全樹
//!    `clear_admin_pat` 呼叫者就是這 7 站"), so only a tree-wide check can
//!    honestly carry the name of test (2).

use std::path::{Path, PathBuf};

use crate::tenant::rooms::srcpin::{code_only, prod_fn_body, production_half};

/// The auth-cache clear. Deliberately the loose form rather than
/// `auth_cache.clear_admin_pat(`: [`the_pinned_site_list_is_the_whole_site_list`]
/// counts with the same needle, and for a completeness check the looser needle
/// is the safer one — it also sees a site that reaches the cache through some
/// other binding.
const CLEAR: &str = "clear_admin_pat(";

/// The rooms eviction, in every spelling a site may legitimately use.
///
/// Two, because the eviction SET is not the same at every site:
///
/// - `bus_rooms.evict` — the direct bus call. Covers both variants
///   (`evict_all_tenants()` where the revoked identity's reach genuinely is the
///   host, `evict_tenant(&tid)` for the owner transfer's single tenant).
/// - `pat_evict::evict_pat_rooms_sockets(` — the shared reach-scoped decision
///   the four self-service PAT-lifecycle sites in `admin_pat.rs` go through
///   (#975 T2 review, MED): those sites are reachable by a `member`, so a
///   host-wide evict there was a cross-tenant availability lever anyone could
///   pull. The helper picks host-wide vs the caller's owned tenants; the SITE's
///   obligation — clear the cache before you close the sockets — is unchanged,
///   which is why it is still what this pin measures.
///
/// - `pat_evict::evict_reach(` — the pre-image variant of the same decision,
///   for a site that must read the reach BEFORE destroying the rows it derives
///   from (`remove_admin`: the FK `ON DELETE SET NULL` orphans
///   `tenants.owner_admin_id` at DELETE time, so the live read would answer
///   `Owned([])` after the fact and evict nothing).
///
/// A site satisfies the pin with ANY spelling. All are counted for
/// completeness, so moving a site from one spelling to another stays accounted
/// for and deleting the call entirely still fails closed.
const EVICTS: &[&str] = &[
    "bus_rooms.evict",
    "pat_evict::evict_pat_rooms_sockets(",
    "pat_evict::evict_reach(",
];

/// Human-readable form of [`EVICTS`] for failure messages.
fn evicts_display() -> String {
    EVICTS.join("` / `")
}

/// Offset of the FIRST eviction call of any spelling in `body`.
fn first_evict(body: &str) -> Option<usize> {
    EVICTS.iter().filter_map(|n| body.find(n)).min()
}

/// How many eviction calls of any spelling `hay` contains.
fn count_evicts(hay: &str) -> usize {
    EVICTS.iter().map(|n| hay.matches(n).count()).sum()
}

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
            let evict = first_evict(body).unwrap_or_else(|| {
                let evicts = evicts_display();
                panic!(
                    "{path} `{head}`: no `{evicts}` call. This handler revokes a PAT, so it must \
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

/// #975 — inside each PINNED FILE, the list above must BE the site list.
///
/// Without this, adding an eighth revocation path to `admin_pat.rs` that clears
/// the cache and evicts in the wrong order would be invisible: the pin would
/// happily verify the four it knows. Counting both needles across the whole
/// production half of each file and requiring the pinned bodies to account for
/// every one of them turns "someone remembered to add the site here" into a
/// build failure when they did not.
///
/// Its scope stops at the three files it iterates, which is why
/// [`no_revocation_site_hides_outside_the_pinned_files`] exists.
#[test]
fn the_pinned_site_list_is_the_whole_site_list() {
    for (path, raw, heads) in SITES {
        let stripped = code_only(raw);
        let prod = production_half(&stripped);

        // `(display name, count in a haystack)` — the eviction half counts
        // every spelling in `EVICTS` together, so a site that switches from the
        // direct bus call to the shared reach-scoped helper (or back) is still
        // accounted for rather than reading as a vanished site.
        let counters: [(String, fn(&str) -> usize); 2] = [
            (CLEAR.to_string(), |hay: &str| hay.matches(CLEAR).count()),
            (evicts_display(), count_evicts),
        ];
        for (needle, count) in &counters {
            let in_file = count(prod);
            let in_pinned: usize = heads
                .iter()
                .map(|head| count(prod_fn_body(&stripped, head)))
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

/// Files under `src/` that mention [`CLEAR`] and are NOT revocation sites, as
/// `(path, why it is not one)`.
///
/// This is the single escape hatch in the tree-wide check below, so the reason
/// is part of the data: an unexplained entry is how an allowlist rots into "add
/// it to the list" reflex, and [`no_revocation_site_hides_outside_the_pinned_files`]
/// additionally fails if an entry here has STOPPED matching, so a stale one
/// cannot linger either. Adding a row is a reviewed act, never a way to quiet
/// the test — a file that actually calls `clear_admin_pat` on a revocation path
/// belongs in `SITES`, not here.
const NON_SITE_CLEAR_FILES: &[(&str, &str)] = &[
    (
        "src/tenant/auth_cache.rs",
        "the definition of `clear_admin_pat` itself — the cache, not a caller",
    ),
    (
        "src/mgmt/pat_evict_pin.rs",
        "this pin: the needle constants and the failure text that quotes them",
    ),
];

/// #975 — TREE-wide: the PAT auth cache is reached from the pinned files only.
///
/// [`the_pinned_site_list_is_the_whole_site_list`] proves completeness INSIDE
/// three hardcoded files, which is one scope narrower than the invariant —
/// CLAUDE.md's warning is that these are "enforced by enumeration across
/// parallel sites", and a parallel site is free to appear anywhere. A T2
/// reviewer measured the hole: an eighth site in `src/mgmt/tokens.rs` with the
/// order INVERTED left both other pins green. This walks the tree instead, so
/// the enumeration is grounded the same way the spec grounded it (a `src`-wide
/// grep) rather than by a list someone has to remember to extend.
///
/// Deliberately keyed on [`CLEAR`] alone, not [`EVICTS`]: `bus_rooms.evict` is
/// a general realtime operation with eight legitimate non-PAT callers (tenant
/// soft-delete, token reroll, user-session revoke, publish-policy, …), so
/// requiring an allowlist row for each of those would be noise. Touching the
/// PAT cache is what makes a site a PAT-revocation site, and that needle has
/// exactly the callers enumerated here.
#[test]
fn no_revocation_site_hides_outside_the_pinned_files() {
    // `include_str!` cannot express "every file in the tree" — it needs a
    // literal path per file, which is the very list being verified. Hence the
    // fs walk. `CARGO_MANIFEST_DIR` is baked in at compile time, so the test
    // does not depend on the working directory `cargo test` was launched from.
    let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut files = Vec::new();
    collect_rs_files(root, &mut files);
    files.sort();

    // A walk that finds nothing passes vacuously — the fail-OPEN direction
    // this whole test exists to remove, and the one that a moved/renamed `src`
    // or a sandboxed fs would produce silently.
    assert!(
        files.len() > 100,
        "the tree walk found only {} .rs file(s) under {} — this crate has far more, so the \
         walk is not seeing the source tree and every assertion below would pass vacuously",
        files.len(),
        root.display(),
    );

    let mut sites_seen = [false; SITES.len()];
    let mut allowed_seen = vec![false; NON_SITE_CLEAR_FILES.len()];
    let mut offenders: Vec<String> = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(root)
            .expect("collect_rs_files only yields paths under root");
        let rel = format!("src/{}", rel.to_string_lossy().replace('\\', "/"));
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

        // The pinned files are read twice: by `include_str!` at compile time
        // for the two pins above, and from disk here. Prove it is the same
        // text, so a `SITES` display path that has drifted from the real
        // layout (or a walk rooted at a stale copy of the tree) cannot let
        // this test bless a file the other two never looked at.
        if let Some(i) = SITES.iter().position(|(p, _, _)| *p == rel) {
            sites_seen[i] = true;
            assert!(
                raw == SITES[i].1,
                "{rel} on disk differs from the `include_str!` copy the other two pins scan — \
                 they are not looking at the same file, so their guarantees do not apply to \
                 the tree this test is walking",
            );
        }

        // Comment-stripped, but NOT `production_half`: cutting at the first
        // `#[cfg(test)]` is fail-OPEN for a whole-file scan, and `src/mgmt/mod.rs`
        // proves it — its `#[cfg(test)] mod pat_evict_pin;` sits above forty
        // more production items, all of which the cut would discard. Test-only
        // code that legitimately calls the cache would therefore surface here;
        // that fails CLOSED, and the fix is a reviewed row in
        // `NON_SITE_CLEAR_FILES` (there are none today).
        if !code_only(&raw).contains(CLEAR) {
            continue;
        }

        if SITES.iter().any(|(p, _, _)| *p == rel) {
            continue;
        }
        match NON_SITE_CLEAR_FILES.iter().position(|(p, _)| *p == rel) {
            Some(i) => allowed_seen[i] = true,
            None => offenders.push(rel),
        }
    }

    // Reachability of the pinned files is asserted FIRST, before the offender
    // list: a drifted `SITES` display path makes all three site files look like
    // unpinned offenders, and that symptom message would send a reader off to
    // add `admin_pat.rs` to a list it is already on. Root cause first.
    for (seen, (path, _, _)) in sites_seen.iter().zip(SITES) {
        assert!(
            seen,
            "the pinned site file {path} was never reached by the tree walk under {} — its \
             `SITES` display path has drifted from where the file actually lives. The other \
             two pins would not notice, because `include_str!` resolves relative to THIS \
             file and keeps compiling the right bytes under a wrong-looking name; the \
             consequence is that every failure message points at a path nobody can open, and \
             that this test can no longer tell a moved site file from a deleted one.",
            root.display(),
        );
    }

    assert!(
        offenders.is_empty(),
        "these file(s) reach the PAT auth cache (`{CLEAR}`) but are neither a pinned \
         revocation site nor a declared non-site: {offenders:?}.\n\
         If one IS a revocation path, it must (a) evict rooms sockets — a revoked admin PAT \
         resolves to `AuthCtx::Service` and keeps its live WS open indefinitely otherwise — \
         (b) do the clear BEFORE the evict, and (c) join `SITES` in this file plus get an \
         integration test for the eviction. If it genuinely is not one, add it to \
         `NON_SITE_CLEAR_FILES` WITH the reason. Do not delete this assertion: it is the \
         only tree-wide half of the #975 enumeration.",
    );

    for (seen, (path, why)) in allowed_seen.iter().zip(NON_SITE_CLEAR_FILES) {
        assert!(
            seen,
            "`NON_SITE_CLEAR_FILES` still exempts {path} ({why}), but that file no longer \
             contains `{CLEAR}` — the exemption is stale. Drop the row; an allowlist nobody \
             prunes is how the next real site gets waved through.",
        );
    }
}

/// Every `.rs` file at or below `dir`, recursively. Panics rather than skipping
/// an unreadable directory: a walk that quietly covers less than the tree is
/// exactly the vacuous pass this pin must not have.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("cannot walk {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}
