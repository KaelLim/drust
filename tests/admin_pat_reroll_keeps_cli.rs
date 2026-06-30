// tests/admin_pat_reroll_keeps_cli.rs — T4.5: UI-PAT reroll must not nuke CLI PATs.
mod helpers;

use axum::Extension;
use axum::extract::State;
use drust::auth::middleware::AdminId;
use drust::tenant::auth_cache::AuthCache;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn reroll_revokes_only_the_unlabeled_ui_pat() {
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    let (state, dir) = helpers::mgmt_state_with_cache_and_admin(42, cache).await;
    // Seed: one unlabeled UI PAT + two labeled CLI PATs, all active.
    {
        let conn = drust::storage::meta::open_meta(&dir.path().join("meta.sqlite")).unwrap();
        conn.execute_batch(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (42,'ui_h','ui_p');
             INSERT INTO _admin_tokens (admin_id, token_hash, plaintext, label) VALUES (42,'a_h','a_p','cli:a');
             INSERT INTO _admin_tokens (admin_id, token_hash, plaintext, label) VALUES (42,'b_h','b_p','cli:b');").unwrap();
    }
    let resp = drust::mgmt::admin_pat::reroll(State(state.clone()), Extension(AdminId(42))).await;
    assert!(resp.status().is_success());

    let conn = drust::storage::meta::open_meta(&dir.path().join("meta.sqlite")).unwrap();
    let cli_active: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM _admin_tokens WHERE label IS NOT NULL AND revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cli_active, 2, "both labeled CLI PATs survive the reroll");
    let old_ui_revoked: Option<String> = conn
        .query_row(
            "SELECT revoked_at FROM _admin_tokens WHERE token_hash='ui_h'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(old_ui_revoked.is_some(), "old unlabeled UI PAT revoked");
    let ui_active: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM _admin_tokens \
             WHERE admin_id=42 AND label IS NULL AND revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        ui_active, 1,
        "exactly one fresh unlabeled UI PAT (relaxed index satisfied)"
    );
}
