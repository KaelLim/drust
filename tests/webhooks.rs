mod webhooks_common;
use webhooks_common::FakeHook;
use drust::tenant::webhook_dispatcher::{
    compute_signature, deliver_for_test, DeliverySchedule, WebhookRow,
};

fn fake_row(url: &str) -> WebhookRow {
    WebhookRow {
        id: 1,
        collection: "videos".into(),
        events: r#"["created"]"#.into(),
        url: url.into(),
        secret: "topsecret".into(),
        active: 1,
    }
}

#[tokio::test]
async fn fake_hook_records_post_with_body() {
    let hook = FakeHook::start().await;
    let body = serde_json::json!({"hi":"there"}).to_string();
    let resp = reqwest::Client::new()
        .post(hook.url())
        .header("Content-Type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let received = hook.requests().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].body_text, body);
    assert_eq!(
        received[0].headers.get("content-type").map(|s| s.as_str()),
        Some("application/json"),
    );
}

#[tokio::test]
async fn deliver_happy_path_signature_matches() {
    let hook = FakeHook::start().await;
    let payload = serde_json::json!({"event":"created","record":{"id":1}});
    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let expected_sig = compute_signature("topsecret", &body_bytes);
    let outcome = deliver_for_test(
        &reqwest::Client::new(),
        &fake_row(hook.url()),
        body_bytes.clone(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(outcome.is_ok(), "happy path must succeed");
    let received = hook.requests().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].headers.get("x-drust-signature").unwrap(), &expected_sig);
}

#[tokio::test]
async fn deliver_retries_on_5xx_then_succeeds() {
    let hook = FakeHook::start_scripted(vec![500, 503]).await; // then 200
    let outcome = deliver_for_test(
        &reqwest::Client::new(),
        &fake_row(hook.url()),
        b"{}".to_vec(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(outcome.is_ok(), "must succeed on 3rd attempt");
    assert_eq!(hook.requests().await.len(), 3);
}

#[tokio::test]
async fn deliver_stops_on_4xx() {
    let hook = FakeHook::start_scripted(vec![401]).await;
    let outcome = deliver_for_test(
        &reqwest::Client::new(),
        &fake_row(hook.url()),
        b"{}".to_vec(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(outcome.is_err(), "4xx must be terminal");
    assert_eq!(hook.requests().await.len(), 1, "no retry on 4xx");
}

#[tokio::test]
async fn deliver_all_four_attempts_fail_returns_err() {
    let hook = FakeHook::start_scripted(vec![500, 500, 500, 500]).await;
    let outcome = deliver_for_test(
        &reqwest::Client::new(),
        &fake_row(hook.url()),
        b"{}".to_vec(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(outcome.is_err(), "4 consecutive 5xx must fail");
    assert_eq!(hook.requests().await.len(), 4);
}
