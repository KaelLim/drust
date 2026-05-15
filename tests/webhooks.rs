mod webhooks_common;
use webhooks_common::FakeHook;

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
