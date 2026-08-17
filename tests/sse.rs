mod helpers;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use eventsource_stream::Eventsource;
use futures::StreamExt;
use helpers::{grab_pool, spin_up_tenant};
use tower::ServiceExt;

async fn seed(dir: &tempfile::TempDir) {
    let pool = grab_pool("blog", dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();
}

/// #976 F2 — a subscription opened with an admin PAT that carries
/// `expires_at` must END at that expiry instead of holding a live event
/// stream under a dead credential. The extension is injected directly here
/// because that is exactly what `bearer_auth_layer`'s PAT arms do; a client
/// cannot set a request extension over the wire.
#[tokio::test]
async fn pat_deadline_ends_the_stream_at_the_deadline() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed(&d).await;

    let started = std::time::Instant::now();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::ACCEPT, "text/event-stream")
                .extension(drust::tenant::rooms::ws_auth::PatDeadline(
                    chrono::Utc::now() + chrono::Duration::milliseconds(400),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body = resp.into_body().into_data_stream();
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(chunk) = body.next().await {
            let _ = chunk;
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "the SSE stream was still open 5s past a 400ms credential deadline — \
         #976 F2's SSE face is off"
    );
    // Lower bound: the stream must have ended BECAUSE of the deadline, not
    // instantly for some unrelated reason (a dropped bus sender would also
    // satisfy the assertion above).
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(250),
        "stream ended after {:?}, well before its 400ms deadline — something \
         other than the expiry closed it",
        started.elapsed()
    );
}

/// The control arm: no `PatDeadline` extension ⇒ no timer at all, i.e. the
/// pre-#976 behaviour. Without this, arming every connection at
/// `Instant::now()` would satisfy the test above.
#[tokio::test]
async fn a_subscription_with_no_deadline_is_never_ended_by_one() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed(&d).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body = resp.into_body().into_data_stream();
    let drained = tokio::time::timeout(std::time::Duration::from_millis(800), async {
        while let Some(chunk) = body.next().await {
            let _ = chunk;
        }
    })
    .await;
    assert!(
        drained.is_err(),
        "a subscription carrying no credential deadline ended on its own"
    );
}

#[tokio::test]
async fn subscribe_receives_created_event() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed(&d).await;

    // Open SSE stream.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/event-stream"));

    // Trigger an insert in parallel
    let app2 = app.clone();
    let tok2 = tok.clone();
    let inserter = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/t/blog/records/posts")
                    .header(header::AUTHORIZATION, format!("Bearer {tok2}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"data":{"title":"hi"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
    });

    let body = resp.into_body();
    let bytes_stream = tokio_stream::wrappers::ReceiverStream::new({
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let mut body_stream = body.into_data_stream();
        tokio::spawn(async move {
            while let Some(chunk) = body_stream.next().await {
                if let Ok(b) = chunk {
                    let _ = tx.send(Ok::<_, std::io::Error>(b)).await;
                }
            }
        });
        rx
    });
    let mut events = bytes_stream.eventsource();

    let ev = tokio::time::timeout(std::time::Duration::from_secs(2), events.next())
        .await
        .expect("timeout");
    inserter.await.unwrap();
    let ev = ev.expect("closed").expect("err");
    assert_eq!(ev.event, "created");
}
