use crate::common;
use common::mock_garage_admin::MockAdminServer;
use drust::storage::garage::GarageClient;

#[tokio::test]
async fn garage_client_can_reach_mock_admin_server() {
    let srv = MockAdminServer::start().await;
    let body = reqwest::Client::new()
        .get(format!("{}/v1/status", srv.base_url()))
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(body.status(), 200);
    assert_eq!(srv.requests().len(), 1);
}

#[tokio::test]
async fn create_bucket_posts_global_alias_payload() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "admin-token");

    let id = c.create_bucket("tenant-foo-pub").await.unwrap();
    assert_eq!(id, "bkt-1");

    let reqs = srv.requests();
    let last = reqs.last().unwrap();
    assert_eq!(last.method, "POST");
    assert_eq!(last.path, "/v1/bucket");
    assert!(last.body.contains("tenant-foo-pub"), "body: {}", last.body);
    assert_eq!(last.auth.as_deref(), Some("Bearer admin-token"));
}

#[tokio::test]
async fn create_bucket_propagates_admin_error() {
    let srv = MockAdminServer::start().await;
    srv.fail_next_with(axum::http::StatusCode::CONFLICT);
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");

    let err = c.create_bucket("x").await.unwrap_err();
    assert!(err.to_string().contains("409"));
}

#[tokio::test]
async fn lookup_bucket_returns_id_when_present() {
    let srv = MockAdminServer::start().await;
    srv.seed_bucket("public", "bkt-existing");
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");

    let info = c.lookup_bucket("public").await.unwrap();
    assert_eq!(info.unwrap().id, "bkt-existing");
}

#[tokio::test]
async fn lookup_bucket_returns_none_on_404() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");
    let info = c.lookup_bucket("nonexistent").await.unwrap();
    assert!(info.is_none());
}

#[tokio::test]
async fn delete_bucket_sends_id_query() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");
    c.delete_bucket("bkt-123").await.unwrap();

    let last = srv.requests().last().unwrap().clone();
    assert_eq!(last.method, "DELETE");
    assert_eq!(last.path, "/v1/bucket");
    assert!(last.query.contains("id=bkt-123"));
}

#[tokio::test]
async fn set_website_enabled_puts_websiteaccess_true() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");
    c.set_website("bkt-7", true).await.unwrap();
    let last = srv.requests().last().unwrap().clone();
    assert_eq!(last.method, "PUT");
    assert_eq!(last.path, "/v1/bucket/bkt-7");
    assert!(last.body.contains("\"websiteAccess\""));
    assert!(last.body.contains("\"enabled\":true"));
}

#[tokio::test]
async fn set_website_disabled_puts_websiteaccess_false() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");
    c.set_website("bkt-7", false).await.unwrap();
    let last = srv.requests().last().unwrap().clone();
    assert_eq!(last.method, "PUT");
    assert_eq!(last.path, "/v1/bucket/bkt-7");
    assert!(last.body.contains("\"websiteAccess\""));
    assert!(last.body.contains("\"enabled\":false"));
}

#[tokio::test]
async fn bucket_allow_includes_permissions_block() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");
    c.bucket_allow("bkt-1", "GKkey", true, true, true)
        .await
        .unwrap();
    let last = srv.requests().last().unwrap().clone();
    assert_eq!(last.path, "/v1/bucket/allow");
    assert!(last.body.contains("bkt-1"));
    assert!(last.body.contains("GKkey"));
    assert!(last.body.contains("\"read\":true"));
    assert!(last.body.contains("\"write\":true"));
    assert!(last.body.contains("\"owner\":true"));
}

#[tokio::test]
async fn bucket_deny_posts_key_and_bucket() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");
    c.bucket_deny("bkt-1", "GKkey").await.unwrap();
    let last = srv.requests().last().unwrap().clone();
    assert_eq!(last.path, "/v1/bucket/deny");
    assert!(last.body.contains("bkt-1"));
    assert!(last.body.contains("GKkey"));
}

// ---- Garage admin API is optional (GARAGE_ADMIN_* unset or half-set) ----

#[tokio::test]
async fn admin_api_without_endpoint_errors_with_config_hint() {
    // `from_store` leaves both admin fields empty: the "not configured" state
    // an S3-trio-only deployment now boots into.
    let store: std::sync::Arc<dyn object_store::ObjectStore> =
        std::sync::Arc::new(object_store::memory::InMemory::new());
    let c = GarageClient::from_store(store, "public");
    let err = c.lookup_bucket("x").await.unwrap_err().to_string();
    assert!(
        err.contains("GARAGE_ADMIN_ENDPOINT") && err.contains("not configured"),
        "an unconfigured admin API must say which settings are missing, got: {err}"
    );
}

#[tokio::test]
async fn admin_api_with_endpoint_but_no_token_sends_no_request() {
    // A half pair reads as "not configured" in config, and the client guards
    // the same way: no request with an empty bearer ever leaves.
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "");
    assert!(c.create_bucket("x").await.is_err());
    assert!(c.lookup_bucket("x").await.is_err());
    assert!(c.delete_bucket("bkt-1").await.is_err());
    assert!(c.set_website("bkt-1", false).await.is_err());
    assert!(
        c.bucket_allow("bkt-1", "GK", true, true, true)
            .await
            .is_err()
    );
    assert!(c.bucket_deny("bkt-1", "GK").await.is_err());
    assert!(
        srv.requests().is_empty(),
        "no admin request may be sent without a token, got {:?}",
        srv.requests()
            .iter()
            .map(|r| r.path.clone())
            .collect::<Vec<_>>()
    );
}

// ---- Boot probe: every bucket a write can land in is listed, concurrently ----

/// A minimal path-style S3 endpoint for `ListObjectsV2`. object_store sends
/// `GET /<bucket>?list-type=2…`; route on the path segment, ignore the query.
mod s3_stub {
    use axum::extract::{Path, State};
    use axum::http::{StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use std::sync::{Arc, Mutex};
    use tokio::sync::Barrier;

    #[derive(Clone)]
    struct St {
        existing: Arc<Vec<String>>,
        paths: Arc<Mutex<Vec<String>>>,
        /// When set, a list of `public` or `private` waits here before it is
        /// answered, so only concurrently issued lists can both complete.
        barrier: Option<Arc<Barrier>>,
    }

    pub struct Stub {
        pub endpoint: String,
        paths: Arc<Mutex<Vec<String>>>,
    }

    impl Stub {
        pub fn paths(&self) -> Vec<String> {
            self.paths.lock().unwrap().clone()
        }
    }

    pub async fn start(existing: &[&str], barrier: Option<Arc<Barrier>>) -> Stub {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let st = St {
            existing: Arc::new(existing.iter().map(|s| s.to_string()).collect()),
            paths: paths.clone(),
            barrier,
        };
        let app = axum::Router::new()
            .route("/{bucket}", axum::routing::get(list))
            .with_state(st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Stub {
            endpoint: format!("http://{addr}"),
            paths,
        }
    }

    async fn list(State(st): State<St>, Path(bucket): Path<String>) -> Response {
        st.paths.lock().unwrap().push(format!("/{bucket}"));
        if let Some(b) = &st.barrier
            && (bucket == "public" || bucket == "private")
        {
            b.wait().await;
        }
        let xml = [(header::CONTENT_TYPE, "application/xml")];
        if st.existing.contains(&bucket) {
            (
                StatusCode::OK,
                xml,
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Name>{bucket}</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
                     <MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>"
                ),
            )
                .into_response()
        } else {
            (
                StatusCode::NOT_FOUND,
                xml,
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <Error><Code>NoSuchBucket</Code>\
                     <Message>The specified bucket does not exist</Message>\
                     <BucketName>{bucket}</BucketName></Error>"
                ),
            )
                .into_response()
        }
    }
}

/// A real (S3) client pointed at the stub, built from config exactly as boot
/// builds it. No admin API: the probe must not need one.
fn s3_client(endpoint: &str, default_bucket: &str) -> GarageClient {
    let cfg = drust::config::StorageConfig {
        endpoint: endpoint.to_string(),
        admin_endpoint: String::new(),
        access_key: "GKtest".into(),
        secret_key: "secret".into(),
        admin_token: String::new(),
        public_bucket: default_bucket.to_string(),
        max_upload_bytes: 1 << 20,
        disk_min_free_pct: 20,
        large_upload_max_bytes: 1 << 20,
        large_upload_chunk_max_bytes: 1 << 20,
        large_upload_max_sessions_per_tenant: 1,
        large_upload_session_ttl_secs: 60,
    };
    GarageClient::new(&cfg).unwrap()
}

#[tokio::test]
async fn probe_required_buckets_reports_missing_private() {
    let stub = s3_stub::start(&["public"], None).await;
    let c = s3_client(&stub.endpoint, "public");
    let res = c.probe_required_buckets("public").await;
    let keys: Vec<&str> = res.iter().map(|(b, _)| b.as_str()).collect();
    assert_eq!(keys, ["public", "private"]);
    let failed: Vec<(&str, String)> = res
        .iter()
        .filter_map(|(b, r)| r.as_ref().err().map(|e| (b.as_str(), format!("{e:#}"))))
        .collect();
    assert_eq!(
        failed.len(),
        1,
        "exactly the missing bucket must fail: {failed:?}"
    );
    assert_eq!(failed[0].0, "private");
    assert!(
        failed[0].1.contains("private"),
        "the error must name the bucket: {}",
        failed[0].1
    );
}

#[tokio::test]
async fn probe_required_buckets_ok_when_both_buckets_exist() {
    let stub = s3_stub::start(&["public", "private"], None).await;
    let c = s3_client(&stub.endpoint, "public");
    let res = c.probe_required_buckets("public").await;
    let keys: Vec<&str> = res.iter().map(|(b, _)| b.as_str()).collect();
    assert_eq!(keys, ["public", "private"]);
    for (b, r) in &res {
        assert!(r.is_ok(), "bucket {b} exists and is empty: {r:?}");
    }
}

#[tokio::test]
async fn probe_required_buckets_probes_a_distinct_configured_default() {
    let stub = s3_stub::start(&["public", "private", "legacy"], None).await;
    let c = s3_client(&stub.endpoint, "legacy");
    let res = c.probe_required_buckets("legacy").await;
    assert!(res.iter().all(|(_, r)| r.is_ok()), "{res:?}");
    let paths = stub.paths();
    for want in ["/public", "/private", "/legacy"] {
        assert!(
            paths.iter().any(|p| p == want),
            "{want} not probed: {paths:?}"
        );
    }
}

#[tokio::test]
async fn probe_required_buckets_runs_probes_concurrently() {
    // Each of public / private is answered only once BOTH lists have arrived.
    // Sequential probes would leave the first one waiting forever; the 5 s
    // timeout is a hang guard, not a timing threshold.
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let stub = s3_stub::start(&["public", "private"], Some(barrier)).await;
    let c = s3_client(&stub.endpoint, "public");
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        c.probe_required_buckets("public"),
    )
    .await
    .expect("the boot probe must list its buckets concurrently");
    assert!(res.iter().all(|(_, r)| r.is_ok()), "{res:?}");
}

#[tokio::test]
async fn ping_bucket_on_a_from_store_client_reads_the_bucket_prefix() {
    // The from_store test affordance (no S3 endpoint) folds the bucket into
    // the key; an empty "bucket" is healthy, like an empty real bucket.
    let store: std::sync::Arc<dyn object_store::ObjectStore> =
        std::sync::Arc::new(object_store::memory::InMemory::new());
    let c = GarageClient::from_store(store, "public");
    let res = c.probe_required_buckets("public").await;
    assert!(res.iter().all(|(_, r)| r.is_ok()), "{res:?}");
}
