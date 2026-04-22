use drust::storage::garage::GarageClient;
use std::time::Duration;

fn mem_client() -> GarageClient {
    use object_store::memory::InMemory;
    use std::sync::Arc;
    let store: Arc<dyn object_store::ObjectStore> = Arc::new(InMemory::new());
    let mut c = GarageClient::from_store(store, "unused");
    c.configure_s3_signing("http://127.0.0.1:47830", "GKkey", "secret", "garage");
    c
}

#[tokio::test]
async fn signed_get_url_contains_signature_and_expiry() {
    let c = mem_client();
    let url = c
        .signed_get_url("public", "some-uuid", Duration::from_secs(3600), None)
        .await
        .unwrap();
    assert!(url.contains("public/some-uuid"), "path embedded: {url}");
    assert!(
        url.contains("X-Amz-Signature="),
        "signature embedded: {url}"
    );
    assert!(url.contains("X-Amz-Expires=3600"), "ttl embedded: {url}");
}

#[tokio::test]
async fn signed_get_url_with_download_name_adds_response_override() {
    let c = mem_client();
    let url = c
        .signed_get_url(
            "public",
            "some-uuid",
            Duration::from_secs(60),
            Some("發票.pdf"),
        )
        .await
        .unwrap();
    assert!(
        url.contains("response-content-disposition"),
        "dl override: {url}"
    );
    assert!(url.to_lowercase().contains("attachment"));
}

#[tokio::test]
#[ignore = "requires a Garage instance with 'alt-bucket' bucket; smoke test in task 27"]
async fn put_object_in_other_bucket_reaches_that_bucket() {
    let c = mem_client();
    c.put_object_in(
        "alt-bucket",
        "k1",
        bytes::Bytes::from_static(b"hello"),
        Some("text/plain"),
        "inline",
        "k1.txt",
        None,
        None,
    )
    .await
    .unwrap();
    let got = c.get_object_bytes_in("alt-bucket", "k1").await.unwrap();
    assert_eq!(&got[..], b"hello");
}
