//! Garage S3 client. Thin wrapper over `object_store::aws::AmazonS3` for the
//! X+ scope (single public bucket managed through drust admin UI). Admin
//! endpoint fields on `StorageConfig` are read but not yet used — future Y
//! scope will call Garage Admin API through them.

use crate::config::StorageConfig;
use anyhow::{Context, Result};
use object_store::ObjectStore;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as StorePath;
use std::sync::Arc;

pub struct GarageClient {
    // S3 object store backend
    store: Arc<dyn ObjectStore>,
    bucket: String,
    // Admin API HTTP client — scaffolded in Task 5, used from Task 6 onwards.
    #[allow(dead_code)]
    admin: reqwest::Client,
    #[allow(dead_code)]
    admin_endpoint: String,
    #[allow(dead_code)]
    admin_token: String,
    #[allow(dead_code)]
    s3_endpoint: String,
    #[allow(dead_code)]
    access_key_id: String,
    #[allow(dead_code)]
    secret_access_key: String,
    #[allow(dead_code)]
    region: String,
}

#[derive(Debug, Clone)]
pub struct ObjectSummary {
    pub key: String,
    pub size: u64,
    pub last_modified: chrono::DateTime<chrono::Utc>,
}

/// ASCII-safe fallback for the plain `filename="..."` token in
/// `Content-Disposition`. Non-ASCII characters are replaced with `_` so
/// the resulting string is guaranteed to fit in an HTTP header; the
/// real original name is preserved in `filename*=UTF-8''...` and in
/// `x-amz-meta-original-name` (both percent-encoded).
fn ascii_fallback_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '\\' | '"' => '_',
            c if c.is_ascii() && !c.is_control() => c,
            _ => '_',
        })
        .collect()
}

/// Build `Content-Disposition: inline; filename="<ascii>"; filename*=UTF-8''<utf8>`.
/// Per RFC 6266 §4.3 the `filename*=UTF-8''...` token is preferred by
/// modern clients; the plain `filename=` is kept for legacy readers.
fn content_disposition(original_name: &str) -> String {
    let ascii = ascii_fallback_filename(original_name);
    let encoded = urlencoding::encode(original_name);
    format!("inline; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

impl GarageClient {
    pub fn new(cfg: &StorageConfig) -> Result<Self> {
        let store = AmazonS3Builder::new()
            .with_endpoint(&cfg.endpoint)
            .with_region("garage")
            .with_access_key_id(&cfg.access_key)
            .with_secret_access_key(&cfg.secret_key)
            .with_bucket_name(&cfg.public_bucket)
            .with_allow_http(true)
            .with_virtual_hosted_style_request(false)
            .build()
            .context("failed to build S3 client for Garage")?;
        let admin = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("failed to build admin HTTP client")?;
        Ok(Self {
            store: Arc::new(store),
            bucket: cfg.public_bucket.clone(),
            admin,
            admin_endpoint: cfg.admin_endpoint.clone(),
            admin_token: cfg.admin_token.clone(),
            s3_endpoint: cfg.endpoint.clone(),
            access_key_id: cfg.access_key.clone(),
            secret_access_key: cfg.secret_key.clone(),
            region: "garage".into(),
        })
    }

    /// Construct from an arbitrary backend (for tests or alternate impls).
    /// Admin fields are intentionally empty — only object-store methods work.
    pub fn from_store(store: Arc<dyn ObjectStore>, bucket: &str) -> Self {
        Self {
            store,
            bucket: bucket.to_string(),
            admin: reqwest::Client::new(),
            admin_endpoint: String::new(),
            admin_token: String::new(),
            s3_endpoint: String::new(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            region: "garage".into(),
        }
    }

    /// Construct pointing at a mock admin server (for integration tests).
    /// Uses in-memory object store; only admin API methods work end-to-end.
    pub fn from_mock_admin(base: &str, token: &str) -> Self {
        use object_store::memory::InMemory;
        Self {
            store: Arc::new(InMemory::new()),
            bucket: "mock".into(),
            admin: reqwest::Client::new(),
            admin_endpoint: base.to_string(),
            admin_token: token.to_string(),
            s3_endpoint: String::new(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            region: "garage".into(),
        }
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Health check. Lists at most one object; an empty bucket is a valid
    /// healthy state.
    pub async fn ping(&self) -> Result<()> {
        use futures::StreamExt;
        let mut stream = self.store.list(None);
        match stream.next().await {
            Some(Ok(_)) | None => Ok(()),
            Some(Err(e)) => Err(e).context("garage ping list failed"),
        }
    }

    /// Upload with metadata. `original_name` is attached both as the
    /// `x-amz-meta-original-name` header and inside a `Content-Disposition:
    /// inline; filename="..."` header so anonymous downloads present the
    /// original filename.
    pub async fn put_object(
        &self,
        key: &str,
        body: bytes::Bytes,
        content_type: Option<&str>,
        original_name: &str,
    ) -> Result<()> {
        use object_store::{Attribute, AttributeValue, Attributes, PutOptions, PutPayload};

        let mut attrs = Attributes::new();
        if let Some(ct) = content_type {
            attrs.insert(Attribute::ContentType, AttributeValue::from(ct.to_string()));
        }
        attrs.insert(
            Attribute::ContentDisposition,
            AttributeValue::from(content_disposition(original_name)),
        );
        // S3 user-metadata header values must be US-ASCII. Percent-encode
        // so non-ASCII filenames round-trip losslessly — readers can
        // `urldecode` on retrieval.
        attrs.insert(
            Attribute::Metadata("original-name".into()),
            AttributeValue::from(urlencoding::encode(original_name).into_owned()),
        );
        attrs.insert(
            Attribute::Metadata("uploaded-at".into()),
            AttributeValue::from(chrono::Utc::now().to_rfc3339()),
        );

        let opts = PutOptions {
            attributes: attrs,
            ..Default::default()
        };
        let path = StorePath::from(key);
        self.store
            .put_opts(&path, PutPayload::from_bytes(body), opts)
            .await
            .context("garage put_object failed")?;
        Ok(())
    }

    /// Idempotent: deleting a missing key is `Ok`.
    pub async fn delete_object(&self, key: &str) -> Result<()> {
        let path = StorePath::from(key);
        match self.store.delete(&path).await {
            Ok(()) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(e).context("garage delete_object failed"),
        }
    }

    /// List every object in the bucket. Intended for reconciliation (admin
    /// action, low frequency).
    pub async fn list_objects(&self) -> Result<Vec<ObjectSummary>> {
        use futures::StreamExt;
        let mut out = Vec::new();
        let mut stream = self.store.list(None);
        while let Some(item) = stream.next().await {
            let meta = item.context("garage list entry failed")?;
            out.push(ObjectSummary {
                key: meta.location.to_string(),
                size: meta.size as u64,
                last_modified: meta.last_modified,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    fn client() -> (Arc<dyn ObjectStore>, GarageClient) {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let client = GarageClient::from_store(store.clone(), "public");
        (store, client)
    }

    #[tokio::test]
    async fn ping_succeeds_on_empty_memory_backend() {
        let (_store, client) = client();
        client.ping().await.unwrap();
    }

    #[tokio::test]
    async fn put_object_stores_bytes() {
        let (store, client) = client();
        let body = bytes::Bytes::from_static(b"hello world");
        client
            .put_object("abc123.txt", body.clone(), Some("text/plain"), "hello.txt")
            .await
            .unwrap();

        let path = StorePath::from("abc123.txt");
        let got = store.get(&path).await.unwrap();
        let fetched = got.bytes().await.unwrap();
        assert_eq!(&fetched[..], &body[..]);
    }

    #[tokio::test]
    async fn delete_object_is_idempotent() {
        let (store, client) = client();
        client
            .put_object("k1.txt", bytes::Bytes::from_static(b"x"), None, "k1.txt")
            .await
            .unwrap();

        client.delete_object("k1.txt").await.unwrap();
        let err = store.head(&StorePath::from("k1.txt")).await.err().unwrap();
        assert!(matches!(err, object_store::Error::NotFound { .. }));

        // Second delete of missing key still Ok.
        client.delete_object("k1.txt").await.unwrap();
    }

    #[tokio::test]
    async fn list_objects_returns_all_with_sizes() {
        let (_store, client) = client();
        client
            .put_object("a.txt", bytes::Bytes::from_static(b"hello"), None, "a.txt")
            .await
            .unwrap();
        client
            .put_object("b.bin", bytes::Bytes::from_static(b"world!"), None, "b.bin")
            .await
            .unwrap();

        let mut items = client.list_objects().await.unwrap();
        items.sort_by(|x, y| x.key.cmp(&y.key));
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].key, "a.txt");
        assert_eq!(items[0].size, 5);
        assert_eq!(items[1].key, "b.bin");
        assert_eq!(items[1].size, 6);
    }

    #[test]
    fn ascii_fallback_replaces_non_ascii() {
        assert_eq!(ascii_fallback_filename("發票.pdf"), "__.pdf");
        assert_eq!(ascii_fallback_filename("a\"b.txt"), "a_b.txt");
        assert_eq!(ascii_fallback_filename("a\nb.txt"), "a_b.txt");
        assert_eq!(ascii_fallback_filename("normal.pdf"), "normal.pdf");
    }

    #[test]
    fn content_disposition_includes_utf8_star() {
        let cd = content_disposition("發票2026.pdf");
        assert!(cd.starts_with("inline; filename=\"__2026.pdf\""));
        assert!(cd.contains("filename*=UTF-8''"));
        assert!(cd.contains("%E7%99%BC%E7%A5%A8")); // 發票 encoded
    }

    #[test]
    fn content_disposition_ascii_only_is_still_valid() {
        let cd = content_disposition("hello.txt");
        assert!(cd.contains("filename=\"hello.txt\""));
        assert!(cd.contains("filename*=UTF-8''hello.txt"));
    }

    #[tokio::test]
    async fn put_object_with_non_ascii_filename_succeeds() {
        let (store, client) = client();
        client
            .put_object(
                "abc.pdf",
                bytes::Bytes::from_static(b"%PDF-1.4"),
                Some("application/pdf"),
                "發票2026.pdf",
            )
            .await
            .unwrap();
        let path = StorePath::from("abc.pdf");
        let got = store.get(&path).await.unwrap();
        assert_eq!(got.bytes().await.unwrap().as_ref(), b"%PDF-1.4");
    }
}
