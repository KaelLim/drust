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
    store: Arc<dyn ObjectStore>,
    bucket: String,
}

#[derive(Debug, Clone)]
pub struct ObjectSummary {
    pub key: String,
    pub size: u64,
    pub last_modified: chrono::DateTime<chrono::Utc>,
}

fn escape_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '\\' | '"' => format!("\\{}", c),
            c if c.is_control() => "_".to_string(),
            c => c.to_string(),
        })
        .collect()
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
        Ok(Self {
            store: Arc::new(store),
            bucket: cfg.public_bucket.clone(),
        })
    }

    /// Construct from an arbitrary backend (for tests or alternate impls).
    pub fn from_store(store: Arc<dyn ObjectStore>, bucket: &str) -> Self {
        Self {
            store,
            bucket: bucket.to_string(),
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
        let disposition = format!("inline; filename=\"{}\"", escape_filename(original_name));
        attrs.insert(
            Attribute::ContentDisposition,
            AttributeValue::from(disposition),
        );
        attrs.insert(
            Attribute::Metadata("original-name".into()),
            AttributeValue::from(original_name.to_string()),
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
    fn escape_filename_handles_quotes_and_backslashes() {
        assert_eq!(
            escape_filename("a\"b\\c.txt"),
            "a\\\"b\\\\c.txt"
        );
    }

    #[test]
    fn escape_filename_replaces_control_chars() {
        assert_eq!(escape_filename("a\nb.txt"), "a_b.txt");
    }
}
