//! Garage S3 client. Thin wrapper over `object_store::aws::AmazonS3` for the
//! X+ scope (single public bucket managed through drust admin UI). Admin
//! endpoint fields on `StorageConfig` are read but not yet used — future Y
//! scope will call Garage Admin API through them.

use crate::config::StorageConfig;
use anyhow::{Context, Result};
use object_store::{ObjectStore, ObjectStoreExt};
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as StorePath;
use std::sync::Arc;

pub struct GarageClient {
    // S3 object store backend
    store: Arc<dyn ObjectStore>,
    // Admin API HTTP client — scaffolded in Task 5, used from Task 6 onwards.
    admin: reqwest::Client,
    admin_endpoint: String,
    admin_token: String,
    s3_endpoint: String,
    access_key_id: String,
    secret_access_key: String,
    region: String,
}

#[derive(Debug, Clone)]
pub struct BucketInfo {
    pub id: String,
    pub name: String,
    pub website_enabled: bool,
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
pub fn ascii_fallback_filename(name: &str) -> String {
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
    pub fn from_store(store: Arc<dyn ObjectStore>, _bucket: &str) -> Self {
        Self {
            store,
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
            admin: reqwest::Client::new(),
            admin_endpoint: base.to_string(),
            admin_token: token.to_string(),
            s3_endpoint: String::new(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            region: "garage".into(),
        }
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

    fn admin_url(&self, path: &str) -> String {
        format!("{}{}", self.admin_endpoint.trim_end_matches('/'), path)
    }

    pub async fn create_bucket(&self, name: &str) -> anyhow::Result<String> {
        let resp = self
            .admin
            .post(self.admin_url("/v1/bucket"))
            .bearer_auth(&self.admin_token)
            .json(&serde_json::json!({ "globalAlias": name }))
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("garage create_bucket({name}) -> {status}: {body}");
        }
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("create_bucket parse: {e} body={body}"))?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("create_bucket missing id in {body}"))?;
        Ok(id.to_string())
    }

    pub async fn delete_bucket(&self, bucket_id: &str) -> anyhow::Result<()> {
        let resp = self
            .admin
            .delete(self.admin_url("/v1/bucket"))
            .query(&[("id", bucket_id)])
            .bearer_auth(&self.admin_token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() && status.as_u16() != 404 {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("garage delete_bucket({bucket_id}) -> {status}: {body}");
        }
        Ok(())
    }

    pub async fn lookup_bucket(&self, name: &str) -> anyhow::Result<Option<BucketInfo>> {
        let resp = self
            .admin
            .get(self.admin_url("/v1/bucket"))
            .query(&[("globalAlias", name)])
            .bearer_auth(&self.admin_token)
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("garage lookup_bucket({name}) -> {status}: {body}");
        }
        let v: serde_json::Value = serde_json::from_str(&body)?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("lookup_bucket missing id"))?;
        Ok(Some(BucketInfo {
            id: id.to_string(),
            name: name.to_string(),
            website_enabled: false,
        }))
    }

    pub async fn set_website(&self, bucket_id: &str, enabled: bool) -> anyhow::Result<()> {
        // Garage v1 admin API: PUT /v1/bucket/{id} with a `websiteAccess`
        // subobject. (There is no `/v1/bucket/{id}/website` endpoint —
        // that 404s as "Unknown API endpoint".)
        let body = if enabled {
            serde_json::json!({
                "websiteAccess": {
                    "enabled": true,
                    "indexDocument": "index.html",
                    "errorDocument": "error.html"
                }
            })
        } else {
            serde_json::json!({
                "websiteAccess": { "enabled": false }
            })
        };
        let resp = self
            .admin
            .put(self.admin_url(&format!("/v1/bucket/{bucket_id}")))
            .bearer_auth(&self.admin_token)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("garage set_website({bucket_id}, {enabled}) -> {status}: {body}");
        }
        Ok(())
    }

    pub async fn bucket_allow(
        &self,
        bucket_id: &str,
        access_key_id: &str,
        read: bool,
        write: bool,
        owner: bool,
    ) -> anyhow::Result<()> {
        let resp = self
            .admin
            .post(self.admin_url("/v1/bucket/allow"))
            .bearer_auth(&self.admin_token)
            .json(&serde_json::json!({
                "bucketId": bucket_id,
                "accessKeyId": access_key_id,
                "permissions": { "read": read, "write": write, "owner": owner }
            }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("garage bucket_allow({bucket_id}, {access_key_id}) -> {status}: {body}");
        }
        Ok(())
    }

    pub async fn bucket_deny(&self, bucket_id: &str, access_key_id: &str) -> anyhow::Result<()> {
        let resp = self
            .admin
            .post(self.admin_url("/v1/bucket/deny"))
            .bearer_auth(&self.admin_token)
            .json(&serde_json::json!({
                "bucketId": bucket_id,
                "accessKeyId": access_key_id,
                "permissions": { "read": true, "write": true, "owner": true }
            }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("garage bucket_deny({bucket_id}, {access_key_id}) -> {status}: {body}");
        }
        Ok(())
    }

    /// Test-only: point the signing machinery at a given endpoint+creds.
    /// Production code uses `new()` which wires these from StorageConfig.
    pub fn configure_s3_signing(
        &mut self,
        endpoint: &str,
        access_key: &str,
        secret_key: &str,
        region: &str,
    ) {
        self.s3_endpoint = endpoint.to_string();
        self.access_key_id = access_key.to_string();
        self.secret_access_key = secret_key.to_string();
        self.region = region.to_string();
    }

    fn build_s3_for_bucket(&self, bucket: &str) -> anyhow::Result<object_store::aws::AmazonS3> {
        let s3 = object_store::aws::AmazonS3Builder::new()
            .with_endpoint(&self.s3_endpoint)
            .with_allow_http(true)
            .with_region(&self.region)
            .with_bucket_name(bucket)
            .with_access_key_id(&self.access_key_id)
            .with_secret_access_key(&self.secret_access_key)
            .with_virtual_hosted_style_request(false)
            .build()?;
        Ok(s3)
    }

    /// Produce a pre-signed S3 v4 GET URL.
    /// If `force_download_name` is Some, injects `response-content-disposition`
    /// with attachment + filename* so the browser downloads.
    pub async fn signed_get_url(
        &self,
        bucket: &str,
        key: &str,
        expires_in: std::time::Duration,
        force_download_name: Option<&str>,
    ) -> anyhow::Result<String> {
        use object_store::signer::Signer;
        let s3 = self.build_s3_for_bucket(bucket)?;
        let method = reqwest::Method::GET;
        let path = StorePath::from(key);
        let mut url = s3.signed_url(method, &path, expires_in).await?;
        if let Some(name) = force_download_name {
            let ascii = ascii_fallback_filename(name);
            let pct = urlencoding::encode(name);
            let disp = format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{pct}");
            let disp_enc = urlencoding::encode(&disp);
            let existing = url.query().unwrap_or("").to_owned();
            let sep = if existing.is_empty() { "" } else { "&" };
            url.set_query(Some(&format!(
                "{existing}{sep}response-content-disposition={disp_enc}",
            )));
        }
        Ok(url.into())
    }

    /// Cross-bucket PUT.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_object_in(
        &self,
        bucket: &str,
        key: &str,
        body: bytes::Bytes,
        content_type: Option<&str>,
        disposition_mode: &str,
        original_name: &str,
        cache_control: Option<&str>,
        meta_json: Option<&str>,
    ) -> anyhow::Result<()> {
        use object_store::{Attribute, AttributeValue, Attributes, ObjectStore, ObjectStoreExt, PutOptions};
        let s3 = self.build_s3_for_bucket(bucket)?;
        let path = StorePath::from(key);

        let ascii = ascii_fallback_filename(original_name);
        let pct = urlencoding::encode(original_name);
        let cd = format!("{disposition_mode}; filename=\"{ascii}\"; filename*=UTF-8''{pct}");

        let mut attrs = Attributes::new();
        if let Some(ct) = content_type {
            attrs.insert(Attribute::ContentType, AttributeValue::from(ct.to_string()));
        }
        attrs.insert(Attribute::ContentDisposition, AttributeValue::from(cd));
        if let Some(cc) = cache_control {
            attrs.insert(
                Attribute::CacheControl,
                AttributeValue::from(cc.to_string()),
            );
        }
        attrs.insert(
            Attribute::Metadata("original-name".into()),
            AttributeValue::from(urlencoding::encode(original_name).into_owned()),
        );
        attrs.insert(
            Attribute::Metadata("uploaded-at".into()),
            AttributeValue::from(chrono::Utc::now().to_rfc3339()),
        );
        if let Some(json) = meta_json {
            let v: serde_json::Value = serde_json::from_str(json)
                .map_err(|e| anyhow::anyhow!("meta_json not valid JSON: {e}"))?;
            if let Some(map) = v.as_object() {
                for (k, val) in map {
                    if !k
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    {
                        anyhow::bail!("meta key must be ASCII alnum/-/_: {k}");
                    }
                    let s = val.as_str().unwrap_or(&val.to_string()).to_string();
                    attrs.insert(
                        Attribute::Metadata(k.clone().into()),
                        AttributeValue::from(urlencoding::encode(&s).into_owned()),
                    );
                }
            }
        }

        let opts = PutOptions {
            attributes: attrs,
            ..Default::default()
        };
        s3.put_opts(&path, body.into(), opts).await?;
        Ok(())
    }

    /// Cross-bucket DELETE. Idempotent: missing key is `Ok`.
    pub async fn delete_object_in(&self, bucket: &str, key: &str) -> anyhow::Result<()> {
        use object_store::{ObjectStore, ObjectStoreExt};
        let s3 = self.build_s3_for_bucket(bucket)?;
        let path = StorePath::from(key);
        match s3.delete(&path).await {
            Ok(()) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Cross-bucket GET — returns all bytes.
    pub async fn get_object_bytes_in(
        &self,
        bucket: &str,
        key: &str,
    ) -> anyhow::Result<bytes::Bytes> {
        use object_store::{ObjectStore, ObjectStoreExt};
        let s3 = self.build_s3_for_bucket(bucket)?;
        let path = StorePath::from(key);
        let result = s3.get(&path).await?;
        Ok(result.bytes().await?)
    }

    /// Cross-bucket GET — streams chunks for proxying to response bodies.
    pub async fn get_object_stream_in(
        &self,
        bucket: &str,
        key: &str,
    ) -> anyhow::Result<impl futures::Stream<Item = anyhow::Result<bytes::Bytes>> + use<>> {
        use object_store::{ObjectStore, ObjectStoreExt};
        let s3 = self.build_s3_for_bucket(bucket)?;
        let path = StorePath::from(key);
        let result = s3.get(&path).await?;
        Ok(futures::StreamExt::map(result.into_stream(), |r| {
            r.map_err(anyhow::Error::from)
        }))
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
