//! HTTP CDN-backed read-only [`Store`].
//!
//! `concord pull` hits this rather than going to the operator API. The
//! Concord chunks + manifests are public (per [[access-visibility]] memory:
//! phase-0 all-public; phase-1 manifest-level privacy). Fetching them
//! direct from the CDN means:
//!
//! - **No auth on pulls.** Faster cold-cache fetch (no SigV4 round-trip).
//! - **CDN-cached.** Chunks are content-addressed and immutable; Bunny
//!   caches them forever and serves egress at ~$0.005/GB instead of from
//!   the operator's NVMe.
//!
//! URL layout matches the underlying S3 key scheme so chunks.eu can stay
//! as a CDN over raw S3 — no operator-API hop on the pull path:
//!
//! - chunk:    `{base}/{bucket}/chunks/<4hex>/<64hex>`
//! - manifest: `{base}/{bucket}/manifests/<name>/<version>.toml`
//!
//! Writes (put_chunk / put_manifest / has_chunk) error out — pull never
//! writes, and trying to PUT over a CDN is a programmer error worth
//! surfacing loudly.

use async_trait::async_trait;
use bytes::Bytes;
use concord_core::chunker::ChunkHash;
use concord_core::store::{Store, StoreError};

#[derive(Debug, Clone)]
pub struct CdnStore {
    /// e.g. `https://chunks.eu.concordfaces.org`. No trailing slash.
    base: String,
    /// e.g. `concord`.
    bucket: String,
    http: reqwest::Client,
}

impl CdnStore {
    pub fn new(base: impl Into<String>, bucket: impl Into<String>) -> Result<Self, StoreError> {
        let base: String = base.into();
        let bucket: String = bucket.into();
        if base.is_empty() || bucket.is_empty() {
            return Err(StoreError::Backend(
                "cdn base/bucket must be non-empty".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| StoreError::Backend(format!("build client: {e}")))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            bucket,
            http,
        })
    }

    fn chunk_url(&self, hash: &ChunkHash) -> String {
        let hex = hex::encode(hash.as_bytes());
        format!("{}/{}/chunks/{}/{}", self.base, self.bucket, &hex[..4], hex)
    }

    fn manifest_url(&self, name: &str, version: &str) -> String {
        format!(
            "{}/{}/manifests/{}/{}.toml",
            self.base, self.bucket, name, version
        )
    }

    async fn fetch(&self, url: &str) -> Result<Bytes, StoreError> {
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("http get {url}: {e}")))?;
        match resp.status() {
            s if s.is_success() => resp
                .bytes()
                .await
                .map_err(|e| StoreError::Backend(format!("read body {url}: {e}"))),
            reqwest::StatusCode::NOT_FOUND => Err(StoreError::NotFound),
            other => Err(StoreError::Backend(format!("HTTP {other} from {url}"))),
        }
    }
}

#[async_trait]
impl Store for CdnStore {
    async fn has_chunk(&self, _hash: &ChunkHash) -> Result<bool, StoreError> {
        Err(StoreError::Backend(
            "CdnStore is read-only: has_chunk not implemented".into(),
        ))
    }

    async fn put_chunk(&self, _hash: &ChunkHash, _body: Bytes) -> Result<(), StoreError> {
        Err(StoreError::Backend(
            "CdnStore is read-only: pushes must go through operator API, not CDN".into(),
        ))
    }

    async fn get_chunk(&self, hash: &ChunkHash) -> Result<Bytes, StoreError> {
        self.fetch(&self.chunk_url(hash)).await
    }

    async fn put_manifest(
        &self,
        _name: &str,
        _version: &str,
        _body: Bytes,
    ) -> Result<(), StoreError> {
        Err(StoreError::Backend(
            "CdnStore is read-only: pushes must go through operator API, not CDN".into(),
        ))
    }

    async fn get_manifest(&self, name: &str, version: &str) -> Result<Bytes, StoreError> {
        self.fetch(&self.manifest_url(name, version)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_url_layout() {
        let s = CdnStore::new("https://chunks.eu.concordfaces.org", "concord").unwrap();
        let h = ChunkHash::from_bytes([0xab; 32]);
        let url = s.chunk_url(&h);
        assert!(url.starts_with("https://chunks.eu.concordfaces.org/test-bucket/chunks/abab/"));
        assert!(url.ends_with(&"ab".repeat(32)));
    }

    #[test]
    fn manifest_url_layout() {
        let s = CdnStore::new("https://chunks.eu.concordfaces.org/", "concord").unwrap();
        let url = s.manifest_url("mistralai/Mixtral-8x22B", "v0.3.1");
        assert_eq!(
            url,
            "https://chunks.eu.concordfaces.org/test-bucket/manifests/mistralai/Mixtral-8x22B/v0.3.1.toml"
        );
    }

    #[test]
    fn rejects_empty_base() {
        assert!(CdnStore::new("", "concord").is_err());
        assert!(CdnStore::new("https://x", "").is_err());
    }

    #[tokio::test]
    async fn writes_error_out() {
        let s = CdnStore::new("https://example.com", "b").unwrap();
        let h = ChunkHash::from_bytes([0; 32]);
        assert!(s.has_chunk(&h).await.is_err());
        assert!(s.put_chunk(&h, Bytes::new()).await.is_err());
        assert!(s.put_manifest("a", "b", Bytes::new()).await.is_err());
    }
}
