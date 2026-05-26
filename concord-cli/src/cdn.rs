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
//! URL layout (deliberately bucket-less — the bucket lives only on the
//! CDN origin config, so a client can't probe arbitrary buckets through
//! the public CDN URL space):
//!
//! - chunk:    `{base}/chunks/<4hex>/<64hex>`
//! - manifest: `{base}/manifests/<name>/<version>.toml`
//!
//! The operator's CDN pull-zone is configured with an origin path that
//! includes the backing bucket prefix; that prefix is spliced
//! server-side so the client URL space stays flat per CDN endpoint and
//! never names a bucket. Phase-1 visibility-gated buckets can sit
//! behind separate CDN hostnames following the same pattern.
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
    /// The bucket is NOT part of the client-visible URL — operators wire
    /// it into the CDN origin path (e.g. Bunny PZ origin
    /// `https://s3.example.org/test-bucket`). Keeping bucket
    /// configuration off the client side closes a path-probe surface:
    /// a malicious client can't enumerate or poke at sibling buckets
    /// by passing a different bucket name.
    base: String,
    http: reqwest::Client,
}

impl CdnStore {
    pub fn new(base: impl Into<String>) -> Result<Self, StoreError> {
        let base: String = base.into();
        if base.is_empty() {
            return Err(StoreError::Backend("cdn base must be non-empty".into()));
        }
        let http = reqwest::Client::builder()
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| StoreError::Backend(format!("build client: {e}")))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http,
        })
    }

    fn chunk_url(&self, hash: &ChunkHash) -> String {
        let hex = hex::encode(hash.as_bytes());
        format!("{}/chunks/{}/{}", self.base, &hex[..4], hex)
    }

    fn manifest_url(&self, name: &str, version: &str) -> String {
        format!("{}/manifests/{}/{}.toml", self.base, name, version)
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

    // Test base URL is a placeholder. The structural invariant being
    // pinned is "URLs have no bucket segment whatsoever" — assert that
    // by checking the exact URL shape rather than blacklisting a
    // specific operator bucket name.
    const TEST_BASE: &str = "https://cdn.example.org";

    #[test]
    fn chunk_url_has_no_bucket_segment() {
        let s = CdnStore::new(TEST_BASE).unwrap();
        let h = ChunkHash::from_bytes([0xab; 32]);
        let url = s.chunk_url(&h);
        // Exact layout: {base}/chunks/<4hex>/<64hex>. Path has exactly
        // 3 segments after the host. A bucket would add a 4th.
        let after_host = url.strip_prefix(TEST_BASE).unwrap();
        let segments: Vec<&str> = after_host.split('/').filter(|s| !s.is_empty()).collect();
        assert_eq!(segments.len(), 3, "url has unexpected segments: {url}");
        assert_eq!(segments[0], "chunks");
        assert_eq!(segments[1], "abab");
        assert_eq!(segments[2], "ab".repeat(32));
    }

    #[test]
    fn manifest_url_has_no_bucket_segment() {
        let s = CdnStore::new(format!("{TEST_BASE}/")).unwrap();
        let url = s.manifest_url("org/name", "v0.3.1");
        assert_eq!(url, format!("{TEST_BASE}/manifests/org/name/v0.3.1.toml"));
    }

    #[test]
    fn rejects_empty_base() {
        assert!(CdnStore::new("").is_err());
    }

    #[tokio::test]
    async fn writes_error_out() {
        let s = CdnStore::new("https://example.com").unwrap();
        let h = ChunkHash::from_bytes([0; 32]);
        assert!(s.has_chunk(&h).await.is_err());
        assert!(s.put_chunk(&h, Bytes::new()).await.is_err());
        assert!(s.put_manifest("a", "b", Bytes::new()).await.is_err());
    }
}
