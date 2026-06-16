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
use std::time::Duration;

/// HTTP status codes worth retrying — transient server/overload signals.
pub(crate) fn is_transient(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Exponential backoff: `base * 2^attempt` (0-based), capped at 30s. A zero
/// base disables sleeping (used by tests to avoid real-time waits).
pub(crate) fn backoff(attempt: u32, base: Duration) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let factor = 1u64 << attempt.min(6); // cap the shift so we never overflow
    let ms = (base.as_millis() as u64).saturating_mul(factor);
    Duration::from_millis(ms.min(30_000))
}

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

    fn keys_url(&self) -> String {
        format!("{}/.well-known/concord/keys.json", self.base)
    }

    /// Fetch the operator's published `keys.json` (issuer → ed25519 pubkey).
    /// Used to resolve the verifying key when `--pubkey` is omitted.
    pub async fn fetch_well_known_keys(&self) -> Result<Bytes, StoreError> {
        self.fetch(&self.keys_url()).await
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

    #[test]
    fn keys_url_is_well_known() {
        let s = CdnStore::new(TEST_BASE).unwrap();
        assert_eq!(
            s.keys_url(),
            format!("{TEST_BASE}/.well-known/concord/keys.json")
        );
    }

    #[tokio::test]
    async fn writes_error_out() {
        let s = CdnStore::new("https://example.com").unwrap();
        let h = ChunkHash::from_bytes([0; 32]);
        assert!(s.has_chunk(&h).await.is_err());
        assert!(s.put_chunk(&h, Bytes::new()).await.is_err());
        assert!(s.put_manifest("a", "b", Bytes::new()).await.is_err());
    }

    #[test]
    fn is_transient_truth_table() {
        for s in [408u16, 429, 500, 502, 503, 504] {
            assert!(is_transient(s), "{s} should be transient");
        }
        for s in [200u16, 204, 301, 400, 403, 404, 410] {
            assert!(!is_transient(s), "{s} should NOT be transient");
        }
    }

    #[test]
    fn backoff_is_monotonic_capped_and_zero_for_zero_base() {
        use std::time::Duration;
        assert_eq!(backoff(0, Duration::ZERO), Duration::ZERO);
        let base = Duration::from_millis(250);
        let b0 = backoff(0, base);
        let b1 = backoff(1, base);
        let b2 = backoff(2, base);
        assert_eq!(b0, Duration::from_millis(250));
        assert_eq!(b1, Duration::from_millis(500));
        assert_eq!(b2, Duration::from_millis(1000));
        assert!(b1 > b0 && b2 > b1, "backoff must grow");
        assert!(backoff(20, base) <= Duration::from_millis(30_000));
    }
}
