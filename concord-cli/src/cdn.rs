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

/// Retry/timeout policy for CDN fetches. Built from env with sane defaults.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base: Duration,
    pub http_timeout: Duration,
}

impl RetryPolicy {
    pub fn from_env() -> Self {
        Self {
            // CONCORD_MAX_RETRIES is the number of RETRIES (extra attempts after
            // the first); total attempts = retries + 1. Default 3 retries → 4 attempts.
            max_attempts: env_u64("CONCORD_MAX_RETRIES", 3).saturating_add(1) as u32,
            base: Duration::from_millis(env_u64("CONCORD_RETRY_BASE_MS", 250)),
            http_timeout: Duration::from_secs(env_u64("CONCORD_HTTP_TIMEOUT_SECS", 60).max(1)),
        }
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Outcome of one fetch attempt, classified for the retry loop.
pub(crate) enum Attempt {
    Ok(Bytes),
    NotFound,
    Transient(String),
    Permanent(String),
}

/// Drive `op` until it succeeds, hits a terminal outcome, or exhausts attempts.
/// Sleeps `backoff(attempt, base)` between transient failures.
pub(crate) async fn retry<F, Fut>(mut op: F, policy: &RetryPolicy) -> Result<Bytes, StoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Attempt>,
{
    let mut last = String::new();
    for attempt in 0..policy.max_attempts {
        match op().await {
            Attempt::Ok(b) => return Ok(b),
            Attempt::NotFound => return Err(StoreError::NotFound),
            Attempt::Permanent(m) => return Err(StoreError::Backend(m)),
            Attempt::Transient(m) => {
                last = m;
                if attempt + 1 < policy.max_attempts {
                    tokio::time::sleep(backoff(attempt, policy.base)).await;
                }
            }
        }
    }
    Err(StoreError::Backend(format!("exhausted retries: {last}")))
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

    fn no_sleep_policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            base: std::time::Duration::ZERO,
            http_timeout: std::time::Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn retry_succeeds_after_transient_failures() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let op = || {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n < 3 {
                    Attempt::Transient(format!("boom {n}"))
                } else {
                    Attempt::Ok(Bytes::from_static(b"ok"))
                }
            }
        };
        let out = retry(op, &no_sleep_policy(5)).await.unwrap();
        assert_eq!(out.as_ref(), b"ok");
        assert_eq!(calls.get(), 3, "two failures then success");
    }

    #[tokio::test]
    async fn retry_gives_up_after_max_attempts() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let op = || {
            calls.set(calls.get() + 1);
            async { Attempt::Transient("always".into()) }
        };
        let err = retry(op, &no_sleep_policy(3)).await.unwrap_err();
        assert!(matches!(err, StoreError::Backend(_)));
        assert_eq!(calls.get(), 3, "exactly max_attempts tries");
    }

    #[tokio::test]
    async fn retry_does_not_retry_not_found_or_permanent() {
        use std::cell::Cell;
        let nf_calls = Cell::new(0u32);
        let nf = || {
            nf_calls.set(nf_calls.get() + 1);
            async { Attempt::NotFound }
        };
        assert!(matches!(retry(nf, &no_sleep_policy(5)).await, Err(StoreError::NotFound)));
        assert_eq!(nf_calls.get(), 1, "NotFound is terminal — no retry");

        let p_calls = Cell::new(0u32);
        let p = || {
            p_calls.set(p_calls.get() + 1);
            async { Attempt::Permanent("403".into()) }
        };
        assert!(matches!(retry(p, &no_sleep_policy(5)).await, Err(StoreError::Backend(_))));
        assert_eq!(p_calls.get(), 1, "permanent is terminal — no retry");
    }
}
