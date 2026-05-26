//! Storage trait for Concord chunk + manifest objects.
//!
//! [`Store`] is the abstraction concord-cli `push` / `pull` / `verify`
//! talk to. A real implementation hits an OpenVerve S3 gateway via HTTP
//! + SigV4; the [`MemoryStore`] in this module is for tests and local
//!   development.
//!
//! Layering reminder: the Concord chunker (4 MiB fixed blake3,
//! content-addressed) is the *protocol* layer. Whatever the operator's
//! S3 backend does internally — OpenVerve's EC 4+2 split across nodes,
//! AWS's chunked multipart, etc. — is orthogonal. We PUT/GET full
//! Concord chunks as opaque S3 objects; the backend's internal chunking
//! does not leak into this trait.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

use crate::chunker::ChunkHash;

/// Errors that any [`Store`] implementation can surface.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("backend error: {0}")]
    Backend(String),
}

/// Concord's storage contract. Chunks are addressed by `blake3` hash;
/// manifests by `(name, version)` pair. All operations are async + take
/// owned `Bytes` for zero-copy when the implementation supports it.
#[async_trait]
pub trait Store: Send + Sync {
    /// Has this chunk already been uploaded? Used by `push` to skip
    /// redundant uploads — the entire dedup mechanism rides on this.
    async fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, StoreError>;

    /// Upload a chunk. Idempotent — if the chunk is already present
    /// (same hash, same bytes), the implementation should treat the
    /// upload as a no-op.
    async fn put_chunk(&self, hash: &ChunkHash, body: Bytes) -> Result<(), StoreError>;

    /// Fetch a chunk by hash.
    async fn get_chunk(&self, hash: &ChunkHash) -> Result<Bytes, StoreError>;

    /// Upload (or replace) a signed manifest at `manifests/<name>/<version>.toml`.
    async fn put_manifest(&self, name: &str, version: &str, body: Bytes) -> Result<(), StoreError>;

    /// Fetch a signed manifest.
    async fn get_manifest(&self, name: &str, version: &str) -> Result<Bytes, StoreError>;
}

// ----- in-memory implementation for tests + local development -----

/// HashMap-backed [`Store`] for tests, local development, and the
/// concord-cli unit tests. Not thread-fast (single Mutex around both
/// maps) — only suitable when correctness > throughput.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<MemoryInner>,
}

#[derive(Debug, Default)]
struct MemoryInner {
    chunks: HashMap<ChunkHash, Bytes>,
    manifests: HashMap<(String, String), Bytes>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test helper: number of chunks currently stored.
    pub fn chunk_count(&self) -> usize {
        self.inner.lock().unwrap().chunks.len()
    }

    /// Test helper: number of manifests currently stored.
    pub fn manifest_count(&self) -> usize {
        self.inner.lock().unwrap().manifests.len()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, StoreError> {
        Ok(self.inner.lock().unwrap().chunks.contains_key(hash))
    }

    async fn put_chunk(&self, hash: &ChunkHash, body: Bytes) -> Result<(), StoreError> {
        // Idempotent: if the key already exists, do nothing — content
        // addressing guarantees the bytes match if the hash matches.
        let mut g = self.inner.lock().unwrap();
        g.chunks.entry(*hash).or_insert(body);
        Ok(())
    }

    async fn get_chunk(&self, hash: &ChunkHash) -> Result<Bytes, StoreError> {
        self.inner
            .lock()
            .unwrap()
            .chunks
            .get(hash)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn put_manifest(&self, name: &str, version: &str, body: Bytes) -> Result<(), StoreError> {
        self.inner
            .lock()
            .unwrap()
            .manifests
            .insert((name.to_string(), version.to_string()), body);
        Ok(())
    }

    async fn get_manifest(&self, name: &str, version: &str) -> Result<Bytes, StoreError> {
        self.inner
            .lock()
            .unwrap()
            .manifests
            .get(&(name.to_string(), version.to_string()))
            .cloned()
            .ok_or(StoreError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> ChunkHash {
        ChunkHash::of(&[seed])
    }

    #[tokio::test]
    async fn put_get_chunk_roundtrip() {
        let s = MemoryStore::new();
        let hash = h(1);
        let body = Bytes::from_static(b"hello");
        assert!(!s.has_chunk(&hash).await.unwrap());
        s.put_chunk(&hash, body.clone()).await.unwrap();
        assert!(s.has_chunk(&hash).await.unwrap());
        assert_eq!(s.get_chunk(&hash).await.unwrap(), body);
        assert_eq!(s.chunk_count(), 1);
    }

    #[tokio::test]
    async fn put_chunk_is_idempotent() {
        // Pushing the same chunk twice must not double-store. This is
        // the protocol's dedup guarantee.
        let s = MemoryStore::new();
        let hash = h(2);
        let body = Bytes::from_static(b"dedupe me");
        s.put_chunk(&hash, body.clone()).await.unwrap();
        s.put_chunk(&hash, body.clone()).await.unwrap();
        s.put_chunk(&hash, body).await.unwrap();
        assert_eq!(s.chunk_count(), 1);
    }

    #[tokio::test]
    async fn get_chunk_missing_is_not_found() {
        let s = MemoryStore::new();
        let missing = h(99);
        assert!(matches!(
            s.get_chunk(&missing).await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn put_get_manifest_roundtrip() {
        let s = MemoryStore::new();
        let body = Bytes::from_static(b"[manifest]\nname=\"x/y\"\n");
        s.put_manifest("x/y", "v1.0.0", body.clone()).await.unwrap();
        assert_eq!(s.get_manifest("x/y", "v1.0.0").await.unwrap(), body);
        assert_eq!(s.manifest_count(), 1);
    }

    #[tokio::test]
    async fn put_manifest_overwrites() {
        // Same (name, version) gets the new bytes — useful when re-signing
        // a manifest with a rotated key. Whether to even allow this is a
        // policy question for the operator; the trait permits it.
        let s = MemoryStore::new();
        let v1 = Bytes::from_static(b"first");
        let v2 = Bytes::from_static(b"second");
        s.put_manifest("x/y", "v1.0.0", v1).await.unwrap();
        s.put_manifest("x/y", "v1.0.0", v2.clone()).await.unwrap();
        assert_eq!(s.get_manifest("x/y", "v1.0.0").await.unwrap(), v2);
        assert_eq!(s.manifest_count(), 1);
    }

    #[tokio::test]
    async fn get_manifest_missing_is_not_found() {
        let s = MemoryStore::new();
        assert!(matches!(
            s.get_manifest("x/y", "v0").await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn different_versions_coexist() {
        let s = MemoryStore::new();
        s.put_manifest("m", "v1", Bytes::from_static(b"a"))
            .await
            .unwrap();
        s.put_manifest("m", "v2", Bytes::from_static(b"b"))
            .await
            .unwrap();
        assert_eq!(s.get_manifest("m", "v1").await.unwrap().as_ref(), b"a");
        assert_eq!(s.get_manifest("m", "v2").await.unwrap().as_ref(), b"b");
        assert_eq!(s.manifest_count(), 2);
    }
}
