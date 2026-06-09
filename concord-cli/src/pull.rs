//! Implementation of `concord pull <ref>`.
//!
//! Fetches the manifest from the store, verifies its signature against
//! the supplied public key, then walks each `[[shard]]` table — fetching
//! its chunks, verifying the shard merkle as it reassembles, and writing
//! the file out to `--out`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use concord_core::chunker::ChunkHash;
use concord_core::manifest::{Manifest, Shard};
use concord_core::shard::shard_merkle;
use concord_core::sign;
use concord_core::store::Store;
use ed25519_dalek::VerifyingKey;

/// Required arguments for [`pull`].
#[derive(Clone, Debug)]
pub struct PullArgs {
    pub name: String,
    pub version: String,
    pub out_dir: PathBuf,
}

/// Version channel a bare `<name>` resolves to. NOT a fixed version — `latest`
/// is a moving pointer object (`manifests/<name>/latest.toml`) that the
/// publisher rewrites to the newest manifest on every push. A bare
/// `concord pull <name>` therefore always tracks the current release, while
/// `<name>:<version>` pins an explicit one. The pointer is a public object on
/// the same bucket/CDN as every other manifest, so resolution needs no API.
pub const DEFAULT_VERSION: &str = "latest";

/// Parsed model reference: `<name>[:<version>]`. A bare `<name>` resolves to
/// the moving [`DEFAULT_VERSION`] pointer; an explicit `<name>:<version>` pins
/// the channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRef {
    pub name: String,
    pub version: String,
}

impl ModelRef {
    /// Parse `name[:version]`. Splits on the last `:` so `org/name:v1` works.
    /// A bare `name` (no colon) resolves to [`DEFAULT_VERSION`]. A colon with
    /// an empty side (`name:` or `:v1`) is malformed and rejected.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        match s.rsplit_once(':') {
            // Explicit, fully-specified ref.
            Some((name, version)) if !name.is_empty() && !version.is_empty() => Ok(Self {
                name: name.to_string(),
                version: version.to_string(),
            }),
            // A colon was typed but one side is empty — malformed, not a default.
            Some(_) => bail!(
                "malformed ref `{s}` — use `<name>` or `<name>:<version>` (e.g. `org/model` or `org/model:v1`)"
            ),
            // Bare name → default version channel.
            None if !s.is_empty() => Ok(Self {
                name: s.to_string(),
                version: DEFAULT_VERSION.to_string(),
            }),
            None => bail!("empty model ref"),
        }
    }
}

/// Per-file accounting reported back to the caller for the human summary.
#[derive(Clone, Debug, Default)]
pub struct PullStats {
    pub files: u64,
    /// Total logical bytes reassembled (sum of shard sizes).
    pub bytes: u64,
    /// Bytes actually fetched over the network (chunk cache misses). The
    /// difference from `bytes` is what dedup/local-cache saved.
    pub on_wire: u64,
    /// `license.residency` from the manifest (e.g. `eu`).
    pub residency: String,
}

impl PullStats {
    /// Fraction of logical bytes served from cache instead of the wire.
    pub fn dedup_pct(&self) -> f64 {
        if self.bytes == 0 {
            0.0
        } else {
            100.0 * (1.0 - (self.on_wire as f64 / self.bytes as f64))
        }
    }
}

/// Progress events emitted during a pull so the CLI can render bars/speed.
#[derive(Clone, Debug)]
pub enum PullEvent {
    /// Manifest fetched + signature verified.
    Manifest {
        issuer: String,
        license: String,
        residency: String,
        shards: usize,
    },
    /// Starting a shard (one output file).
    ShardStart {
        idx: usize,
        total: usize,
        role: String,
        format: String,
        size: u64,
        parts: usize,
    },
    /// A chunk finished — `cache_hit` = served from the local chunk cache
    /// (no wire bytes). `idx` is the 1-based shard number so a parallel
    /// renderer can route the tick to the right bar.
    ChunkDone {
        idx: usize,
        bytes: u64,
        cache_hit: bool,
    },
    /// A shard finished, written to `filename`.
    ShardDone { idx: usize, filename: String },
}

/// Sink for [`PullEvent`]s. The CLI hooks indicatif here.
pub type PullProgress = std::sync::Arc<dyn Fn(PullEvent) + Send + Sync>;

/// Pull + verify + reassemble, no progress reporting (back-compat).
pub async fn pull<S: Store + ?Sized>(
    store: &S,
    args: &PullArgs,
    pubkey: &VerifyingKey,
) -> Result<(Manifest, PullStats)> {
    pull_with_progress(store, args, pubkey, None).await
}

/// Pull a manifest from `store`, verify its signature with `pubkey`, then
/// reassemble each shard into `args.out_dir`, emitting [`PullEvent`]s.
///
/// Chunks are cached locally (`$XDG_CACHE_HOME/concord/chunks` or
/// `~/.cache/concord/chunks`), so a chunk already present — from a prior pull
/// or shared between shards — is served from disk (a cache-hit, zero wire
/// bytes). That's the dedup the summary reports.
pub async fn pull_with_progress<S: Store + ?Sized>(
    store: &S,
    args: &PullArgs,
    pubkey: &VerifyingKey,
    progress: Option<PullProgress>,
) -> Result<(Manifest, PullStats)> {
    let raw = store
        .get_manifest(&args.name, &args.version)
        .await
        .map_err(|e| anyhow!("get manifest {}:{}: {e}", args.name, args.version))?;
    let manifest = Manifest::parse(&raw).context("parse manifest")?;
    sign::verify(&manifest, pubkey).map_err(|e| anyhow!("verify signature: {e}"))?;

    let emit = |e: PullEvent| {
        if let Some(p) = &progress {
            p(e);
        }
    };
    emit(PullEvent::Manifest {
        issuer: manifest.manifest.issuer.clone(),
        license: manifest.license.spdx.clone(),
        residency: manifest.license.residency.clone(),
        shards: manifest.shards.len(),
    });

    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("mkdir -p {}", args.out_dir.display()))?;
    let cache_dir = chunk_cache_dir();

    let concurrency = download_concurrency();
    let (files, bytes, on_wire) = download_shards(
        store,
        &manifest.shards,
        &args.out_dir,
        cache_dir.as_deref(),
        concurrency,
        &emit,
    )
    .await?;

    let stats = PullStats {
        files,
        bytes,
        on_wire,
        residency: manifest.license.residency.clone(),
    };
    Ok((manifest, stats))
}

/// Shard-level download concurrency. Each shard is one output file; fetching
/// several at once is the bulk of the HuggingFace-style speedup. Override with
/// `CONCORD_DOWNLOAD_CONCURRENCY`; defaults to 4.
fn download_concurrency() -> usize {
    std::env::var("CONCORD_DOWNLOAD_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(4)
}

/// Reassemble every shard, up to `concurrency` in flight at once, into
/// `out_dir`. Each shard is independent (own file, own chunk list), so they
/// parallelize cleanly; chunk order *within* a shard is still sequential to
/// keep reassembly correct. Returns `(files, total_bytes, on_wire_bytes)`.
///
/// A single shard failure aborts the whole pull (the model is incomplete
/// without it) — `try_for_each`-style: the first error returned wins.
async fn download_shards<S: Store + ?Sized>(
    store: &S,
    shards: &[Shard],
    out_dir: &Path,
    cache_dir: Option<&Path>,
    concurrency: usize,
    emit: &(impl Fn(PullEvent) + Sync),
) -> Result<(u64, u64, u64)> {
    use futures::stream::{self, StreamExt, TryStreamExt};

    let total = shards.len();
    let (files, bytes, on_wire) = stream::iter(shards.iter().enumerate())
        .map(|(i, shard)| async move {
            let idx = i + 1;
            emit(PullEvent::ShardStart {
                idx,
                total,
                role: shard.role.clone(),
                format: shard.format.clone(),
                size: shard.size,
                parts: shard.parts.unwrap_or(1) as usize,
            });
            let (written, wire) = pull_shard(store, shard, out_dir, cache_dir, idx, emit).await?;
            emit(PullEvent::ShardDone {
                idx,
                filename: shard_filename(shard),
            });
            Ok::<(u64, u64), anyhow::Error>((written, wire))
        })
        .buffer_unordered(concurrency.max(1))
        .try_fold(
            (0u64, 0u64, 0u64),
            |(f, b, w), (written, wire)| async move { Ok((f + 1, b + written, w + wire)) },
        )
        .await?;

    Ok((files, bytes, on_wire))
}

/// Local chunk cache dir (`$XDG_CACHE_HOME/concord/chunks` or
/// `~/.cache/concord/chunks`). `None` if neither env var is set (cache disabled).
fn chunk_cache_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    let dir = base.join("concord").join("chunks");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Fetch all chunks for `shard`, verify the merkle root matches the
/// manifest's claim, and write the reassembled bytes to disk.
///
/// Returns `(bytes_written, bytes_on_wire)`. Chunks present in `cache_dir`
/// are read from disk (no wire bytes); misses are fetched, verified, and
/// written to the cache for next time. Emits one [`PullEvent::ChunkDone`]
/// per chunk so the caller can drive a progress bar.
async fn pull_shard<S: Store + ?Sized>(
    store: &S,
    shard: &Shard,
    out_dir: &Path,
    cache_dir: Option<&Path>,
    idx: usize,
    emit: &(impl Fn(PullEvent) + Sync),
) -> Result<(u64, u64)> {
    // Resolve the ordered chunk-hash list for this shard.
    //   - Multi-chunk (and new single-chunk) shards carry `chunks` in the
    //     manifest (RFC 0001 §Shards).
    //   - Legacy single-chunk shards omit it; then the merkle root IS the
    //     one chunk's hash.
    let chunk_hashes: Vec<ChunkHash> = if !shard.chunks.is_empty() {
        shard
            .chunks
            .iter()
            .map(|h| {
                h.parse::<ChunkHash>()
                    .with_context(|| format!("parse chunk hash {h}"))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let parts = shard.parts.unwrap_or(1);
        if parts > 1 {
            bail!(
                "shard {} has {} chunks but the manifest carries no chunk list \
                 (predates RFC 0001 chunk-index) — re-push to migrate",
                shard.role,
                parts
            );
        }
        vec![shard
            .merkle
            .parse::<ChunkHash>()
            .with_context(|| format!("parse shard merkle: {}", shard.merkle))?]
    };

    // Authenticate the chunk list against the signed merkle root: the
    // manifest signature covers `merkle`, so a matching recomputed root
    // proves the list is genuine (no separate sidecar signature needed).
    let recomputed = shard_merkle(&chunk_hashes);
    if recomputed.to_string() != shard.merkle {
        bail!(
            "shard {} chunk list does not match signed merkle: manifest={} computed={}",
            shard.role,
            shard.merkle,
            recomputed
        );
    }

    // Fetch each chunk, verify its content hash, concatenate in order.
    // Local cache short-circuits the wire: a chunk already on disk (from a
    // prior pull or shared with another shard) is a cache-hit, zero wire bytes.
    let mut body: Vec<u8> = Vec::with_capacity(shard.size as usize);
    let mut on_wire: u64 = 0;
    for h in &chunk_hashes {
        let cache_path = cache_dir.map(|d| d.join(h.to_string()));

        // Try the cache first, re-verifying its content hash (local files can
        // rot; the integrity guarantee must hold regardless of source).
        let cached = cache_path.as_deref().and_then(|p| std::fs::read(p).ok());
        let bytes = match cached {
            Some(b) if ChunkHash::of(&b).to_string() == h.to_string() => {
                emit(PullEvent::ChunkDone {
                    idx,
                    bytes: b.len() as u64,
                    cache_hit: true,
                });
                b
            }
            _ => {
                let b = store
                    .get_chunk(h)
                    .await
                    .map_err(|e| anyhow!("get chunk {h}: {e}"))?;
                let got = ChunkHash::of(&b);
                if got.to_string() != h.to_string() {
                    bail!("chunk {h} content hash mismatch: got {got}");
                }
                on_wire += b.len() as u64;
                // Populate the cache (best-effort; a cache write failure must
                // not fail the pull). Atomic-ish: write to a temp sibling then
                // rename so a concurrent reader never sees a partial file.
                if let Some(p) = &cache_path {
                    let tmp = p.with_extension("partial");
                    if std::fs::write(&tmp, &b).is_ok() {
                        let _ = std::fs::rename(&tmp, p);
                    }
                }
                emit(PullEvent::ChunkDone {
                    idx,
                    bytes: b.len() as u64,
                    cache_hit: false,
                });
                b.to_vec()
            }
        };
        body.extend_from_slice(&bytes);
    }

    let filename = shard_filename(shard);
    let path = out_dir.join(&filename);
    std::fs::write(&path, &body).with_context(|| format!("write {}", path.display()))?;

    Ok((body.len() as u64, on_wire))
}

/// Map a shard back to a filename. role+format → `<role>.<format>`,
/// except for tokenizer/format=tokenizers.json which maps to
/// `tokenizer.json` and config/json which maps to `config.json` to match
/// what `push` originally read.
fn shard_filename(shard: &Shard) -> String {
    match (shard.role.as_str(), shard.format.as_str()) {
        ("tokenizer", "tokenizers.json") => "tokenizer.json".into(),
        ("config", "json") => "config.json".into(),
        ("weights", "safetensors") => "model.safetensors".into(),
        (role, fmt) => format!("{role}.{fmt}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modelref_parse_ok() {
        let r = ModelRef::parse("mistral/mixtral-8x22b:v0.3.1").unwrap();
        assert_eq!(r.name, "mistral/mixtral-8x22b");
        assert_eq!(r.version, "v0.3.1");
    }

    #[test]
    fn modelref_bare_name_defaults_to_latest() {
        let r = ModelRef::parse("org/model").unwrap();
        assert_eq!(r.name, "org/model");
        assert_eq!(r.version, DEFAULT_VERSION);
        assert_eq!(r.version, "latest");
    }

    #[test]
    fn modelref_rejects_malformed_colon() {
        // A typed colon with an empty side is malformed, NOT a default.
        assert!(ModelRef::parse("name:").is_err());
        assert!(ModelRef::parse(":v1").is_err());
        assert!(ModelRef::parse("").is_err());
    }

    #[test]
    fn shard_filename_known_combos() {
        let mk = |role: &str, fmt: &str| Shard {
            role: role.into(),
            format: fmt.into(),
            parts: None,
            size: 0,
            merkle: String::new(),
            chunks: vec![],
        };
        assert_eq!(
            shard_filename(&mk("weights", "safetensors")),
            "model.safetensors"
        );
        assert_eq!(
            shard_filename(&mk("tokenizer", "tokenizers.json")),
            "tokenizer.json"
        );
        assert_eq!(shard_filename(&mk("config", "json")), "config.json");
        assert_eq!(shard_filename(&mk("adapter", "lora")), "adapter.lora");
    }

    #[tokio::test]
    async fn multi_chunk_shard_reassembles_in_order() {
        use concord_core::store::MemoryStore;
        let store = MemoryStore::new();
        let bodies: Vec<Vec<u8>> = vec![vec![1u8; 100], vec![2u8; 80], vec![3u8; 50]];
        let mut hashes = Vec::new();
        for b in &bodies {
            let h = ChunkHash::of(b.as_slice());
            store
                .put_chunk(&h, bytes::Bytes::from(b.clone()))
                .await
                .unwrap();
            hashes.push(h);
        }
        let merkle = shard_merkle(&hashes);
        let shard = Shard {
            role: "weights".into(),
            format: "bin".into(),
            parts: Some(3),
            size: 230,
            merkle: merkle.to_string(),
            chunks: hashes.iter().map(|h| h.to_string()).collect(),
        };
        let dir = tempfile::tempdir().unwrap();
        let (n, wire) = pull_shard(&store, &shard, dir.path(), None, 1, &|_| {})
            .await
            .unwrap();
        assert_eq!(n, 230);
        assert_eq!(wire, 230, "no cache → every byte is on the wire");
        let got = std::fs::read(dir.path().join("weights.bin")).unwrap();
        let expect: Vec<u8> = bodies.concat();
        assert_eq!(got, expect, "reassembled bytes must match concat in order");
    }

    #[tokio::test]
    async fn multi_chunk_list_not_matching_merkle_is_rejected() {
        use concord_core::store::MemoryStore;
        let store = MemoryStore::new();
        let b = vec![9u8; 10];
        let h = ChunkHash::of(b.as_slice());
        store.put_chunk(&h, bytes::Bytes::from(b)).await.unwrap();
        // merkle claims something the chunk list can't produce → must fail
        // (the signature covers merkle, so a tampered list is caught here).
        let shard = Shard {
            role: "weights".into(),
            format: "bin".into(),
            parts: Some(2),
            size: 20,
            merkle: "b3:0000000000000000000000000000000000000000000000000000000000000000".into(),
            chunks: vec![h.to_string(), h.to_string()],
        };
        let dir = tempfile::tempdir().unwrap();
        assert!(pull_shard(&store, &shard, dir.path(), None, 1, &|_| {})
            .await
            .is_err());
    }

    #[test]
    fn dedup_pct_reflects_wire_savings() {
        let s = PullStats {
            files: 1,
            bytes: 100,
            on_wire: 25,
            residency: "eu".into(),
        };
        assert_eq!(s.dedup_pct(), 75.0);
        assert_eq!(
            PullStats::default().dedup_pct(),
            0.0,
            "empty pull = no dedup"
        );
    }

    /// Wraps a store and counts `get_chunk` calls so a test can prove a
    /// cache-hit didn't go back to the wire.
    struct CountingStore {
        inner: concord_core::store::MemoryStore,
        gets: std::sync::atomic::AtomicUsize,
    }
    impl CountingStore {
        fn new(inner: concord_core::store::MemoryStore) -> Self {
            Self {
                inner,
                gets: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn gets(&self) -> usize {
            self.gets.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    #[async_trait::async_trait]
    impl Store for CountingStore {
        async fn has_chunk(&self, h: &ChunkHash) -> Result<bool, concord_core::store::StoreError> {
            self.inner.has_chunk(h).await
        }
        async fn put_chunk(
            &self,
            h: &ChunkHash,
            b: bytes::Bytes,
        ) -> Result<(), concord_core::store::StoreError> {
            self.inner.put_chunk(h, b).await
        }
        async fn get_chunk(
            &self,
            h: &ChunkHash,
        ) -> Result<bytes::Bytes, concord_core::store::StoreError> {
            self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.get_chunk(h).await
        }
        async fn put_manifest(
            &self,
            n: &str,
            v: &str,
            b: bytes::Bytes,
        ) -> Result<(), concord_core::store::StoreError> {
            self.inner.put_manifest(n, v, b).await
        }
        async fn get_manifest(
            &self,
            n: &str,
            v: &str,
        ) -> Result<bytes::Bytes, concord_core::store::StoreError> {
            self.inner.get_manifest(n, v).await
        }
    }

    /// Wraps MemoryStore, tracks the MAX number of `get_chunk` calls in
    /// flight at once. Yields a few times inside each call so the scheduler
    /// can advance other buffered shard futures → overlap is observable.
    struct ConcurrencyStore {
        inner: concord_core::store::MemoryStore,
        inflight: std::sync::atomic::AtomicUsize,
        max: std::sync::atomic::AtomicUsize,
    }
    impl ConcurrencyStore {
        fn new(inner: concord_core::store::MemoryStore) -> Self {
            Self {
                inner,
                inflight: std::sync::atomic::AtomicUsize::new(0),
                max: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn max_inflight(&self) -> usize {
            self.max.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    #[async_trait::async_trait]
    impl Store for ConcurrencyStore {
        async fn has_chunk(&self, h: &ChunkHash) -> Result<bool, concord_core::store::StoreError> {
            self.inner.has_chunk(h).await
        }
        async fn put_chunk(
            &self,
            h: &ChunkHash,
            b: bytes::Bytes,
        ) -> Result<(), concord_core::store::StoreError> {
            self.inner.put_chunk(h, b).await
        }
        async fn get_chunk(
            &self,
            h: &ChunkHash,
        ) -> Result<bytes::Bytes, concord_core::store::StoreError> {
            use std::sync::atomic::Ordering::SeqCst;
            let n = self.inflight.fetch_add(1, SeqCst) + 1;
            self.max.fetch_max(n, SeqCst);
            for _ in 0..6 {
                tokio::task::yield_now().await;
            }
            let r = self.inner.get_chunk(h).await;
            self.inflight.fetch_sub(1, SeqCst);
            r
        }
        async fn put_manifest(
            &self,
            n: &str,
            v: &str,
            b: bytes::Bytes,
        ) -> Result<(), concord_core::store::StoreError> {
            self.inner.put_manifest(n, v, b).await
        }
        async fn get_manifest(
            &self,
            n: &str,
            v: &str,
        ) -> Result<bytes::Bytes, concord_core::store::StoreError> {
            self.inner.get_manifest(n, v).await
        }
    }

    /// Build N single-chunk shards with distinct content in `store`.
    async fn seed_shards(store: &concord_core::store::MemoryStore, n: usize) -> Vec<Shard> {
        let mut shards = Vec::new();
        for i in 0..n {
            let body = vec![i as u8 + 1; 64 + i];
            let h = ChunkHash::of(body.as_slice());
            store
                .put_chunk(&h, bytes::Bytes::from(body.clone()))
                .await
                .unwrap();
            shards.push(Shard {
                role: format!("w{i}"),
                format: "bin".into(),
                parts: Some(1),
                size: body.len() as u64,
                merkle: shard_merkle(std::slice::from_ref(&h)).to_string(),
                chunks: vec![h.to_string()],
            });
        }
        shards
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shards_download_in_parallel() {
        use concord_core::store::MemoryStore;
        let inner = MemoryStore::new();
        let shards = seed_shards(&inner, 6).await;
        let store = ConcurrencyStore::new(inner);
        let out = tempfile::tempdir().unwrap();

        let (files, bytes, _on_wire) =
            download_shards(&store, &shards, out.path(), None, 4, &|_| {})
                .await
                .unwrap();

        assert_eq!(files, 6, "all shards reassembled");
        assert_eq!(bytes, shards.iter().map(|s| s.size).sum::<u64>());
        assert!(
            store.max_inflight() >= 2,
            "expected concurrent fetches, max in-flight was {}",
            store.max_inflight()
        );
        // Every file present on disk.
        for s in &shards {
            assert!(
                out.path().join(shard_filename(s)).exists(),
                "{} missing",
                s.role
            );
        }
    }

    #[tokio::test]
    async fn cache_hit_avoids_wire_refetch() {
        use concord_core::store::MemoryStore;
        let inner = MemoryStore::new();
        let body = vec![7u8; 256];
        let h = ChunkHash::of(body.as_slice());
        inner
            .put_chunk(&h, bytes::Bytes::from(body.clone()))
            .await
            .unwrap();
        let merkle = shard_merkle(std::slice::from_ref(&h));
        let shard = Shard {
            role: "weights".into(),
            format: "bin".into(),
            parts: Some(1),
            size: 256,
            merkle: merkle.to_string(),
            chunks: vec![h.to_string()],
        };
        let store = CountingStore::new(inner);
        let cache = tempfile::tempdir().unwrap();

        // First pull: cold cache → fetched over the wire.
        let out1 = tempfile::tempdir().unwrap();
        let (w1, wire1) = pull_shard(&store, &shard, out1.path(), Some(cache.path()), 1, &|_| {})
            .await
            .unwrap();
        assert_eq!((w1, wire1), (256, 256), "cold pull fetches over the wire");
        assert_eq!(store.gets(), 1);

        // Second pull: warm cache → served from disk, zero wire bytes.
        let out2 = tempfile::tempdir().unwrap();
        let (w2, wire2) = pull_shard(&store, &shard, out2.path(), Some(cache.path()), 1, &|_| {})
            .await
            .unwrap();
        assert_eq!(w2, 256, "still reassembles full bytes from cache");
        assert_eq!(wire2, 0, "cache hit fetches nothing over the wire");
        assert_eq!(
            store.gets(),
            1,
            "cache hit must not re-fetch from the store"
        );
        let got = std::fs::read(out2.path().join("weights.bin")).unwrap();
        assert_eq!(got, body, "cached reassembly matches original");
    }
}
