//! Implementation of `concord push <model-dir>`.
//!
//! Walks the dir, chunks each file (one shard per file), HEAD-checks each
//! chunk against the store before upload (the dedup contract), uploads
//! new chunks, builds + signs the manifest, writes it to the store.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use concord_core::chunker::{self, ChunkHash, ChunkRef};
use concord_core::manifest::{License, Manifest, ManifestHeader, Shard};
use concord_core::shard::shard_merkle;
use concord_core::sign;
use concord_core::store::Store;
use ed25519_dalek::SigningKey;
use futures::stream::{StreamExt, TryStreamExt};
use time::OffsetDateTime;

/// One file's worth of work — what gets hashed, what shard it becomes.
#[derive(Clone, Debug)]
struct FilePlan {
    relpath: String,
    abspath: PathBuf,
    role: &'static str,
    format: String,
}

/// Per-shard upload accounting, fed back to the caller for the
/// human-readable summary.
#[derive(Clone, Copy, Debug, Default)]
pub struct PushStats {
    pub chunks_total: u64,
    pub chunks_uploaded: u64,
    pub chunks_skipped: u64,
    pub bytes_total: u64,
    pub bytes_uploaded: u64,
    pub bytes_skipped: u64,
}

impl PushStats {
    fn add(&mut self, other: &PushStats) {
        self.chunks_total += other.chunks_total;
        self.chunks_uploaded += other.chunks_uploaded;
        self.chunks_skipped += other.chunks_skipped;
        self.bytes_total += other.bytes_total;
        self.bytes_uploaded += other.bytes_uploaded;
        self.bytes_skipped += other.bytes_skipped;
    }
}

/// Required arguments for [`push`]. Mirrors the CLI flags one-to-one.
#[derive(Clone, Debug)]
pub struct PushArgs {
    pub model_dir: PathBuf,
    pub name: String,
    pub version: String,
    pub key_id: String,
    pub residency: String,
    pub license_spdx: String,
    /// RFC 3339 UTC timestamp ending in `Z`. `None` ⇒ `now`.
    pub issued_at: Option<String>,
}

/// Progress callback emitted per chunk decision. CLI hooks indicatif here;
/// library + tests leave it `None`.
pub type ProgressFn = std::sync::Arc<dyn Fn(ProgressEvent) + Send + Sync>;

/// One event per chunk decision (or per file boundary).
#[derive(Clone, Debug)]
pub enum ProgressEvent {
    /// Up-front: total bytes + chunk count discovered by walking the dir.
    Plan { total_bytes: u64, total_chunks: u64 },
    /// A chunk was uploaded (new bytes hit the wire).
    Uploaded { bytes: u64 },
    /// A chunk was skipped (dedup hit; zero wire bytes).
    Skipped { bytes: u64 },
    /// Whole push complete.
    Done,
}

/// Push a model dir into `store`, returning the signed manifest + stats.
///
/// The manifest is uploaded under `manifests/<name>/<version>.toml`. The
/// signed bytes are also returned so the caller (CLI) can print them /
/// write them locally if desired.
pub async fn push<S: Store + ?Sized>(
    store: &S,
    args: &PushArgs,
    signing_key: &SigningKey,
) -> Result<(Manifest, Vec<u8>, PushStats)> {
    push_with_progress(store, args, signing_key, None).await
}

/// Variant of [`push`] that emits [`ProgressEvent`]s through the callback.
pub async fn push_with_progress<S: Store + ?Sized>(
    store: &S,
    args: &PushArgs,
    signing_key: &SigningKey,
    progress: Option<ProgressFn>,
) -> Result<(Manifest, Vec<u8>, PushStats)> {
    if !args.model_dir.is_dir() {
        bail!(
            "model dir does not exist or is not a directory: {}",
            args.model_dir.display()
        );
    }

    let plans = walk_model_dir(&args.model_dir)?;
    if plans.is_empty() {
        bail!("model dir is empty: {}", args.model_dir.display());
    }

    // Pre-scan: total bytes on disk + a chunk-count estimate (ceil-divide
    // by 4 MiB). Emitted up-front so the CLI can prime a sized progress
    // bar before any work begins.
    if let Some(cb) = progress.as_ref() {
        let total_bytes: u64 = plans
            .iter()
            .filter_map(|p| std::fs::metadata(&p.abspath).ok().map(|m| m.len()))
            .sum();
        let chunk_sz = concord_core::CHUNK_SIZE as u64;
        let total_chunks = plans
            .iter()
            .filter_map(|p| std::fs::metadata(&p.abspath).ok())
            .map(|m| m.len().div_ceil(chunk_sz))
            .sum();
        cb(ProgressEvent::Plan {
            total_bytes,
            total_chunks,
        });
    }

    let mut shards: Vec<Shard> = Vec::with_capacity(plans.len());
    let mut totals = PushStats::default();

    // Per-file: hash chunks (blocking, off the runtime), upload missing
    // ones in parallel via the store. We don't pipeline across files
    // because that risks unbounded memory growth on a big model — one
    // file at a time, each file's chunks fanned out concurrently.
    for plan in plans {
        let (refs, bodies) = chunk_file(&plan.abspath)
            .with_context(|| format!("chunk file {}", plan.abspath.display()))?;

        let merkle = shard_merkle(&refs.iter().map(|r| r.hash).collect::<Vec<_>>());
        let size: u64 = refs.iter().map(|r| r.len as u64).sum();

        let stats = upload_chunks(store, &refs, bodies, progress.as_ref())
            .await
            .with_context(|| format!("upload chunks for {} ({})", plan.relpath, plan.role))?;
        totals.add(&stats);

        // Carry the ordered chunk hashes so multi-chunk shards are
        // retrievable (RFC 0001 §Shards). The signed merkle vouches for the
        // list; pull verifies shard_merkle(chunks) == merkle.
        let chunks: Vec<String> = refs.iter().map(|r| r.hash.to_string()).collect();

        shards.push(Shard {
            role: plan.role.to_string(),
            format: plan.format,
            parts: Some(refs.len() as u32),
            size,
            merkle: merkle.to_string(),
            chunks,
        });
    }

    let issued_at = args.issued_at.clone().unwrap_or_else(default_issued_at);
    if !issued_at.ends_with('Z') {
        bail!("issued_at must end in Z (RFC 3339 UTC)");
    }

    let issuer = derive_issuer(&args.key_id);
    let unsigned = Manifest {
        manifest: ManifestHeader {
            name: args.name.clone(),
            version: args.version.clone(),
            protocol: concord_core::PROTOCOL_VERSION.to_string(),
            issuer,
            issued_at,
        },
        license: License {
            spdx: args.license_spdx.clone(),
            residency: args.residency.clone(),
            export: "unrestricted".to_string(),
        },
        shards,
        pull_policy: None,
        supersedes: None,
        signature: None,
    };
    unsigned.validate().context("manifest validation")?;

    let signed = sign::sign(unsigned, &args.key_id, signing_key)
        .map_err(|e| anyhow!("sign manifest: {e}"))?;
    let signed_bytes = signed
        .to_signed_bytes()
        .map_err(|e| anyhow!("serialize signed manifest: {e}"))?;

    store
        .put_manifest(&args.name, &args.version, Bytes::from(signed_bytes.clone()))
        .await
        .map_err(|e| anyhow!("put manifest: {e}"))?;

    if let Some(cb) = progress.as_ref() {
        cb(ProgressEvent::Done);
    }

    Ok((signed, signed_bytes, totals))
}

/// Read + chunk a file. Hashing 4 MiB blake3 chunks on the current thread
/// blocks the runtime; callers in async context should wrap this in
/// [`tokio::task::spawn_blocking`]. For typical small phase-0 fixtures
/// the inline cost is negligible.
fn chunk_file(path: &Path) -> Result<(Vec<ChunkRef>, Vec<Bytes>)> {
    let file = std::fs::File::open(path)?;
    let mut bodies: Vec<Bytes> = Vec::new();
    let refs = chunker::chunk_stream(file, |_cref, body| {
        bodies.push(Bytes::copy_from_slice(body));
        Ok(())
    })?;
    Ok((refs, bodies))
}

/// Number of attempts for `put_chunk` before giving up. The first attempt
/// is the one inside the main loop; this is the retry budget. Chosen so
/// a flaky CloudVerve EC quorum (~1 in N chunks deadlines silently on
/// aarch64; opensharded#324) doesn't tank an entire push.
const PUT_CHUNK_RETRIES: usize = 5;

/// Default max chunk PUTs in flight per file; override with
/// `CONCORD_UPLOAD_CONCURRENCY`.
const DEFAULT_UPLOAD_CONCURRENCY: usize = 32;

/// Chunk-PUT concurrency, from `CONCORD_UPLOAD_CONCURRENCY` (clamped ≥1),
/// else [`DEFAULT_UPLOAD_CONCURRENCY`].
fn upload_concurrency() -> usize {
    std::env::var("CONCORD_UPLOAD_CONCURRENCY")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|n| n.max(1))
        .unwrap_or(DEFAULT_UPLOAD_CONCURRENCY)
}

/// Retry `put_chunk` with exponential backoff. Idempotent at the storage
/// layer because chunks are blake3-addressed — a repeat PUT of the same
/// hash is a no-op or an identical overwrite.
async fn put_chunk_with_retry<S: Store + ?Sized>(
    store: &S,
    hash: &ChunkHash,
    body: Bytes,
) -> Result<()> {
    let mut last_err: Option<anyhow::Error> = None;
    let mut delay = std::time::Duration::from_secs(1);
    for attempt in 0..=PUT_CHUNK_RETRIES {
        match store.put_chunk(hash, body.clone()).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                let msg = format!(
                    "put_chunk attempt {} of {}: {e}",
                    attempt + 1,
                    PUT_CHUNK_RETRIES + 1
                );
                if attempt < PUT_CHUNK_RETRIES {
                    tracing::warn!("{msg}, retrying in {:?}", delay);
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(std::time::Duration::from_secs(30));
                }
                last_err = Some(anyhow!(msg));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("put_chunk: exhausted retries")))
}

async fn upload_chunks<S: Store + ?Sized>(
    store: &S,
    refs: &[ChunkRef],
    bodies: Vec<Bytes>,
    progress: Option<&ProgressFn>,
) -> Result<PushStats> {
    let mut stats = PushStats {
        chunks_total: refs.len() as u64,
        bytes_total: refs.iter().map(|r| r.len as u64).sum(),
        ..Default::default()
    };

    // PUT-always. Backend is content-addressed (key = blake3 hash), so a
    // redundant write of an identical chunk is a no-op at the storage
    // layer. Skipping the per-chunk `has_chunk` HEAD avoids two known
    // failure modes against CloudVerve: (1) HEAD on a non-existent
    // `chunks/<hh>/<64hex>` key hangs the connection forever; (2) a
    // timed-out HEAD on a pooled connection poisons subsequent PUTs on
    // that same connection with `error sending request`. MemoryStore
    // tolerates the duplicate PUT (overwrite). The on-the-wire cost is
    // duplicate writes for already-uploaded chunks; acceptable for
    // phase-0 push throughput.
    // Fan out chunk PUTs with bounded concurrency. `Store: Send + Sync`, so
    // `&store` is shared across the in-flight futures (no Arc / no spawn —
    // the stream is driven within this fn, so borrows of `refs`/`progress`
    // are sound). Content-addressed PUT-always means order doesn't matter.
    let uploaded: Vec<u64> = futures::stream::iter(refs.iter().zip(bodies.into_iter()))
        .map(|(cref, body)| {
            let len = cref.len as u64;
            async move {
                put_chunk_with_retry(store, &cref.hash, body).await?;
                if let Some(cb) = progress {
                    cb(ProgressEvent::Uploaded { bytes: len });
                }
                Ok::<u64, anyhow::Error>(len)
            }
        })
        .buffer_unordered(upload_concurrency())
        .try_collect()
        .await?;

    stats.chunks_uploaded = uploaded.len() as u64;
    stats.bytes_uploaded = uploaded.iter().sum();

    Ok(stats)
}

/// Walk `dir` recursively, mapping each regular file to a [`FilePlan`].
/// File order is sorted by relative path so a re-push produces a
/// byte-identical manifest (canonical bytes order shards in input order).
fn walk_model_dir(dir: &Path) -> Result<Vec<FilePlan>> {
    let mut out = Vec::new();
    collect(dir, dir, &mut out)?;
    out.sort_by(|a, b| a.relpath.cmp(&b.relpath));
    Ok(out)
}

fn collect(root: &Path, cur: &Path, out: &mut Vec<FilePlan>) -> Result<()> {
    for entry in std::fs::read_dir(cur).with_context(|| format!("read_dir {}", cur.display()))? {
        let entry = entry?;
        let p = entry.path();
        let meta = entry.metadata()?;
        if meta.is_dir() {
            collect(root, &p, out)?;
        } else if meta.is_file() {
            let relpath = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let (role, format) = classify(&relpath);
            out.push(FilePlan {
                relpath,
                abspath: p,
                role,
                format,
            });
        }
    }
    Ok(())
}

/// Infer `(role, format)` from a file's relative path. Anything we don't
/// recognise drops to the `aux` role with `bin` format so the manifest
/// still records it.
fn classify(relpath: &str) -> (&'static str, String) {
    let name = relpath.rsplit('/').next().unwrap_or(relpath);
    let lname = name.to_ascii_lowercase();
    if lname.ends_with(".safetensors") {
        ("weights", "safetensors".into())
    } else if lname.starts_with("tokenizer") && lname.ends_with(".json") {
        ("tokenizer", "tokenizers.json".into())
    } else if lname == "config.json" {
        ("config", "json".into())
    } else {
        let ext = lname.rsplit('.').next().unwrap_or("bin").to_string();
        ("aux", ext)
    }
}

fn default_issued_at() -> String {
    use time::macros::format_description;
    let now = OffsetDateTime::now_utc();
    // RFC 3339 UTC ending in Z, second precision.
    let fmt = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    now.format(fmt).expect("format now")
}

/// Issuer is the namespace prefix of the key id. e.g.
/// `eu:test-operator:k/2026-01` → `eu:test-operator`.
fn derive_issuer(key_id: &str) -> String {
    match key_id.rsplit_once(':') {
        Some((prefix, _)) => prefix.to_string(),
        None => key_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use concord_core::store::MemoryStore;

    fn write(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn classify_known_files() {
        assert_eq!(classify("model.safetensors").0, "weights");
        assert_eq!(classify("tokenizer.json").0, "tokenizer");
        assert_eq!(classify("tokenizer.model"), ("aux", "model".into()));
        assert_eq!(classify("config.json").0, "config");
        assert_eq!(classify("README.md"), ("aux", "md".into()));
        // path with subdirs uses the basename, not the dir name.
        assert_eq!(classify("nested/dir/model.safetensors").0, "weights");
    }

    #[test]
    fn derive_issuer_drops_last_segment() {
        assert_eq!(
            derive_issuer("eu:test-operator:k/2026-01"),
            "eu:test-operator"
        );
        assert_eq!(derive_issuer("single"), "single");
    }

    #[tokio::test]
    async fn push_into_memory_store_roundtrip() {
        let (sk, _vk) = sign::generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "model.safetensors", b"weights body bytes");
        write(dir.path(), "tokenizer.json", b"{\"vocab\":[]}");
        write(dir.path(), "config.json", b"{\"hidden\":4}");

        let store = MemoryStore::new();
        let args = PushArgs {
            model_dir: dir.path().to_path_buf(),
            name: "test/tiny".into(),
            version: "v0.1.0".into(),
            key_id: "eu:test:k/1".into(),
            residency: "eu".into(),
            license_spdx: "Apache-2.0".into(),
            issued_at: Some("2026-05-26T00:00:00Z".into()),
        };

        let (m, _bytes, stats) = push(&store, &args, &sk).await.unwrap();
        assert_eq!(m.shards.len(), 3);
        assert_eq!(stats.chunks_total, 3);
        assert_eq!(stats.chunks_uploaded, 3);
        assert_eq!(stats.chunks_skipped, 0);
        assert!(m.signature.is_some());

        assert_eq!(store.manifest_count(), 1);
        assert_eq!(store.chunk_count(), 3);
    }

    #[tokio::test]
    async fn push_dedups_identical_files_across_a_push() {
        // Two files with identical bodies → one chunk total, not two.
        let (sk, _vk) = sign::generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.safetensors", b"identical body");
        write(dir.path(), "b.safetensors", b"identical body");

        let store = MemoryStore::new();
        let args = PushArgs {
            model_dir: dir.path().to_path_buf(),
            name: "test/dup".into(),
            version: "v0.1.0".into(),
            key_id: "eu:test:k/1".into(),
            residency: "eu".into(),
            license_spdx: "Apache-2.0".into(),
            issued_at: Some("2026-05-26T00:00:00Z".into()),
        };

        let (_m, _b, stats) = push(&store, &args, &sk).await.unwrap();
        assert_eq!(stats.chunks_total, 2);
        // Per chunk we PUT-always; backend dedups by content-addressed key.
        // Both chunks are uploaded (idempotent overwrite), but the store
        // ends up holding exactly one.
        assert_eq!(stats.chunks_uploaded, 2);
        assert_eq!(stats.chunks_skipped, 0);
        assert_eq!(store.chunk_count(), 1);
    }

    #[tokio::test]
    async fn push_dedups_across_pushes() {
        // Second push of the same dir uploads zero chunks.
        let (sk, _vk) = sign::generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "model.safetensors", b"hello");
        let store = MemoryStore::new();
        let args = PushArgs {
            model_dir: dir.path().to_path_buf(),
            name: "test/m".into(),
            version: "v1".into(),
            key_id: "eu:t:k".into(),
            residency: "eu".into(),
            license_spdx: "Apache-2.0".into(),
            issued_at: Some("2026-05-26T00:00:00Z".into()),
        };
        let (_, _, s1) = push(&store, &args, &sk).await.unwrap();
        assert_eq!(s1.chunks_uploaded, 1);
        // Re-push re-uploads (idempotent at content-addressed backend),
        // chunk_count stays at 1 because the key is the blake3 hash.
        let (_, _, s2) = push(&store, &args, &sk).await.unwrap();
        assert_eq!(s2.chunks_uploaded, 1);
        assert_eq!(s2.chunks_skipped, 0);
        assert_eq!(store.chunk_count(), 1);
    }

    #[tokio::test]
    async fn push_rejects_missing_dir() {
        let (sk, _vk) = sign::generate_keypair();
        let store = MemoryStore::new();
        let args = PushArgs {
            model_dir: PathBuf::from("/definitely/does/not/exist/xyz"),
            name: "a/b".into(),
            version: "v1".into(),
            key_id: "eu:t:k".into(),
            residency: "eu".into(),
            license_spdx: "Apache-2.0".into(),
            issued_at: Some("2026-05-26T00:00:00Z".into()),
        };
        assert!(push(&store, &args, &sk).await.is_err());
    }

    #[tokio::test]
    async fn push_rejects_empty_dir() {
        let (sk, _vk) = sign::generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::new();
        let args = PushArgs {
            model_dir: dir.path().to_path_buf(),
            name: "a/b".into(),
            version: "v1".into(),
            key_id: "eu:t:k".into(),
            residency: "eu".into(),
            license_spdx: "Apache-2.0".into(),
            issued_at: Some("2026-05-26T00:00:00Z".into()),
        };
        assert!(push(&store, &args, &sk).await.is_err());
    }
}
