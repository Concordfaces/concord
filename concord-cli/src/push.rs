//! Implementation of `concord push <model-dir>`.
//!
//! Walks the dir, chunks each file (one shard per file), HEAD-checks each
//! chunk against the store before upload (the dedup contract), uploads
//! new chunks, builds + signs the manifest, writes it to the store.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use concord_core::chunker::{self, ChunkHash, ChunkRef};
use concord_core::manifest::{License, Manifest, ManifestHeader, Quantization, Shard};
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

/// GGUF scheme from a `*.<SCHEME>.gguf` filename (`model.Q4_K_M.gguf` → `Q4_K_M`).
/// `None` when there's no scheme segment.
fn gguf_scheme(fname: &str) -> Option<String> {
    let stem = fname.strip_suffix(".gguf")?;
    stem.rsplit_once('.').map(|(_, sc)| sc.to_string())
}

/// Best-effort quantization from a single unambiguous source signal. `None` if
/// nothing clear. Never errors (any IO/parse failure → None).
fn derive_quant(dir: &Path) -> Option<Quantization> {
    let ggufs: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".gguf"))
        .collect();
    if ggufs.len() == 1 {
        return Some(Quantization {
            method: "gguf".into(),
            scheme: gguf_scheme(&ggufs[0]),
            bits: None,
        });
    }
    if ggufs.len() > 1 {
        return None; // ambiguous — pusher declares via --quant
    }
    let cfg = std::fs::read(dir.join("config.json")).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&cfg).ok()?;
    let qc = v.get("quantization_config")?;
    let method = qc.get("quant_method")?.as_str()?.to_string();
    let bits = qc
        .get("bits")
        .or_else(|| qc.get("w_bit"))
        .and_then(|b| b.as_u64())
        .and_then(|b| u8::try_from(b).ok());
    Some(Quantization {
        method,
        scheme: None,
        bits,
    })
}

/// Base model from `config.json.base_model`, when present.
fn derive_base_model(dir: &Path) -> Option<String> {
    let cfg = std::fs::read(dir.join("config.json")).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&cfg).ok()?;
    v.get("base_model")?.as_str().map(|s| s.to_string())
}

/// Parse `--quant` as `method[:scheme][/bits]`, e.g. `gguf:Q4_K_M`, `awq/4`,
/// `gptq:128g/4`, `nvfp4/4`, `fp8`.
pub fn parse_quant(s: &str) -> Result<Quantization> {
    let (rest, bits) = match s.rsplit_once('/') {
        Some((r, b)) => (
            r,
            Some(
                b.parse::<u8>()
                    .with_context(|| format!("quant bits in {s:?}"))?,
            ),
        ),
        None => (s, None),
    };
    let (method, scheme) = match rest.split_once(':') {
        Some((m, sc)) => (m, Some(sc.to_string())),
        None => (rest, None),
    };
    if method.is_empty() {
        bail!("--quant needs a method, e.g. gguf:Q4_K_M, awq/4, nvfp4/4");
    }
    Ok(Quantization {
        method: method.to_string(),
        scheme,
        bits,
    })
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
    /// `--base-model`: the base this is a quantization of (authoritative).
    pub base_model: Option<String>,
    /// `--quant` descriptor (`method[:scheme][/bits]`), authoritative.
    pub quant: Option<String>,
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
            // Carry the real source-relative filename so pull reconstructs the
            // exact layout — role+format alone collides (e.g. many aux/json).
            path: Some(plan.relpath.clone()),
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

    // Quantization: flag authoritative, else a single unambiguous source signal.
    let quantization = match &args.quant {
        Some(s) => Some(parse_quant(s).context("parse --quant")?),
        None => derive_quant(&args.model_dir),
    };
    let base_model = args
        .base_model
        .clone()
        .or_else(|| derive_base_model(&args.model_dir));

    let issuer = derive_issuer(&args.key_id);
    let unsigned = Manifest {
        manifest: ManifestHeader {
            name: args.name.clone(),
            version: args.version.clone(),
            protocol: concord_core::PROTOCOL_VERSION.to_string(),
            issuer,
            issued_at,
            base_model,
        },
        license: License {
            spdx: args.license_spdx.clone(),
            residency: args.residency.clone(),
            export: "unrestricted".to_string(),
        },
        shards,
        pull_policy: None,
        supersedes: None,
        quantization,
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

    // Maintain the moving `latest` pointer (`manifests/<name>/latest.toml`): a
    // byte-identical copy of the manifest just pushed, so a bare
    // `concord pull <name>` resolves to this release. Same signed bytes ⇒ the
    // ed25519 signature still verifies (it covers content, not the object key).
    // Skipped when the caller already pushed to the `latest` channel explicitly.
    if args.version != crate::pull::DEFAULT_VERSION {
        store
            .put_manifest(
                &args.name,
                crate::pull::DEFAULT_VERSION,
                Bytes::from(signed_bytes.clone()),
            )
            .await
            .map_err(|e| anyhow!("put latest pointer: {e}"))?;
    }

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
    let uploaded: Vec<u64> = futures::stream::iter(refs.iter().zip(bodies))
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
            base_model: None,
            quant: None,
        };

        let (m, bytes, stats) = push(&store, &args, &sk).await.unwrap();
        assert_eq!(m.shards.len(), 3);
        assert_eq!(stats.chunks_total, 3);
        assert_eq!(stats.chunks_uploaded, 3);
        assert_eq!(stats.chunks_skipped, 0);
        assert!(m.signature.is_some());

        // Versioned manifest + the moving `latest` pointer.
        assert_eq!(store.manifest_count(), 2);
        assert_eq!(store.chunk_count(), 3);
        // The pointer is a byte-identical copy of the versioned manifest.
        let versioned = store.get_manifest("test/tiny", "v0.1.0").await.unwrap();
        let latest = store.get_manifest("test/tiny", "latest").await.unwrap();
        assert_eq!(&versioned[..], &bytes[..]);
        assert_eq!(versioned, latest);
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
            base_model: None,
            quant: None,
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
            base_model: None,
            quant: None,
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
            base_model: None,
            quant: None,
        };
        assert!(push(&store, &args, &sk).await.is_err());
    }

    #[test]
    fn parse_quant_variants() {
        use concord_core::manifest::Quantization;
        let p = |s: &str| super::parse_quant(s).unwrap();
        assert_eq!(
            p("gguf:Q4_K_M"),
            Quantization {
                method: "gguf".into(),
                scheme: Some("Q4_K_M".into()),
                bits: None
            }
        );
        assert_eq!(
            p("awq/4"),
            Quantization {
                method: "awq".into(),
                scheme: None,
                bits: Some(4)
            }
        );
        assert_eq!(
            p("gptq:128g/4"),
            Quantization {
                method: "gptq".into(),
                scheme: Some("128g".into()),
                bits: Some(4)
            }
        );
        assert_eq!(
            p("nvfp4/4"),
            Quantization {
                method: "nvfp4".into(),
                scheme: None,
                bits: Some(4)
            }
        );
        assert_eq!(
            p("mxfp4/4"),
            Quantization {
                method: "mxfp4".into(),
                scheme: None,
                bits: Some(4)
            }
        );
        assert_eq!(
            p("fp8"),
            Quantization {
                method: "fp8".into(),
                scheme: None,
                bits: None
            }
        );
        assert!(super::parse_quant("").is_err());
        assert!(super::parse_quant("/4").is_err()); // no method
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
            base_model: None,
            quant: None,
        };
        assert!(push(&store, &args, &sk).await.is_err());
    }

    #[test]
    fn gguf_scheme_from_filename() {
        assert_eq!(
            super::gguf_scheme("model.Q4_K_M.gguf").as_deref(),
            Some("Q4_K_M")
        );
        assert_eq!(super::gguf_scheme("foo.Q8_0.gguf").as_deref(), Some("Q8_0"));
        assert_eq!(super::gguf_scheme("model.gguf"), None); // no scheme segment
        assert_eq!(super::gguf_scheme("model.safetensors"), None);
    }

    #[test]
    fn derive_quant_and_base_from_dir() {
        use concord_core::manifest::Quantization;
        // one .gguf → gguf + scheme, no bits.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("model.Q5_K_M.gguf"), b"x").unwrap();
        assert_eq!(
            super::derive_quant(d.path()),
            Some(Quantization {
                method: "gguf".into(),
                scheme: Some("Q5_K_M".into()),
                bits: None
            })
        );

        // two .gguf → ambiguous → None.
        std::fs::write(d.path().join("model.Q8_0.gguf"), b"y").unwrap();
        assert_eq!(super::derive_quant(d.path()), None);

        // config.json quantization_config → method + bits; base_model.
        let d2 = tempfile::tempdir().unwrap();
        std::fs::write(
            d2.path().join("config.json"),
            br#"{"quantization_config":{"quant_method":"awq","bits":4},"base_model":"org/base"}"#,
        )
        .unwrap();
        assert_eq!(
            super::derive_quant(d2.path()),
            Some(Quantization {
                method: "awq".into(),
                scheme: None,
                bits: Some(4)
            })
        );
        assert_eq!(
            super::derive_base_model(d2.path()).as_deref(),
            Some("org/base")
        );

        // plain dir → no quant, no base.
        let d3 = tempfile::tempdir().unwrap();
        std::fs::write(d3.path().join("config.json"), br#"{"hidden_size":4}"#).unwrap();
        assert_eq!(super::derive_quant(d3.path()), None);
        assert_eq!(super::derive_base_model(d3.path()), None);
    }

    #[tokio::test]
    async fn push_records_quant_and_base_model() {
        use concord_core::store::Store;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("model.Q4_K_M.gguf"), b"weights-bytes").unwrap();

        let (sk, _vk) = sign::generate_keypair();
        let store = MemoryStore::new();
        let args = PushArgs {
            model_dir: dir.path().to_path_buf(),
            name: "org/m-GGUF-Q4_K_M".into(),
            version: "v1".into(),
            key_id: "eu:concordfaces:k/test".into(),
            residency: "eu".into(),
            license_spdx: "MIT".into(),
            issued_at: Some("2026-06-17T00:00:00Z".into()),
            base_model: Some("org/m".into()),
            quant: None, // auto-derive from the .gguf
        };

        push(&store, &args, &sk).await.unwrap();

        let raw = store.get_manifest("org/m-GGUF-Q4_K_M", "v1").await.unwrap();
        let m = concord_core::manifest::Manifest::parse(&raw).unwrap();
        assert_eq!(m.manifest.base_model.as_deref(), Some("org/m"));
        let q = m.quantization.unwrap();
        assert_eq!(q.method, "gguf");
        assert_eq!(q.scheme.as_deref(), Some("Q4_K_M"));
    }
}
