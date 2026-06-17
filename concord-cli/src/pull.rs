//! Implementation of `concord pull <ref>`.
//!
//! Fetches the manifest from the store, verifies its signature against
//! the supplied public key, then walks each `[[shard]]` table — fetching
//! its chunks, verifying the shard merkle as it reassembles, and writing
//! the file out to `--out`.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use concord_core::chunker::ChunkHash;
use concord_core::manifest::{Manifest, Shard};
use concord_core::shard::shard_merkle;
use concord_core::sign;
use concord_core::store::Store;
use ed25519_dalek::VerifyingKey;

use crate::resume::{ResumeMarker, ShardPaths, Status};

/// Required arguments for [`pull`].
#[derive(Clone, Debug)]
pub struct PullArgs {
    pub name: String,
    pub version: String,
    pub out_dir: PathBuf,
    /// Ignore resume state + skip-done: re-fetch and rebuild every shard from
    /// scratch (cache hits still re-verify). For when a local file is suspect.
    pub reverify: bool,
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
    /// Starting a shard (one output file). `resumed_chunks`/`resumed_bytes`
    /// report how much was already on disk from a prior run (0 for a fresh
    /// pull) so the renderer can start the bar at the right offset.
    ShardStart {
        idx: usize,
        total: usize,
        role: String,
        format: String,
        size: u64,
        parts: usize,
        resumed_chunks: usize,
        resumed_bytes: u64,
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
        args.reverify,
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

/// Intra-shard chunk look-ahead. Chunks are fetched up to this many at once
/// (ordered commit), pipelining the network. With the HTTP/1.1 store client each
/// in-flight chunk is its own TCP connection, so this is effectively the number
/// of parallel connections per file — the main throughput dial. 16 reaches
/// ~60 MB/s to the CDN edge for a single large file (a 4.65 GB model);
/// `CONCORD_CHUNK_CONCURRENCY` overrides (32 ≈ 160 MB/s if the link allows).
fn chunk_concurrency() -> usize {
    std::env::var("CONCORD_CHUNK_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(16)
}

/// Global cap on concurrent over-the-wire chunk fetches, across ALL shards.
/// The operator's reconstruct path serializes/contends under load — measured
/// cold throughput peaks near 2 in-flight and collapses past ~4 — so a small
/// global cap downloads FASTER than wide fan-out (and avoids 503s). Raise once
/// the origin streams properly. `CONCORD_MAX_INFLIGHT`; default 2.
/// Process-global adaptive in-flight limiter (AIMD). Starts at 2 concurrent
/// wire fetches and adapts up to `CONCORD_MAX_INFLIGHT` (default 12) while
/// latency stays healthy, backing off on contention/errors. See `limiter`.
fn limiter() -> &'static crate::limiter::Limiter {
    static L: std::sync::OnceLock<crate::limiter::Limiter> = std::sync::OnceLock::new();
    L.get_or_init(|| {
        let max = std::env::var("CONCORD_MAX_INFLIGHT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(12);
        crate::limiter::Limiter::new(2, 1, max)
    })
}

/// Chunks committed before fsync+marker advance. 1 = safest. `CONCORD_COMMIT_EVERY`; default 1.
fn commit_every() -> u32 {
    std::env::var("CONCORD_COMMIT_EVERY")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1)
}

/// Resolve + authenticate the ordered chunk-hash list for a shard against its
/// signed merkle root.
fn resolve_chunk_hashes(shard: &Shard) -> Result<Vec<ChunkHash>> {
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
    let recomputed = shard_merkle(&chunk_hashes);
    if recomputed.to_string() != shard.merkle {
        bail!(
            "shard {} chunk list does not match signed merkle: manifest={} computed={}",
            shard.role,
            shard.merkle,
            recomputed
        );
    }
    Ok(chunk_hashes)
}

/// Fetch one chunk: cache-hit (re-verified) or wire (verified + cached).
/// Returns `(bytes, cache_hit)`.
async fn fetch_one_chunk<S: Store + ?Sized>(
    store: &S,
    h: &ChunkHash,
    cache_path: Option<&Path>,
) -> Result<(bytes::Bytes, bool)> {
    if let Some(p) = cache_path {
        if let Ok(b) = std::fs::read(p) {
            if ChunkHash::of(&b) == *h {
                return Ok((bytes::Bytes::from(b), true));
            }
        }
    }
    // Gate OVER-THE-WIRE fetches through the adaptive limiter (cache hits above
    // never wait). Time each fetch + feed the outcome back so the limiter grows
    // concurrency when the path is fast (edge-warm) and backs off under the
    // origin's contention (cold). The permit is released before recording.
    let lim = limiter();
    let permit = lim.acquire().await;
    let t0 = std::time::Instant::now();
    let result = store.get_chunk(h).await;
    let dur = t0.elapsed();
    drop(permit);
    let b = match result {
        Ok(b) => {
            lim.record(b.len(), dur, false).await;
            b
        }
        Err(e) => {
            lim.record(0, dur, true).await;
            return Err(anyhow!("get chunk {h}: {e}"));
        }
    };
    let got = ChunkHash::of(&b);
    if got != *h {
        bail!("chunk {h} content hash mismatch: got {got}");
    }
    if let Some(p) = cache_path {
        let tmp = p.with_extension("partial");
        if std::fs::write(&tmp, &b).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
    Ok((b, false))
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
    reverify: bool,
    emit: &(impl Fn(PullEvent) + Sync),
) -> Result<(u64, u64, u64)> {
    use futures::stream::{StreamExt, TryStreamExt};

    let total = shards.len();
    let (files, bytes, on_wire) = futures::stream::iter(shards.iter().enumerate())
        .map(|(i, shard)| async move {
            let idx = i + 1;
            let (written, wire) =
                pull_shard(store, shard, out_dir, cache_dir, idx, total, reverify, emit).await?;
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

/// Fetch all chunks for `shard`, streaming them to a `.part` file under
/// `<out_dir>/.concord/`, then atomic-rename to the final output. Resumes from
/// the durable marker; skips shards already complete. Returns
/// `(bytes_written, bytes_on_wire)` — `bytes_written` is the full shard size,
/// `bytes_on_wire` only what was fetched THIS run.
#[allow(clippy::too_many_arguments)]
async fn pull_shard<S: Store + ?Sized>(
    store: &S,
    shard: &Shard,
    out_dir: &Path,
    cache_dir: Option<&Path>,
    idx: usize,
    total: usize,
    reverify: bool,
    emit: &(impl Fn(PullEvent) + Sync),
) -> Result<(u64, u64)> {
    use futures::stream::{self, StreamExt};

    let chunk_hashes = resolve_chunk_hashes(shard)?;
    let filename = shard_output_name(shard);
    // Key the transient .part/marker on the shard INDEX, not the filename, so
    // two shards that resolve to the same output name (legacy manifests with no
    // `path`) never share a .part and race on rename. The final file still uses
    // the resolved name.
    let paths = ShardPaths::new(out_dir, idx, &filename);

    let shard_start = |resumed_chunks: usize, resumed_bytes: u64| {
        emit(PullEvent::ShardStart {
            idx,
            total,
            role: shard.role.clone(),
            format: shard.format.clone(),
            size: shard.size,
            parts: shard.parts.unwrap_or(1) as usize,
            resumed_chunks,
            resumed_bytes,
        });
    };

    // Skip-done: trust only a marker WE wrote (complete + matching merkle) with
    // the final file present.
    if !reverify {
        if let Some(m) = ResumeMarker::load(&paths.marker_path) {
            if m.status == Status::Complete && m.merkle == shard.merkle && paths.final_path.exists()
            {
                shard_start(chunk_hashes.len(), shard.size);
                emit(PullEvent::ShardDone { idx, filename });
                return Ok((shard.size, 0));
            }
        }
    }

    std::fs::create_dir_all(ShardPaths::state_dir(out_dir))
        .with_context(|| format!("mkdir {}", ShardPaths::state_dir(out_dir).display()))?;

    // The resolved name may carry subdirectories (e.g. `subdir/weights.bin`);
    // ensure the final file's parent exists before the rename.
    if let Some(parent) = paths.final_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    // Resume point: a partial marker with the SAME merkle, else fresh.
    let mut marker = if reverify {
        ResumeMarker::fresh(&shard.merkle)
    } else {
        match ResumeMarker::load(&paths.marker_path) {
            Some(m) if m.status == Status::Partial && m.merkle == shard.merkle => m,
            _ => ResumeMarker::fresh(&shard.merkle),
        }
    };

    // Open `.part`, truncate down to the durable boundary (drops any torn tail),
    // position for appending. Never reset to 0 on a short file: the durability
    // invariant guarantees `.part` len >= bytes_done.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&paths.part_path)
        .with_context(|| format!("open {}", paths.part_path.display()))?;
    // The durability invariant guarantees `.part` length >= bytes_done in the
    // normal case. If it's SHORTER (e.g. a prior run renamed .part → final then
    // crashed before writing the Complete marker, or .part was deleted), the
    // committed prefix is gone — trusting bytes_done would zero-pad a fresh file
    // and clobber a possibly-good final file. Restart this shard from scratch.
    let actual_len = file.metadata().context("stat part")?.len();
    if actual_len < marker.bytes_done {
        marker = ResumeMarker::fresh(&shard.merkle);
    }
    file.set_len(marker.bytes_done).with_context(|| {
        format!(
            "truncate {} to {}",
            paths.part_path.display(),
            marker.bytes_done
        )
    })?;
    file.seek(SeekFrom::End(0)).context("seek part to end")?;

    shard_start(marker.chunks_done, marker.bytes_done);

    let start = marker.chunks_done;
    let remaining: Vec<ChunkHash> = chunk_hashes.iter().cloned().skip(start).collect();

    let concurrency = chunk_concurrency();
    let commit_n = commit_every();

    let mut fetches = stream::iter(remaining.into_iter().map(|h| {
        let cache_path = cache_dir.map(|d| d.join(h.to_string()));
        async move { fetch_one_chunk(store, &h, cache_path.as_deref()).await }
    }))
    .buffered(concurrency.max(1));

    let mut on_wire: u64 = 0;
    let mut since_commit: u32 = 0;
    while let Some(item) = fetches.next().await {
        let (bytes, cache_hit) = item?;
        if !cache_hit {
            on_wire += bytes.len() as u64;
        }
        file.write_all(&bytes)
            .with_context(|| format!("append to {}", paths.part_path.display()))?;
        marker.chunks_done += 1;
        marker.bytes_done += bytes.len() as u64;
        since_commit += 1;
        if since_commit >= commit_n {
            file.flush().context("flush part")?;
            file.sync_all().context("fsync part")?;
            marker.save(&paths.marker_path)?;
            since_commit = 0;
        }
        emit(PullEvent::ChunkDone {
            idx,
            bytes: bytes.len() as u64,
            cache_hit,
        });
    }

    file.flush().context("flush part")?;
    file.sync_all().context("fsync part")?;
    drop(file);
    std::fs::rename(&paths.part_path, &paths.final_path).with_context(|| {
        format!(
            "rename {} → {}",
            paths.part_path.display(),
            paths.final_path.display()
        )
    })?;
    marker.status = Status::Complete;
    marker.save(&paths.marker_path)?;

    emit(PullEvent::ShardDone { idx, filename });
    Ok((marker.bytes_done, on_wire))
}

/// The output path (relative to out_dir) for a shard. Prefers the manifest's
/// real `path` (the exact source layout); falls back to a `role.format` name
/// for legacy manifests that predate the `path` field. The path is sanitized
/// to a safe relative path so a manifest can never escape out_dir.
fn shard_output_name(shard: &Shard) -> String {
    if let Some(p) = &shard.path {
        let safe = sanitize_rel_path(p);
        if !safe.is_empty() {
            return safe;
        }
    }
    shard_filename(shard)
}

/// Reduce a path to its safe `Normal` components joined by `/` — drops leading
/// `/`, `..`, `.`, and any drive/root prefix. Guards against path traversal: a
/// manifest `path` like `../../etc/x` or `/etc/x` can only ever write inside
/// out_dir.
fn sanitize_rel_path(p: &str) -> String {
    use std::path::Component;
    Path::new(p)
        .components()
        .filter_map(|c| match c {
            Component::Normal(os) => os.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
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
            path: None,
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
            path: None,
            parts: Some(3),
            size: 230,
            merkle: merkle.to_string(),
            chunks: hashes.iter().map(|h| h.to_string()).collect(),
        };
        let dir = tempfile::tempdir().unwrap();
        let (n, wire) = pull_shard(&store, &shard, dir.path(), None, 1, 1, false, &|_| {})
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
            path: None,
            parts: Some(2),
            size: 20,
            merkle: "b3:0000000000000000000000000000000000000000000000000000000000000000".into(),
            chunks: vec![h.to_string(), h.to_string()],
        };
        let dir = tempfile::tempdir().unwrap();
        assert!(
            pull_shard(&store, &shard, dir.path(), None, 1, 1, false, &|_| {})
                .await
                .is_err()
        );
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
                path: None,
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
            download_shards(&store, &shards, out.path(), None, 4, false, &|_| {})
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
            path: None,
            parts: Some(1),
            size: 256,
            merkle: merkle.to_string(),
            chunks: vec![h.to_string()],
        };
        let store = CountingStore::new(inner);
        let cache = tempfile::tempdir().unwrap();

        // First pull: cold cache → fetched over the wire.
        let out1 = tempfile::tempdir().unwrap();
        let (w1, wire1) = pull_shard(
            &store,
            &shard,
            out1.path(),
            Some(cache.path()),
            1,
            1,
            false,
            &|_| {},
        )
        .await
        .unwrap();
        assert_eq!((w1, wire1), (256, 256), "cold pull fetches over the wire");
        assert_eq!(store.gets(), 1);

        // Second pull: warm cache → served from disk, zero wire bytes.
        let out2 = tempfile::tempdir().unwrap();
        let (w2, wire2) = pull_shard(
            &store,
            &shard,
            out2.path(),
            Some(cache.path()),
            1,
            1,
            false,
            &|_| {},
        )
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

    async fn three_chunk_shard(store: &concord_core::store::MemoryStore) -> (Shard, Vec<Vec<u8>>) {
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
        let shard = Shard {
            role: "weights".into(),
            format: "bin".into(),
            path: None,
            parts: Some(3),
            size: 230,
            merkle: shard_merkle(&hashes).to_string(),
            chunks: hashes.iter().map(|h| h.to_string()).collect(),
        };
        (shard, bodies)
    }

    #[tokio::test]
    async fn fresh_pull_streams_full_file() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let (written, wire) = pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        assert_eq!((written, wire), (230, 230));
        assert_eq!(store.gets(), 3);
        let got = std::fs::read(out.path().join("weights.bin")).unwrap();
        assert_eq!(got, bodies.concat());
        let p = ShardPaths::new(out.path(), 1, "weights.bin");
        assert_eq!(
            ResumeMarker::load(&p.marker_path).unwrap().status,
            Status::Complete
        );
    }

    #[tokio::test]
    async fn skip_done_does_not_refetch() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, _bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        let after_first = store.gets();
        let (written, wire) = pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        assert_eq!((written, wire), (230, 0));
        assert_eq!(store.gets(), after_first, "skip-done must not re-fetch");
    }

    #[tokio::test]
    async fn resume_fetches_only_remaining_chunks() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let p = ShardPaths::new(out.path(), 1, "weights.bin");
        std::fs::create_dir_all(ShardPaths::state_dir(out.path())).unwrap();
        std::fs::write(&p.part_path, &bodies[0]).unwrap();
        ResumeMarker {
            version: crate::resume::MARKER_VERSION,
            merkle: shard.merkle.clone(),
            chunks_done: 1,
            bytes_done: bodies[0].len() as u64,
            status: Status::Partial,
        }
        .save(&p.marker_path)
        .unwrap();
        let (written, wire) = pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        assert_eq!(written, 230);
        assert_eq!(
            wire,
            (bodies[1].len() + bodies[2].len()) as u64,
            "only tail on the wire"
        );
        assert_eq!(store.gets(), 2, "chunk 0 already done → only 2 fetched");
        assert_eq!(
            std::fs::read(out.path().join("weights.bin")).unwrap(),
            bodies.concat()
        );
    }

    #[tokio::test]
    async fn stale_merkle_discards_part_and_refetches() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let p = ShardPaths::new(out.path(), 1, "weights.bin");
        std::fs::create_dir_all(ShardPaths::state_dir(out.path())).unwrap();
        std::fs::write(&p.part_path, b"garbage from another version").unwrap();
        ResumeMarker {
            version: crate::resume::MARKER_VERSION,
            merkle: "b3:0000000000000000000000000000000000000000000000000000000000000000".into(),
            chunks_done: 1,
            bytes_done: 999,
            status: Status::Partial,
        }
        .save(&p.marker_path)
        .unwrap();
        let (written, _wire) = pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        assert_eq!(written, 230);
        assert_eq!(store.gets(), 3, "stale .part → full re-fetch");
        assert_eq!(
            std::fs::read(out.path().join("weights.bin")).unwrap(),
            bodies.concat()
        );
    }

    #[tokio::test]
    async fn torn_write_is_truncated_then_resumed() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let p = ShardPaths::new(out.path(), 1, "weights.bin");
        std::fs::create_dir_all(ShardPaths::state_dir(out.path())).unwrap();
        let mut torn = bodies[0].clone();
        torn.extend_from_slice(b"torn-partial-write");
        std::fs::write(&p.part_path, &torn).unwrap();
        ResumeMarker {
            version: crate::resume::MARKER_VERSION,
            merkle: shard.merkle.clone(),
            chunks_done: 1,
            bytes_done: bodies[0].len() as u64,
            status: Status::Partial,
        }
        .save(&p.marker_path)
        .unwrap();
        let (written, _wire) = pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        assert_eq!(written, 230);
        assert_eq!(
            std::fs::read(out.path().join("weights.bin")).unwrap(),
            bodies.concat(),
            "torn tail truncated, file reassembles correctly"
        );
    }

    #[tokio::test]
    async fn reverify_ignores_complete_marker() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, _bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        let after_first = store.gets();
        pull_shard(&store, &shard, out.path(), None, 1, 1, true, &|_| {})
            .await
            .unwrap();
        assert!(store.gets() > after_first, "reverify must re-fetch");
    }

    #[tokio::test]
    async fn ordered_assembly_with_concurrency() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let (written, _w) = pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        assert_eq!(written, 230);
        assert_eq!(
            std::fs::read(out.path().join("weights.bin")).unwrap(),
            bodies.concat(),
            "buffered(C) preserves chunk order"
        );
    }

    #[tokio::test]
    async fn stale_marker_with_missing_part_restarts_clean() {
        // Simulates a crash after rename→final but before the Complete marker:
        // the marker still says Partial/all-done, but .part no longer exists.
        // The shard must restart cleanly and produce the REAL bytes, never a
        // zero-padded file.
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let p = ShardPaths::new(out.path(), 1, "weights.bin");
        std::fs::create_dir_all(ShardPaths::state_dir(out.path())).unwrap();
        // Marker claims everything done; NO .part file written.
        ResumeMarker {
            version: crate::resume::MARKER_VERSION,
            merkle: shard.merkle.clone(),
            chunks_done: 3,
            bytes_done: 230,
            status: Status::Partial,
        }
        .save(&p.marker_path)
        .unwrap();
        let (written, _wire) = pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        assert_eq!(written, 230);
        assert_eq!(
            std::fs::read(out.path().join("weights.bin")).unwrap(),
            bodies.concat(),
            "must not zero-pad; clean restart produces correct bytes"
        );
    }

    #[test]
    fn sanitize_rel_path_strips_traversal() {
        assert_eq!(sanitize_rel_path("../../etc/passwd"), "etc/passwd");
        assert_eq!(sanitize_rel_path("/abs/x.json"), "abs/x.json");
        assert_eq!(sanitize_rel_path("sub/dir/file.json"), "sub/dir/file.json");
        assert_eq!(sanitize_rel_path("./a/./b"), "a/b");
    }

    #[test]
    fn shard_output_name_prefers_path_else_role_format() {
        let with_path = Shard {
            role: "aux".into(),
            format: "json".into(),
            path: Some("generation_config.json".into()),
            parts: Some(1),
            size: 1,
            merkle: String::new(),
            chunks: vec![],
        };
        assert_eq!(shard_output_name(&with_path), "generation_config.json");
        let legacy = Shard {
            role: "config".into(),
            format: "json".into(),
            path: None,
            parts: Some(1),
            size: 1,
            merkle: String::new(),
            chunks: vec![],
        };
        assert_eq!(shard_output_name(&legacy), "config.json");
    }

    /// Two shards with the SAME (role, format) — which `shard_filename` would
    /// collide onto one name — but distinct `path` write to distinct files with
    /// no rename race/error (the bug that made gpt2/phi-2 unpullable).
    #[tokio::test]
    async fn colliding_role_format_writes_distinct_files_via_path() {
        let store = concord_core::store::MemoryStore::new();
        let b1 = vec![1u8; 40];
        let b2 = vec![2u8; 50];
        let h1 = ChunkHash::of(b1.as_slice());
        let h2 = ChunkHash::of(b2.as_slice());
        store
            .put_chunk(&h1, bytes::Bytes::from(b1.clone()))
            .await
            .unwrap();
        store
            .put_chunk(&h2, bytes::Bytes::from(b2.clone()))
            .await
            .unwrap();
        let mk = |path: &str, sz: u64, h: &ChunkHash| Shard {
            role: "aux".into(),
            format: "json".into(),
            path: Some(path.into()),
            parts: Some(1),
            size: sz,
            merkle: shard_merkle(std::slice::from_ref(h)).to_string(),
            chunks: vec![h.to_string()],
        };
        let s1 = mk("config.json", 40, &h1);
        let s2 = mk("generation_config.json", 50, &h2);
        let out = tempfile::tempdir().unwrap();
        pull_shard(&store, &s1, out.path(), None, 1, 2, false, &|_| {})
            .await
            .unwrap();
        pull_shard(&store, &s2, out.path(), None, 2, 2, false, &|_| {})
            .await
            .unwrap();
        assert_eq!(std::fs::read(out.path().join("config.json")).unwrap(), b1);
        assert_eq!(
            std::fs::read(out.path().join("generation_config.json")).unwrap(),
            b2
        );
    }

    #[tokio::test]
    async fn path_with_subdir_creates_parent() {
        let store = concord_core::store::MemoryStore::new();
        let body = vec![7u8; 64];
        let h = ChunkHash::of(body.as_slice());
        store
            .put_chunk(&h, bytes::Bytes::from(body.clone()))
            .await
            .unwrap();
        let s = Shard {
            role: "weights".into(),
            format: "safetensors".into(),
            path: Some("nested/dir/model.safetensors".into()),
            parts: Some(1),
            size: 64,
            merkle: shard_merkle(std::slice::from_ref(&h)).to_string(),
            chunks: vec![h.to_string()],
        };
        let out = tempfile::tempdir().unwrap();
        pull_shard(&store, &s, out.path(), None, 1, 1, false, &|_| {})
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(out.path().join("nested/dir/model.safetensors")).unwrap(),
            body
        );
    }
}
