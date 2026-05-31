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

/// Parsed model reference: `<name>:<version>`. A bare `<name>` is rejected
/// (versioning channels — e.g. `latest` — are still an open RFC issue).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRef {
    pub name: String,
    pub version: String,
}

impl ModelRef {
    /// Parse `name:version`. Splits on the last `:` so `org/name:v1` works
    /// and a name containing a `:` (it shouldn't, but) still parses
    /// against the rightmost colon.
    pub fn parse(s: &str) -> Result<Self> {
        match s.rsplit_once(':') {
            Some((name, version)) if !name.is_empty() && !version.is_empty() => Ok(Self {
                name: name.to_string(),
                version: version.to_string(),
            }),
            _ => bail!(
                "ref must be `<name>:<version>` — bare names aren't supported (no version channels yet)"
            ),
        }
    }
}

/// Per-file accounting reported back to the caller for the human summary.
#[derive(Clone, Copy, Debug, Default)]
pub struct PullStats {
    pub files: u64,
    pub bytes: u64,
}

/// Pull a manifest from `store`, verify its signature with `pubkey`, then
/// reassemble each shard into `args.out_dir`. Returns the manifest +
/// per-shard byte stats so the caller can print a summary.
///
/// File naming: each shard becomes a file named by its role + format
/// (`weights.safetensors`, `tokenizer.json`, …). This is good enough for
/// the phase-0 demo where each shard maps 1:1 to a source file; phase 1+
/// will carry the original filenames in the manifest.
pub async fn pull<S: Store + ?Sized>(
    store: &S,
    args: &PullArgs,
    pubkey: &VerifyingKey,
) -> Result<(Manifest, PullStats)> {
    let raw = store
        .get_manifest(&args.name, &args.version)
        .await
        .map_err(|e| anyhow!("get manifest {}:{}: {e}", args.name, args.version))?;
    let manifest = Manifest::parse(&raw).context("parse manifest")?;
    sign::verify(&manifest, pubkey).map_err(|e| anyhow!("verify signature: {e}"))?;

    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("mkdir -p {}", args.out_dir.display()))?;

    let mut stats = PullStats::default();
    for shard in &manifest.shards {
        let bytes_written = pull_shard(store, shard, &args.out_dir).await?;
        stats.files += 1;
        stats.bytes += bytes_written;
    }

    Ok((manifest, stats))
}

/// Fetch all chunks for `shard`, verify the merkle root matches the
/// manifest's claim, and write the reassembled bytes to disk.
async fn pull_shard<S: Store + ?Sized>(store: &S, shard: &Shard, out_dir: &Path) -> Result<u64> {
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
    let mut body: Vec<u8> = Vec::with_capacity(shard.size as usize);
    for h in &chunk_hashes {
        let bytes = store
            .get_chunk(h)
            .await
            .map_err(|e| anyhow!("get chunk {h}: {e}"))?;
        let got = ChunkHash::of(&bytes);
        if got.to_string() != h.to_string() {
            bail!("chunk {h} content hash mismatch: got {got}");
        }
        body.extend_from_slice(&bytes);
    }

    let filename = shard_filename(shard);
    let path = out_dir.join(&filename);
    std::fs::write(&path, &body).with_context(|| format!("write {}", path.display()))?;

    Ok(body.len() as u64)
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
    fn modelref_requires_version() {
        assert!(ModelRef::parse("only-name").is_err());
        assert!(ModelRef::parse("name:").is_err());
        assert!(ModelRef::parse(":v1").is_err());
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
        let n = pull_shard(&store, &shard, dir.path()).await.unwrap();
        assert_eq!(n, 230);
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
        assert!(pull_shard(&store, &shard, dir.path()).await.is_err());
    }
}
