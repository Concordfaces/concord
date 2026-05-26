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
    // We don't actually have the per-chunk hash list in the manifest
    // (RFC 0001 only carries the merkle root); for the phase-0 single-
    // chunk-per-file fixtures this happens to coincide — root == chunk.
    // For multi-chunk shards we'd need a sidecar chunk index. Surface
    // that limitation explicitly rather than silently producing junk.
    if shard.parts.unwrap_or(1) > 1 {
        bail!(
            "shard {} has {} chunks; multi-chunk pull needs a chunk-index sidecar (tracked in RFC 0001 open issues)",
            shard.role,
            shard.parts.unwrap_or(1)
        );
    }

    // Single-chunk shard: the merkle root IS the chunk hash.
    let hash: ChunkHash = shard
        .merkle
        .parse()
        .with_context(|| format!("parse shard merkle: {}", shard.merkle))?;

    let body = store
        .get_chunk(&hash)
        .await
        .map_err(|e| anyhow!("get chunk {hash}: {e}"))?;

    // Sanity check: re-derive the merkle from the fetched bytes' chunk
    // hash, verify it matches what the manifest claims.
    let recomputed = shard_merkle(&[ChunkHash::of(&body)]);
    if recomputed.to_string() != shard.merkle {
        bail!(
            "shard {} merkle mismatch after reassembly: manifest={} actual={}",
            shard.role,
            shard.merkle,
            recomputed
        );
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
}
