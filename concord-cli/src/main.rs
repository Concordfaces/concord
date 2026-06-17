//! `concord` — CLI for the Concordfaces federated model registry.
//!
//! See [RFC 0001](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md)
//! for the protocol this CLI speaks.

use std::fs;
use std::path::PathBuf;

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use concord_cli::fmt::human_bytes;
use concord_cli::key::{load_signing_key, parse_pubkey_hex, resolve_issuer_key};
use concord_cli::pull::{self, ModelRef, PullArgs, PullEvent, PullProgress};
use concord_cli::push::{self, ProgressEvent, ProgressFn, PushArgs};
use concord_core::manifest::Manifest;
use concord_core::sign;
use concord_store_s3::{Credentials, S3Config, S3Store};
use indicatif::{ProgressBar, ProgressStyle};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "concord",
    version,
    about = "Concordfaces CLI — push / pull / verify / sign manifests against any Concord operator.",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

// Clap subcommand enums are stack-allocated only once at program startup; the
// large-variant size difference is inconsequential for a CLI binary.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Cmd {
    /// Pull a model version from an operator's CDN.
    ///
    /// Pulls hit the public CDN (chunks.eu.concordfaces.org) directly:
    /// no SigV4, no operator API hop, cache-friendly. The manifest
    /// signature is always verified before any chunk is written; the
    /// verifying key comes from `--pubkey` or, if omitted, the operator's
    /// published `.well-known/concord/keys.json` (resolved by issuer).
    /// Chunks are cached under `~/.cache/concord/chunks`, so a re-pull is
    /// served from disk (the reported dedup).
    Pull {
        /// Model reference, e.g. `mistral/mixtral-8x22b:v0.3.1`.
        target: String,
        /// Output directory. Defaults to a subdir of `cwd` named after the model.
        #[arg(long)]
        out: Option<PathBuf>,
        /// 32-byte ed25519 public key (hex) to verify the manifest. Optional:
        /// if omitted, the operator's key is resolved from the CDN's published
        /// `.well-known/concord/keys.json` by the manifest's issuer.
        #[arg(long)]
        pubkey: Option<String>,
        /// CDN base URL. The default targets the Concordfaces phase-0 EU
        /// operator; override for self-hosting or local tests. The
        /// operator's bucket prefix is wired into the CDN origin and is
        /// deliberately NOT exposed as a client-side flag — that would
        /// let a malicious client probe sibling buckets.
        #[arg(
            long = "cdn-endpoint",
            default_value = "https://chunks.eu.concordfaces.org"
        )]
        cdn_endpoint: String,
        /// Re-fetch and rebuild every shard from scratch, ignoring resume
        /// state and skip-done. Use if a local file is suspected corrupt.
        #[arg(long)]
        reverify: bool,
    },
    /// Push a model version to an operator.
    Push {
        /// Path to the local model directory.
        path: PathBuf,
        /// Manifest `[manifest].name`, e.g. `mistral/mixtral-8x22b`.
        #[arg(long)]
        name: String,
        /// Manifest `[manifest].version`, e.g. `v0.3.1`.
        #[arg(long)]
        version: String,
        /// Path to the ed25519 signing key (PKCS#8 PEM or 64-hex seed).
        #[arg(long)]
        key: PathBuf,
        /// Operator-namespaced key id, e.g. `eu:test-operator:k/2026-01`.
        #[arg(long)]
        key_id: String,
        /// Residency token (`eu|na|sa|af|as|oc|any`).
        #[arg(long, default_value = "eu")]
        residency: String,
        /// SPDX license identifier.
        #[arg(long, default_value = "Apache-2.0")]
        license: String,
        /// Base model this is a quantization of, e.g. `zai-org/GLM-5.2`.
        #[arg(long = "base-model")]
        base_model: Option<String>,
        /// Quantization descriptor `method[:scheme][/bits]`, e.g. `gguf:Q4_K_M`,
        /// `awq/4`, `nvfp4/4`.
        #[arg(long)]
        quant: Option<String>,
        #[command(flatten)]
        store: StoreFlags,
    },
    /// Verify the signature of a manifest TOML file.
    Verify {
        /// Path to a signed manifest TOML on disk.
        path: PathBuf,
        /// 32-byte ed25519 public key in hex (64 hex chars). Phase-0 demo
        /// passes the publisher's pubkey explicitly; phase 1+ resolves it
        /// via the operator KMS / federation gossip key bundle.
        #[arg(long)]
        pubkey: String,
    },
    /// Manifest authoring commands.
    Manifest {
        #[command(subcommand)]
        op: ManifestOp,
    },
}

/// Flags shared by `push` and `pull` for configuring the S3-compatible
/// backend the operator runs.
#[derive(clap::Args, Debug)]
struct StoreFlags {
    /// S3 endpoint root, e.g. `https://s3.example.org`.
    #[arg(long = "store-endpoint")]
    endpoint: String,
    /// Bucket name, e.g. `concord`.
    #[arg(long = "store-bucket")]
    bucket: String,
    /// AWS region string. CloudVerve accepts anything non-empty.
    #[arg(long = "store-region", default_value = "us-east-1")]
    region: String,
    /// SigV4 access key id. Falls back to `AWS_ACCESS_KEY_ID` env var.
    #[arg(long = "store-access-key")]
    access_key: Option<String>,
    /// SigV4 secret access key. Falls back to `AWS_SECRET_ACCESS_KEY` env var.
    #[arg(long = "store-secret-key")]
    secret_key: Option<String>,
}

impl StoreFlags {
    fn into_store(self) -> Result<S3Store> {
        let access_key = self
            .access_key
            .or_else(|| std::env::var("AWS_ACCESS_KEY_ID").ok())
            .ok_or_else(|| anyhow!("missing --store-access-key (or AWS_ACCESS_KEY_ID env var)"))?;
        let secret_key = self
            .secret_key
            .or_else(|| std::env::var("AWS_SECRET_ACCESS_KEY").ok())
            .ok_or_else(|| {
                anyhow!("missing --store-secret-key (or AWS_SECRET_ACCESS_KEY env var)")
            })?;
        let cfg = S3Config {
            endpoint: self.endpoint,
            bucket: self.bucket,
            region: self.region,
            credentials: Credentials {
                access_key_id: access_key,
                secret_access_key: secret_key,
            },
        };
        S3Store::new(cfg).map_err(|e| anyhow!("build S3 store: {e}"))
    }
}

#[derive(Subcommand, Debug)]
enum ManifestOp {
    /// Sign a manifest TOML file in place, producing a signed manifest envelope.
    Sign {
        /// Path to the manifest TOML.
        path: PathBuf,
        /// Path to the ed25519 signing key (PKCS#8 PEM or hex).
        #[arg(long)]
        key: PathBuf,
        /// Operator-namespaced key id for the `[signature]` table, e.g.
        /// `eu:concordfaces:k/2026-05`. If omitted, reuses the key id already
        /// in the manifest (re-signing in place).
        #[arg(long = "key-id")]
        key_id: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Pull {
            target,
            out,
            pubkey,
            cdn_endpoint,
            reverify,
        } => {
            let model = ModelRef::parse(&target)?;
            let out_dir = out.unwrap_or_else(|| PathBuf::from(model.name.replace('/', "_")));
            let cdn = concord_cli::cdn::CdnStore::new(cdn_endpoint)
                .map_err(|e| anyhow!("build CDN store: {e}"))?;
            let args = PullArgs {
                name: model.name.clone(),
                version: model.version.clone(),
                out_dir: out_dir.clone(),
                reverify,
            };

            // Resolve the verifying key. With --pubkey we trust the operator
            // supplied it out-of-band; without it we peek the (still
            // unverified) manifest for its issuer, then look that issuer up in
            // the operator's published keys. Either way the pull below
            // re-fetches and cryptographically verifies before writing bytes.
            let pk = match &pubkey {
                Some(hex) => parse_pubkey_hex(hex).context("parse --pubkey")?,
                None => resolve_pubkey_via_well_known(&cdn, &args).await?,
            };

            let progress = make_pull_progress();
            let (_manifest, stats) =
                pull::pull_with_progress(&cdn, &args, &pk, Some(progress)).await?;

            println!(
                "\n✓ {} · {} on the wire (dedup {:.1}%)",
                human_bytes(stats.bytes),
                human_bytes(stats.on_wire),
                stats.dedup_pct(),
            );
            println!(
                "✓ residency: {} · {} files → {}",
                if stats.residency.is_empty() {
                    "unspecified"
                } else {
                    &stats.residency
                },
                stats.files,
                out_dir.display(),
            );
            Ok(())
        }
        Cmd::Push {
            path,
            name,
            version,
            key,
            key_id,
            residency,
            license,
            base_model,
            quant,
            store,
        } => {
            let sk = load_signing_key(&key).context("load --key")?;
            let s3 = store.into_store()?;
            let args = PushArgs {
                model_dir: path,
                name: name.clone(),
                version: version.clone(),
                key_id,
                residency,
                license_spdx: license,
                issued_at: None,
                base_model,
                quant,
            };
            let progress = make_push_progress();
            let (manifest, _bytes, stats) =
                push::push_with_progress(&s3, &args, &sk, Some(progress)).await?;
            print_manifest_summary(&manifest);
            println!(
                "\nuploaded {}/{} chunks ({} bytes); skipped {} chunks ({} bytes saved by dedup)",
                stats.chunks_uploaded,
                stats.chunks_total,
                stats.bytes_uploaded,
                stats.chunks_skipped,
                stats.bytes_skipped
            );
            println!("manifest → manifests/{}/{}.toml", name, version);
            Ok(())
        }
        Cmd::Verify { path, pubkey } => verify(&path, &pubkey),
        Cmd::Manifest { op } => match op {
            ManifestOp::Sign { path, key, key_id } => manifest_sign(&path, &key, key_id),
        },
    }
}

/// Build an indicatif-backed progress callback for `concord push`.
///
/// The bar is sized lazily on the `Plan` event so the first redraw shows the
/// real total, not 0/0. Uploaded bytes advance the bar; skipped (dedup-hit)
/// bytes don't — but the suffix counter still ticks so the user sees that
/// the work is being processed even when no bytes hit the wire.
fn make_push_progress() -> ProgressFn {
    let pb = Arc::new(ProgressBar::hidden());
    let pb_cb = Arc::clone(&pb);
    Arc::new(move |ev: ProgressEvent| match ev {
        ProgressEvent::Plan {
            total_bytes,
            total_chunks,
        } => {
            pb_cb.set_length(total_bytes);
            pb_cb.set_draw_target(indicatif::ProgressDrawTarget::stderr());
            let style = ProgressStyle::with_template(
                "{spinner} [{elapsed_precise}] [{wide_bar:.cyan/blue}] \
                 {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta}) {msg}",
            )
            .expect("progress template")
            .progress_chars("=>-");
            pb_cb.set_style(style);
            pb_cb.set_message(format!("0/{total_chunks} chunks"));
        }
        ProgressEvent::Uploaded { bytes } => {
            pb_cb.inc(bytes);
        }
        ProgressEvent::Skipped { bytes } => {
            pb_cb.inc(bytes);
            pb_cb.set_message("dedup hit");
        }
        ProgressEvent::Done => {
            pb_cb.finish_and_clear();
        }
    })
}

/// Resolve the operator verifying key from the CDN's published keys, using
/// the issuer named in the (as-yet unverified) manifest. The manifest is
/// re-fetched and verified by the pull itself, so reading the issuer here is
/// just a routing hint — a forged issuer can only point at a key that won't
/// verify the signature.
async fn resolve_pubkey_via_well_known(
    cdn: &concord_cli::cdn::CdnStore,
    args: &PullArgs,
) -> Result<ed25519_dalek::VerifyingKey> {
    use concord_core::store::Store;
    let raw = cdn
        .get_manifest(&args.name, &args.version)
        .await
        .map_err(|e| anyhow!("fetch manifest {}:{}: {e}", args.name, args.version))?;
    let manifest = Manifest::parse(&raw).context("parse manifest for issuer")?;
    let issuer = &manifest.manifest.issuer;
    eprintln!("resolving key for issuer {issuer:?} via .well-known/concord/keys.json");
    let keys = cdn.fetch_well_known_keys().await.map_err(|e| {
        anyhow!(
            "fetch .well-known/concord/keys.json: {e} \
            (pass --pubkey to verify against a key you already trust)"
        )
    })?;
    resolve_issuer_key(&keys, issuer)
}

/// Build a [`PullProgress`] that renders a HuggingFace-style header and one
/// live progress bar **per in-flight shard** (shards download concurrently),
/// keyed by shard index in a `MultiProgress`. Bars + the MultiProgress live
/// behind a mutex so the `Send + Sync` callback can mutate them from whichever
/// task fires the event.
fn make_pull_progress() -> PullProgress {
    use indicatif::MultiProgress;
    use std::collections::HashMap;
    use std::sync::Mutex;

    let mp = MultiProgress::new();
    let bars: Arc<Mutex<HashMap<usize, (ProgressBar, u64)>>> = Arc::new(Mutex::new(HashMap::new()));

    Arc::new(move |ev: PullEvent| match ev {
        PullEvent::Manifest {
            issuer,
            license,
            residency,
            shards,
        } => {
            let _ = mp.println(format!(
                "issuer    {issuer}  · signed ed25519\nlicense   {license}  · residency={residency}\nshards    {shards}"
            ));
        }
        PullEvent::ShardStart {
            idx,
            total,
            role,
            format,
            size,
            parts,
            resumed_chunks,
            resumed_bytes,
        } => {
            let pb = mp.add(ProgressBar::new(size));
            let style = ProgressStyle::with_template(
                "  {prefix} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta}) {msg}",
            )
            .expect("progress template")
            .progress_chars("=>-");
            pb.set_style(style);
            pb.set_prefix(format!("[{idx}/{total}] {role}.{format}"));
            // Start the bar at what's already on disk so resume doesn't replay.
            pb.set_position(resumed_bytes);
            if resumed_chunks > 0 {
                // Reset the rate/ETA clock so the resumed prefix (added to the
                // bar in ~0s) isn't counted as throughput — otherwise the speed
                // reads as an absurd spike (e.g. "2.74 TiB/s") on the first tick.
                pb.reset_elapsed();
                pb.set_message(format!(
                    "resumed {}",
                    concord_cli::fmt::human_bytes(resumed_bytes)
                ));
            } else if parts > 1 {
                pb.set_message(format!("{parts} parts"));
            }
            bars.lock().unwrap().insert(idx, (pb, resumed_bytes));
        }
        PullEvent::ChunkDone {
            idx,
            bytes,
            cache_hit,
        } => {
            if let Some((pb, _resumed)) = bars.lock().unwrap().get(&idx) {
                pb.inc(bytes);
                // Reflect the latest chunk's source — clear a stale "cache-hit"
                // once we're fetching over the wire (otherwise it sticks for the
                // whole shard after a single early cache hit).
                pb.set_message(if cache_hit { "cache-hit" } else { "" });
            }
        }
        PullEvent::ShardDone { idx, filename } => {
            let avg = bars.lock().unwrap().remove(&idx).map(|(pb, resumed)| {
                let transferred = pb.position().saturating_sub(resumed);
                let r = concord_cli::fmt::rate(transferred, pb.elapsed().as_secs_f64());
                pb.finish_and_clear();
                r
            });
            match avg {
                Some(speed) => {
                    let _ = mp.println(format!("  [{idx}] {filename}  ✓  avg {speed}"));
                }
                None => {
                    let _ = mp.println(format!("  [{idx}] {filename}  ✓"));
                }
            }
        }
    })
}

/// Sign (or re-sign) a manifest TOML in place. Adds/overwrites the
/// `[signature]` table using `key`; the key id is `key_id` or, when omitted,
/// the manifest's existing signature key (re-signing in place after an edit).
fn manifest_sign(
    path: &std::path::Path,
    key: &std::path::Path,
    key_id: Option<String>,
) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read manifest {}", path.display()))?;
    let manifest = Manifest::parse(&bytes).context("parse manifest")?;
    let sk = load_signing_key(key).context("load --key")?;
    let kid = key_id
        .or_else(|| manifest.signature.as_ref().map(|s| s.key.clone()))
        .ok_or_else(|| {
            anyhow!("--key-id required (manifest has no existing signature to reuse)")
        })?;
    let signed = sign::sign(manifest, &kid, &sk).map_err(|e| anyhow!("sign manifest: {e}"))?;
    let out = toml::to_string(&signed).context("serialize signed manifest")?;
    fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
    println!("signed {} (key_id {})", path.display(), kid);
    Ok(())
}

fn verify(path: &std::path::Path, pubkey_hex: &str) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read manifest {}", path.display()))?;
    let manifest = Manifest::parse(&bytes).context("parse manifest")?;
    let pk = parse_pubkey_hex(pubkey_hex).context("parse --pubkey")?;
    sign::verify(&manifest, &pk).map_err(|e| anyhow!("signature verification failed: {e}"))?;
    print_manifest_summary(&manifest);
    println!("\nsignature: OK");
    Ok(())
}

fn print_manifest_summary(m: &Manifest) {
    println!("manifest:");
    println!("  name      = {}", m.manifest.name);
    println!("  version   = {}", m.manifest.version);
    println!("  protocol  = {}", m.manifest.protocol);
    println!("  issuer    = {}", m.manifest.issuer);
    println!("  issued_at = {}", m.manifest.issued_at);
    println!("license:");
    println!(
        "  {} / residency={} / export={}",
        m.license.spdx, m.license.residency, m.license.export
    );
    println!("shards: {}", m.shards.len());
    for s in &m.shards {
        let parts = s
            .parts
            .map(|p| format!(", parts={}", p))
            .unwrap_or_default();
        println!(
            "  [{}] {} {}B{}  {}",
            s.role, s.format, s.size, parts, s.merkle
        );
    }
    if let Some(pp) = &m.pull_policy {
        println!("pull_policy:");
        if !pp.block_asn_groups.is_empty() {
            println!("  block_asn_groups = {:?}", pp.block_asn_groups);
        }
        if !pp.block_asn.is_empty() {
            println!("  block_asn = {:?}", pp.block_asn);
        }
        if !pp.allow_asn.is_empty() {
            println!("  allow_asn = {:?}", pp.allow_asn);
        }
    }
    if let Some(sp) = &m.supersedes {
        println!("supersedes: {} — {}", sp.version, sp.reason);
    }
    if let Some(sig) = &m.signature {
        println!("signature:");
        println!("  alg = {}", sig.alg);
        println!("  key = {}", sig.key);
    }
}
