//! `concord` — CLI for the Concordfaces federated model registry.
//!
//! See [RFC 0001](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md)
//! for the protocol this CLI speaks.

use std::fs;
use std::path::PathBuf;

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use concord_cli::key::{load_signing_key, parse_pubkey_hex};
use concord_cli::pull::{self, ModelRef, PullArgs};
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

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Pull a model version from an operator's CDN.
    ///
    /// Pulls hit the public CDN (chunks.eu.concordfaces.org) directly:
    /// no SigV4, no operator API hop, cache-friendly. Verifies the
    /// manifest signature with `--pubkey` before reassembling chunks.
    Pull {
        /// Model reference, e.g. `mistral/mixtral-8x22b:v0.3.1`.
        target: String,
        /// Output directory. Defaults to a subdir of `cwd` named after the model.
        #[arg(long)]
        out: Option<PathBuf>,
        /// 32-byte ed25519 public key (hex). Required to verify the manifest.
        #[arg(long)]
        pubkey: String,
        /// CDN base URL. The default targets the Concordfaces phase-0 EU
        /// operator; override for self-hosting or local tests.
        #[arg(
            long = "cdn-endpoint",
            default_value = "https://chunks.eu.concordfaces.org"
        )]
        cdn_endpoint: String,
        /// Bucket name underneath the CDN base. Matches the operator's
        /// `[store].bucket` setting; phase-0 default is `concord`.
        #[arg(long = "cdn-bucket", default_value = "concord")]
        cdn_bucket: String,
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
            cdn_bucket,
        } => {
            let model = ModelRef::parse(&target)?;
            let out_dir = out.unwrap_or_else(|| PathBuf::from(model.name.replace('/', "_")));
            let pk = parse_pubkey_hex(&pubkey).context("parse --pubkey")?;
            let cdn = concord_cli::cdn::CdnStore::new(cdn_endpoint, cdn_bucket)
                .map_err(|e| anyhow!("build CDN store: {e}"))?;
            let (manifest, stats) = pull::pull(
                &cdn,
                &PullArgs {
                    name: model.name.clone(),
                    version: model.version.clone(),
                    out_dir: out_dir.clone(),
                },
                &pk,
            )
            .await?;
            print_manifest_summary(&manifest);
            println!(
                "\npulled {} files / {} bytes → {}",
                stats.files,
                stats.bytes,
                out_dir.display()
            );
            println!("signature: OK");
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
            ManifestOp::Sign { path, key } => {
                tracing::info!(?path, ?key, "manifest sign not yet implemented");
                bail!("manifest sign not yet implemented");
            }
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
