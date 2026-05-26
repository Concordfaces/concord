//! `concord` — CLI for the Concordfaces federated model registry.
//!
//! See [RFC 0001](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md)
//! for the protocol this CLI speaks.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use concord_core::manifest::Manifest;
use concord_core::sign;
use ed25519_dalek::{VerifyingKey, PUBLIC_KEY_LENGTH};
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
    /// Pull a model version from an operator.
    Pull {
        /// Model reference, e.g. `mistral/mixtral-8x22b:v0.3.1`.
        target: String,
    },
    /// Push a model version to an operator.
    Push {
        /// Path to the local model directory.
        path: PathBuf,
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
        Cmd::Pull { target } => {
            tracing::info!(%target, "pull not yet implemented");
            bail!("pull not yet implemented (lands once storage trait + S3 client are in)");
        }
        Cmd::Push { path } => {
            tracing::info!(?path, "push not yet implemented");
            bail!("push not yet implemented (lands once storage trait + S3 client are in)");
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

fn verify(path: &std::path::Path, pubkey_hex: &str) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read manifest {}", path.display()))?;
    let manifest = Manifest::parse(&bytes).context("parse manifest")?;
    let pk = parse_pubkey(pubkey_hex).context("parse --pubkey")?;
    sign::verify(&manifest, &pk).map_err(|e| anyhow!("signature verification failed: {e}"))?;
    print_summary(&manifest);
    println!("\nsignature: OK");
    Ok(())
}

fn parse_pubkey(s: &str) -> Result<VerifyingKey> {
    let s = s.strip_prefix("ed25519:").unwrap_or(s);
    if s.len() != PUBLIC_KEY_LENGTH * 2 {
        bail!(
            "expected {} hex chars (32-byte ed25519 pubkey), got {}",
            PUBLIC_KEY_LENGTH * 2,
            s.len()
        );
    }
    let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(s, &mut bytes).context("invalid hex")?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow!("invalid ed25519 pubkey: {e}"))
}

fn print_summary(m: &Manifest) {
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
