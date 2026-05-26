//! `concord` — CLI for the Concordfaces federated model registry.
//!
//! See [RFC 0001](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md)
//! for the protocol this CLI speaks.

use anyhow::Result;
use clap::{Parser, Subcommand};
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
        path: String,
    },
    /// Verify the signature of a manifest.
    Verify {
        /// Path to a manifest TOML file, or a model reference to fetch + verify.
        target: String,
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
        path: String,
        /// Path to the ed25519 signing key (PKCS#8 PEM or hex).
        #[arg(long)]
        key: String,
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
            anyhow::bail!(
                "pull not yet implemented (RFC 0001 client, landing in upcoming commits)"
            );
        }
        Cmd::Push { path } => {
            tracing::info!(%path, "push not yet implemented");
            anyhow::bail!("push not yet implemented");
        }
        Cmd::Verify { target } => {
            tracing::info!(%target, "verify not yet implemented");
            anyhow::bail!("verify not yet implemented");
        }
        Cmd::Manifest { op } => match op {
            ManifestOp::Sign { path, key } => {
                tracing::info!(%path, %key, "manifest sign not yet implemented");
                anyhow::bail!("manifest sign not yet implemented");
            }
        },
    }
}
