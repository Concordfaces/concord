# Concord

The official Rust CLI + core library for the [Concordfaces](https://concordfaces.org)
federated, sovereignty-respecting registry for machine-learning model artifacts.

> **Status: pre-alpha.** This repo holds the workspace scaffold for the
> phase-0 demo. Verbs are stubbed; chunker / manifest / signer / verifier
> land in upcoming commits implementing
> [RFC 0001 — Manifest format](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md).

## Workspace

| Crate                                | What it is                                                                 |
|--------------------------------------|----------------------------------------------------------------------------|
| [`concord-core`](concord-core/)      | Protocol types — chunker, manifest, signing, verification. `crates.io`.    |
| [`concord-cli`](concord-cli/)        | The `concord` binary — `pull`, `push`, `verify`, `manifest sign`.          |

## Install (planned)

```bash
# crates.io (Rust toolchain required)
cargo install concord-cli

# Pre-built binaries (linux, macOS, windows) — cargo-dist GitHub releases
curl -fsSL https://concordfaces.org/install.sh | sh
```

## Quick start (planned)

```bash
concord pull mistral/mixtral-8x22b:v0.3.1
concord verify mistral/mixtral-8x22b:v0.3.1
concord push ./my-model
concord manifest sign manifest.toml --key publisher.pem
```

## Building from source

```bash
cargo build --release
./target/release/concord --help
```

Requires Rust 1.80+.

## What is *not* in this repo

- **Operator-side serving binary** — proprietary, separate (not public).
  RFC 0001 is complete enough that a compliant operator implementation
  can be built independently.
- **SDK bindings for Python / Go** — separate repos when the binding
  API is stable.
- **Landing site** — [Concordfaces/concordfaces.org](https://github.com/Concordfaces/concordfaces.org).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
