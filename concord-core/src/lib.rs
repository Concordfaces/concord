//! Concord core — protocol types for the Concordfaces federated model registry.
//!
//! This crate is the implementation reference for [RFC 0001](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md).
//! It is **not** the operator-side serving code (proprietary, separate repo).
//! Everything here is published as Apache-2.0 so any party can build a
//! compatible client or a compatible operator implementation.
//!
//! Currently this crate exposes only protocol constants and stub types.
//! The chunker, manifest parser, signer, and verifier land in upcoming
//! commits per the RFC.

#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

/// Protocol-contract version this crate implements.
pub const PROTOCOL_VERSION: &str = "concord/1";

/// Fixed chunk boundary, in bytes (RFC 0001 §Chunking).
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Allowed residency tokens (RFC 0001 §Manifest grammar).
pub const RESIDENCY_TOKENS: &[&str] = &["eu", "na", "sa", "af", "as", "oc", "any"];

/// Allowed shard roles. Unrecognised roles MUST be ignored by clients.
pub const SHARD_ROLES: &[&str] = &["weights", "tokenizer", "config", "adapter", "quant", "aux"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_constant_matches_rfc() {
        assert_eq!(PROTOCOL_VERSION, "concord/1");
    }

    #[test]
    fn chunk_size_is_four_mib() {
        assert_eq!(CHUNK_SIZE, 4_194_304);
    }
}
