//! Concord core — protocol types for the Concordfaces federated model registry.
//!
//! Reference implementation of [RFC 0001](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md).
//! This crate is **not** the operator-side serving code (that lives in a
//! separate, proprietary repo). Everything here is published Apache-2.0 so
//! third parties can build compatible clients or operators.
//!
//! Layering note: this crate's [`chunker`] is the *protocol* layer — fixed
//! 4 MiB blake3 chunks, content-addressed for dedup + idempotent uploads.
//! It is orthogonal to whatever the operator's S3 backend does internally
//! for placement and erasure coding (OpenVerve, for example, performs its
//! own EC 4+2 split under the hood). The two layers do not know about each
//! other.

#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

pub mod chunker;

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
