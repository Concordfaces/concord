//! ed25519 signing + verification of manifests per [RFC 0001 §Signature](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md#signature).
//!
//! The signature covers [`Manifest::to_canonical_bytes`] — the deterministic
//! byte sequence with the `[signature]` table excluded. Sign once with a
//! publisher's ed25519 key, ship the manifest + signature, verify with the
//! publisher's pubkey.
//!
//! Encoding for the `sig` field in the manifest's `[signature]` table is
//! **base64 standard, no padding** (RFC 4648 §4 without `=` padding). The
//! `key` field is an operator-namespaced key id like `eu:europa:k/2026-01`;
//! key id → public-key lookup is the caller's responsibility (operator KMS
//! in production, hard-coded for phase 0 demo).

use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

use crate::manifest::{Manifest, ManifestError, Signature};

#[derive(Debug, Error)]
pub enum SignError {
    #[error("serialize manifest: {0}")]
    Serialize(#[from] ManifestError),
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("serialize manifest: {0}")]
    Serialize(#[from] ManifestError),
    #[error("manifest has no [signature] table")]
    Missing,
    #[error("unsupported signature algorithm: {0}")]
    BadAlg(String),
    #[error("base64 decode of sig: {0}")]
    BadBase64(#[from] base64::DecodeError),
    #[error("signature is {0} bytes; ed25519 expects 64")]
    BadSigLen(usize),
    #[error("signature verification failed")]
    BadSignature,
}

/// Sign a manifest in place. Returns the manifest with `[signature]`
/// populated using the supplied signing key under the given operator key
/// id (e.g. `eu:europa:k/2026-01`).
pub fn sign(mut manifest: Manifest, key_id: &str, sk: &SigningKey) -> Result<Manifest, SignError> {
    let bytes = manifest.to_canonical_bytes()?;
    let sig: EdSignature = sk.sign(&bytes);
    manifest.signature = Some(Signature {
        alg: "ed25519".to_string(),
        key: key_id.to_string(),
        sig: B64.encode(sig.to_bytes()),
    });
    Ok(manifest)
}

/// Verify a manifest's `[signature]` against the supplied public key.
///
/// The caller is responsible for mapping `manifest.signature.key` (the
/// operator-namespaced key id) to the right `VerifyingKey`. This function
/// only does the cryptographic check.
pub fn verify(manifest: &Manifest, pk: &VerifyingKey) -> Result<(), VerifyError> {
    let sig = manifest.signature.as_ref().ok_or(VerifyError::Missing)?;
    if sig.alg != "ed25519" {
        return Err(VerifyError::BadAlg(sig.alg.clone()));
    }

    let sig_bytes = B64.decode(sig.sig.as_bytes())?;
    if sig_bytes.len() != 64 {
        return Err(VerifyError::BadSigLen(sig_bytes.len()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let ed_sig = EdSignature::from_bytes(&arr);

    let canonical = manifest.to_canonical_bytes()?;
    pk.verify(&canonical, &ed_sig)
        .map_err(|_| VerifyError::BadSignature)
}

/// Generate a fresh ed25519 keypair. Useful for tests + the phase-0
/// demo CLI. Production code should mint keys via the operator KMS,
/// never inline.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    use ed25519_dalek::SECRET_KEY_LENGTH;
    use rand_core::{OsRng, TryRngCore};

    let mut seed = [0u8; SECRET_KEY_LENGTH];
    OsRng.try_fill_bytes(&mut seed).expect("OsRng");
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{License, Manifest, ManifestHeader, Shard};

    fn sample() -> Manifest {
        Manifest {
            manifest: ManifestHeader {
                name: "test/model".into(),
                version: "v1.0.0".into(),
                protocol: "concord/1".into(),
                issuer: "eu:test-operator".into(),
                issued_at: "2026-01-01T00:00:00Z".into(),
            },
            license: License {
                spdx: "Apache-2.0".into(),
                residency: "eu".into(),
                export: "unrestricted".into(),
            },
            shards: vec![Shard {
                role: "weights".into(),
                format: "safetensors".into(),
                parts: None,
                size: 1234,
                merkle: "b3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .into(),
                chunks: vec![],
            }],
            pull_policy: None,
            supersedes: None,
            signature: None,
        }
    }

    #[test]
    fn sign_then_verify_ok() {
        let (sk, vk) = generate_keypair();
        let signed = sign(sample(), "eu:test-operator:k/2026-01", &sk).unwrap();
        assert!(signed.signature.is_some());
        verify(&signed, &vk).expect("verify must succeed");
    }

    #[test]
    fn verify_fails_with_wrong_pubkey() {
        let (sk, _) = generate_keypair();
        let (_, other_vk) = generate_keypair();
        let signed = sign(sample(), "eu:test-operator:k/2026-01", &sk).unwrap();
        assert!(matches!(
            verify(&signed, &other_vk),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn verify_fails_when_canonical_changes() {
        let (sk, vk) = generate_keypair();
        let mut signed = sign(sample(), "eu:test-operator:k/2026-01", &sk).unwrap();
        // Tamper with the version — canonical bytes change, sig no longer valid.
        signed.manifest.version = "v1.0.1-tampered".into();
        assert!(matches!(
            verify(&signed, &vk),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn verify_missing_signature_errors() {
        let (_, vk) = generate_keypair();
        let unsigned = sample();
        assert!(matches!(verify(&unsigned, &vk), Err(VerifyError::Missing)));
    }

    #[test]
    fn verify_rejects_unsupported_alg() {
        let (sk, vk) = generate_keypair();
        let mut signed = sign(sample(), "eu:test-operator:k/2026-01", &sk).unwrap();
        signed.signature.as_mut().unwrap().alg = "rsa-pkcs1-sha256".into();
        assert!(matches!(verify(&signed, &vk), Err(VerifyError::BadAlg(_))));
    }

    #[test]
    fn signed_roundtrip_through_toml() {
        // Sign, serialize to bytes, parse back, verify. Proves the
        // canonical bytes are stable across serialize/parse cycles.
        let (sk, vk) = generate_keypair();
        let signed = sign(sample(), "eu:test-operator:k/2026-01", &sk).unwrap();
        let signed_bytes = signed.to_signed_bytes().unwrap();
        let reparsed = Manifest::parse(&signed_bytes).unwrap();
        verify(&reparsed, &vk).expect("roundtrip verify");
    }
}
