//! Load an ed25519 signing or verifying key from disk in one of the
//! formats operators actually hand out: PKCS#8 PEM (what `openssl genpkey`
//! and the operator KMS export) or 64-hex raw seed (what tests use).

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

/// Load an ed25519 signing key from `path`. Accepts PKCS#8 PEM **or**
/// 64-hex raw seed (32-byte ed25519 seed, hex-encoded, with optional
/// `ed25519:` prefix and surrounding whitespace).
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("read key {}", path.display()))?;

    if raw.contains("BEGIN PRIVATE KEY") || raw.contains("BEGIN ED25519 PRIVATE KEY") {
        return SigningKey::from_pkcs8_pem(&raw).map_err(|e| anyhow!("parse PKCS#8 PEM key: {e}"));
    }

    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix("ed25519:").unwrap_or(trimmed);
    if trimmed.len() != SECRET_KEY_LENGTH * 2 {
        bail!(
            "expected PKCS#8 PEM or {} hex chars (32-byte ed25519 seed); got {} chars",
            SECRET_KEY_LENGTH * 2,
            trimmed.len()
        );
    }
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    hex::decode_to_slice(trimmed, &mut seed).context("invalid hex in signing key")?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Parse a 32-byte ed25519 verifying key from a hex string. Accepts an
/// optional `ed25519:` prefix.
pub fn parse_pubkey_hex(s: &str) -> Result<VerifyingKey> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_hex_seed() {
        // Deterministic seed → known signing key.
        let seed = [7u8; 32];
        let hex_seed = hex::encode(seed);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("key.hex");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "{}", hex_seed).unwrap();

        let sk = load_signing_key(&p).unwrap();
        assert_eq!(sk.to_bytes(), seed);
    }

    #[test]
    fn load_hex_seed_with_prefix() {
        let seed = [9u8; 32];
        let hex_seed = format!("ed25519:{}", hex::encode(seed));
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("key.hex");
        std::fs::write(&p, hex_seed).unwrap();

        let sk = load_signing_key(&p).unwrap();
        assert_eq!(sk.to_bytes(), seed);
    }

    #[test]
    fn load_rejects_short_hex() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        std::fs::write(&p, "deadbeef").unwrap();
        assert!(load_signing_key(&p).is_err());
    }

    #[test]
    fn parse_pubkey_hex_roundtrips() {
        let bytes = [3u8; 32];
        let s = hex::encode(bytes);
        let vk = parse_pubkey_hex(&s).unwrap();
        assert_eq!(vk.to_bytes(), bytes);
    }

    #[test]
    fn parse_pubkey_hex_rejects_garbage() {
        assert!(parse_pubkey_hex("xx").is_err());
        assert!(parse_pubkey_hex("zz".repeat(32).as_str()).is_err());
    }
}
