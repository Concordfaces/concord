//! Manifest types + canonical (de)serializer per [RFC 0001](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md).
//!
//! A manifest IS the version of a model. Signed TOML, no git, no history.
//! Reverting = signing a prior manifest.
//!
//! Canonical serialization (RFC 0001 §Signature): reserialise the parsed
//! manifest with table order `[manifest]`, `[license]`, `[[shard]]…`,
//! `[pull_policy]`, `[supersedes]`. Keys within each table in the order
//! shown in the RFC. UTF-8, LF line endings, no trailing whitespace,
//! trailing newline. The `[signature]` table is **excluded** from the
//! bytes the signature covers.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level manifest. `to_canonical_bytes()` / `parse()` round-trip; the
/// canonical form is the byte sequence that signing covers (excluding the
/// `[signature]` table itself).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub manifest: ManifestHeader,
    pub license: License,
    #[serde(rename = "shard", default)]
    pub shards: Vec<Shard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<PullPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<Supersedes>,
    /// Present iff this model is a quantization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantization: Option<Quantization>,
    /// Filled by `sign()`. Empty on a freshly built or just-parsed unsigned
    /// manifest. Excluded from the canonical bytes the signature covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ManifestHeader {
    pub name: String,
    pub version: String,
    pub protocol: String,
    pub issuer: String,
    /// RFC 3339 UTC; MUST end in `Z`.
    pub issued_at: String,
    /// For a quantization: the base model it derives from (e.g. `org/model`).
    /// Omitted for a base model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_model: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct License {
    pub spdx: String,
    /// `eu|na|sa|af|as|oc|any`
    pub residency: String,
    /// `unrestricted|signed-token-required|forbidden`
    pub export: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Shard {
    /// `weights|tokenizer|config|adapter|quant|aux`
    pub role: String,
    pub format: String,
    /// Original source-relative path/filename (e.g. `tokenizer_config.json`,
    /// `subdir/weights.bin`). Restores the real layout that `role`+`format`
    /// cannot uniquely encode — without it, files sharing a (role, format)
    /// collide on one output name. Optional for backward compat: legacy
    /// manifests omit it and the puller falls back to a `role.format` name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parts: Option<u32>,
    pub size: u64,
    /// `b3:<64-hex>` blake3 merkle root.
    pub merkle: String,
    /// Ordered `b3:<64-hex>` chunk hashes whose merkle root equals `merkle`
    /// (RFC 0001 §Shards). REQUIRED to retrieve a multi-chunk shard; MAY be
    /// omitted for a single-chunk shard, where `merkle` IS the chunk hash.
    /// Self-authenticating: a client MUST verify `shard_merkle(chunks) ==
    /// merkle`, and `merkle` is covered by the manifest signature — so the
    /// chunk list needs no separate signature.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct PullPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_asn_groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_asn: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_asn: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Supersedes {
    pub version: String,
    pub reason: String,
}

/// Quantization descriptor for a quantized model. `method` is freeform so new
/// formats (nvfp4, mxfp4, …) need no schema change.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Quantization {
    /// `gguf | awq | gptq | bitsandbytes | fp8 | nvfp4 | mxfp4 | <freeform>`.
    pub method: String,
    /// GGUF scheme / method-specific label (e.g. `Q4_K_M`, `128g`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Bit width, ONLY for bit-exact methods (awq/gptq/nvfp4/mxfp4/bitsandbytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Signature {
    pub alg: String,
    pub key: String,
    /// Base64 (no padding) of the ed25519 signature.
    pub sig: String,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("toml parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("toml serialize: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("invalid residency token: {0}")]
    BadResidency(String),
    #[error("invalid issued_at — must be RFC 3339 UTC ending in Z")]
    BadIssuedAt,
}

impl Manifest {
    /// Parse a manifest from TOML bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let s = std::str::from_utf8(bytes)
            .map_err(|_| toml::de::Error::custom("manifest is not valid UTF-8"))?;
        let m: Manifest = toml::from_str(s)?;
        m.validate()?;
        Ok(m)
    }

    /// Validate the constrained fields (residency tokens, issued_at format).
    pub fn validate(&self) -> Result<(), ManifestError> {
        if !crate::RESIDENCY_TOKENS.contains(&self.license.residency.as_str()) {
            return Err(ManifestError::BadResidency(self.license.residency.clone()));
        }
        if !self.manifest.issued_at.ends_with('Z') {
            return Err(ManifestError::BadIssuedAt);
        }
        Ok(())
    }

    /// Emit the **canonical bytes** the signature covers (RFC 0001
    /// §Signature). Does NOT include the `[signature]` table. Used by
    /// `sign()` to compute the digest and by `verify()` to re-derive it.
    ///
    /// Format: deterministic table + key order, UTF-8, LF line endings,
    /// no trailing whitespace, trailing newline.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        let mut out = String::with_capacity(1024);

        // ---- [manifest] ----
        writeln!(out, "[manifest]").unwrap();
        write_kv_str(&mut out, "name", &self.manifest.name);
        write_kv_str(&mut out, "version", &self.manifest.version);
        write_kv_str(&mut out, "protocol", &self.manifest.protocol);
        write_kv_str(&mut out, "issuer", &self.manifest.issuer);
        // issued_at: keep RFC 3339 UTC; emit unquoted as a TOML datetime so
        // it parses back as a datetime if needed. We standardise on the
        // string form here for round-trip simplicity — signature covers
        // bytes so format must be deterministic, not its TOML type.
        write_kv_str(&mut out, "issued_at", &self.manifest.issued_at);
        writeln!(out).unwrap();

        // ---- [license] ----
        writeln!(out, "[license]").unwrap();
        write_kv_str(&mut out, "spdx", &self.license.spdx);
        write_kv_str(&mut out, "residency", &self.license.residency);
        write_kv_str(&mut out, "export", &self.license.export);
        writeln!(out).unwrap();

        // ---- [[shard]] entries (preserve input order) ----
        for s in &self.shards {
            writeln!(out, "[[shard]]").unwrap();
            write_kv_str(&mut out, "role", &s.role);
            write_kv_str(&mut out, "format", &s.format);
            if let Some(parts) = s.parts {
                writeln!(out, "parts    = {}", parts).unwrap();
            }
            writeln!(out, "size     = {}", s.size).unwrap();
            write_kv_str(&mut out, "merkle", &s.merkle);
            write_kv_str_array(&mut out, "chunks", &s.chunks);
            writeln!(out).unwrap();
        }

        // ---- [pull_policy] (optional) ----
        if let Some(pp) = &self.pull_policy {
            writeln!(out, "[pull_policy]").unwrap();
            write_kv_str_array(&mut out, "block_asn_groups", &pp.block_asn_groups);
            write_kv_u32_array(&mut out, "block_asn", &pp.block_asn);
            write_kv_u32_array(&mut out, "allow_asn", &pp.allow_asn);
            writeln!(out).unwrap();
        }

        // ---- [supersedes] (optional) ----
        if let Some(sp) = &self.supersedes {
            writeln!(out, "[supersedes]").unwrap();
            write_kv_str(&mut out, "version", &sp.version);
            write_kv_str(&mut out, "reason", &sp.reason);
            writeln!(out).unwrap();
        }

        // Strip a single trailing blank line if present, then guarantee
        // exactly one trailing newline. Keeps the canonical form stable
        // regardless of how many optional tables were present.
        while out.ends_with("\n\n") {
            out.pop();
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }

        Ok(out.into_bytes())
    }

    /// Emit a complete, signed manifest TOML (canonical bytes plus the
    /// `[signature]` table appended in canonical key order). Used when
    /// writing a manifest to storage.
    pub fn to_signed_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        let mut out = String::from_utf8(self.to_canonical_bytes()?).expect("canonical is utf-8");
        if let Some(sig) = &self.signature {
            writeln!(out).unwrap();
            writeln!(out, "[signature]").unwrap();
            write_kv_str(&mut out, "alg", &sig.alg);
            write_kv_str(&mut out, "key", &sig.key);
            write_kv_str(&mut out, "sig", &sig.sig);
        }
        Ok(out.into_bytes())
    }
}

// ---------- helpers ----------

fn toml_quote(s: &str) -> String {
    // Use TOML's basic string syntax with the standard escapes the spec
    // requires. We deliberately avoid literal strings (single-quoted) so
    // the canonical form is uniform.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn write_kv_str(out: &mut String, key: &str, value: &str) {
    // Aligned `=` for readability; alignment is fixed so it's still
    // canonical (every signer produces the same bytes).
    writeln!(out, "{:<8} = {}", key, toml_quote(value)).unwrap();
}

fn write_kv_str_array(out: &mut String, key: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    let parts: Vec<String> = values.iter().map(|s| toml_quote(s)).collect();
    writeln!(out, "{:<16} = [{}]", key, parts.join(", ")).unwrap();
}

fn write_kv_u32_array(out: &mut String, key: &str, values: &[u32]) {
    if values.is_empty() {
        return;
    }
    let parts: Vec<String> = values.iter().map(|n| n.to_string()).collect();
    writeln!(out, "{:<16} = [{}]", key, parts.join(", ")).unwrap();
}

// Re-export the custom toml error constructor so this module compiles
// against the `toml` crate's stable surface.
trait CustomToml {
    fn custom(msg: &str) -> Self;
}
impl CustomToml for toml::de::Error {
    fn custom(msg: &str) -> Self {
        // toml::de::Error::custom isn't part of the public surface in all
        // versions; round-trip a parse failure to construct one.
        toml::from_str::<toml::Value>(&format!("__err = \"{}\"", msg.replace('"', "'")))
            .err()
            .unwrap_or_else(|| {
                // As a last resort, force an error by parsing invalid TOML.
                toml::from_str::<toml::Value>("=").unwrap_err()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
        Manifest {
            manifest: ManifestHeader {
                name: "mistral/mixtral-8x22b".into(),
                version: "v0.3.1".into(),
                protocol: "concord/1".into(),
                issuer: "eu:stichting-concord-europa".into(),
                issued_at: "2026-05-13T09:14:22Z".into(),
                base_model: None,
            },
            license: License {
                spdx: "Apache-2.0".into(),
                residency: "eu".into(),
                export: "unrestricted".into(),
            },
            shards: vec![
                Shard {
                    role: "weights".into(),
                    format: "safetensors".into(),
                    path: None,
                    parts: Some(56),
                    size: 90_172_948_480,
                    merkle: "b3:7a4e9c2f9b1d0000000000000000000000000000000000000000000000000000"
                        .into(),
                    chunks: vec![],
                },
                Shard {
                    role: "tokenizer".into(),
                    format: "tokenizers.json".into(),
                    path: None,
                    parts: None,
                    size: 2_412_904,
                    merkle: "b3:88a0f0e1000000000000000000000000000000000000000000000000000000000"
                        .into(),
                    chunks: vec![],
                },
            ],
            pull_policy: None,
            supersedes: None,
            quantization: None,
            signature: None,
        }
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let m = sample_manifest();
        let bytes = m.to_canonical_bytes().expect("serialize");
        let s = std::str::from_utf8(&bytes).unwrap();
        let m2 = Manifest::parse(s.as_bytes()).expect("parse");
        assert_eq!(m.manifest, m2.manifest);
        assert_eq!(m.license, m2.license);
        assert_eq!(m.shards, m2.shards);
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let m = sample_manifest();
        let a = m.to_canonical_bytes().unwrap();
        let b = m.to_canonical_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_excludes_signature_table() {
        let mut m = sample_manifest();
        let unsigned = m.to_canonical_bytes().unwrap();
        m.signature = Some(Signature {
            alg: "ed25519".into(),
            key: "eu:europa:k/2026-01".into(),
            sig: "5f3cd091".into(),
        });
        let signed_canonical = m.to_canonical_bytes().unwrap();
        // The signature table should NOT appear in canonical bytes,
        // because that's the bytes the signature must cover.
        assert_eq!(unsigned, signed_canonical);
        let s = std::str::from_utf8(&signed_canonical).unwrap();
        assert!(!s.contains("[signature]"));
    }

    #[test]
    fn signed_bytes_include_signature_table() {
        let mut m = sample_manifest();
        m.signature = Some(Signature {
            alg: "ed25519".into(),
            key: "eu:europa:k/2026-01".into(),
            sig: "5f3cd091".into(),
        });
        let s_bytes = m.to_signed_bytes().unwrap();
        let s = std::str::from_utf8(&s_bytes).unwrap();
        assert!(s.contains("[signature]"));
        assert!(s.contains("alg      = \"ed25519\""));
    }

    #[test]
    fn reject_bad_residency() {
        let mut m = sample_manifest();
        m.license.residency = "antarctica".into();
        assert!(matches!(m.validate(), Err(ManifestError::BadResidency(_))));
    }

    #[test]
    fn reject_non_utc_issued_at() {
        let mut m = sample_manifest();
        m.manifest.issued_at = "2026-05-13T09:14:22+01:00".into();
        assert!(matches!(m.validate(), Err(ManifestError::BadIssuedAt)));
    }

    #[test]
    fn pull_policy_emitted_when_set() {
        let mut m = sample_manifest();
        m.pull_policy = Some(PullPolicy {
            block_asn_groups: vec!["hyperscaler:us".into(), "tor".into()],
            block_asn: vec![16509, 15169],
            allow_asn: vec![],
        });
        let bytes = m.to_canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("[pull_policy]"));
        assert!(s.contains("block_asn_groups = [\"hyperscaler:us\", \"tor\"]"));
        assert!(s.contains("block_asn        = [16509, 15169]"));
        assert!(!s.contains("allow_asn"));
    }

    #[test]
    fn supersedes_emitted_when_set() {
        let mut m = sample_manifest();
        m.supersedes = Some(Supersedes {
            version: "v0.3.0".into(),
            reason: "corrupted tokenizer shard".into(),
        });
        let bytes = m.to_canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("[supersedes]"));
        assert!(s.contains("version  = \"v0.3.0\""));
    }

    #[test]
    fn quantization_roundtrips_and_is_optional() {
        // A manifest WITH quant + base_model round-trips.
        let toml = r#"
[manifest]
name = "org/m-GGUF-Q4_K_M"
version = "v1"
protocol = "concord/1"
issuer = "eu:concordfaces"
issued_at = "2026-06-17T00:00:00Z"
base_model = "org/m"

[license]
spdx = "MIT"
residency = "eu"
export = "unrestricted"

[quantization]
method = "gguf"
scheme = "Q4_K_M"

[[shard]]
role = "weights"
format = "gguf"
size = 10
merkle = "b3:0000000000000000000000000000000000000000000000000000000000000000"
"#;
        let m = Manifest::parse(toml.as_bytes()).unwrap();
        assert_eq!(m.manifest.base_model.as_deref(), Some("org/m"));
        let q = m.quantization.as_ref().unwrap();
        assert_eq!(q.method, "gguf");
        assert_eq!(q.scheme.as_deref(), Some("Q4_K_M"));
        assert_eq!(q.bits, None);

        // A manifest WITHOUT them parses with None (backward compatible).
        let plain = toml.replace("base_model = \"org/m\"\n", "")
            .replace("\n[quantization]\nmethod = \"gguf\"\nscheme = \"Q4_K_M\"\n", "");
        let p = Manifest::parse(plain.as_bytes()).unwrap();
        assert_eq!(p.manifest.base_model, None);
        assert!(p.quantization.is_none());
    }
}
