# Quantization Metadata (Spec 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry quantization metadata in the signed manifest and have `concord push` record it (flag-declared, with simple auto-derive).

**Architecture:** Manifest gains an optional `[manifest].base_model` + an optional `[quantization]{method,scheme,bits}` table (both signed, both backward-compatible via serde defaults). `push` resolves them from `--quant`/`--base-model` flags (authoritative) or a single unambiguous source signal (one `.gguf` filename, or `config.json.quantization_config`/`base_model`).

**Tech Stack:** Rust, serde/toml, serde_json (config.json parsing — already a concord-cli dep), ed25519 signing (`sign.rs`).

**Spec:** `docs/superpowers/specs/2026-06-17-quantization-metadata-design.md`

---

## File Structure

- `concord-core/src/manifest.rs` — MODIFY: `Quantization` struct; `base_model` on `ManifestHeader`; `quantization` on `Manifest`.
- `concord-cli/src/push.rs` — MODIFY: `parse_quant`; `gguf_scheme`; `derive_quant`/`derive_base_model` from the model dir; `PushArgs` gains `base_model`/`quant`; wire into the manifest build.
- `concord-cli/src/main.rs` — MODIFY: `--base-model`/`--quant` flags on the `Push` subcommand → `PushArgs`.

---

## Task 1: Manifest schema

**Files:**
- Modify: `concord-core/src/manifest.rs`

- [ ] **Step 1: Write the failing test** — append to the `#[cfg(test)] mod tests` in `manifest.rs`:

```rust
    #[test]
    fn quantization_roundtrips_and_is_optional() {
        // A manifest WITH quant + base_model round-trips.
        let toml = r#"
[manifest]
name = "org/m-GGUF-Q4_K_M"
version = "v1"
protocol = "1.0"
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
```

- [ ] **Step 2: Run it — expect FAIL** (`base_model`/`quantization` fields don't exist).

Run: `cargo test -p concord-core --lib quantization_roundtrips_and_is_optional`
Expected: FAIL (no field `base_model` / `quantization`).

- [ ] **Step 3: Add the schema** — in `manifest.rs`, add `base_model` to `ManifestHeader` (after `issued_at`):

```rust
    /// RFC 3339 UTC; MUST end in `Z`.
    pub issued_at: String,
    /// For a quantization: the base model it derives from (e.g. `org/model`).
    /// Omitted for a base model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_model: Option<String>,
```

Add the `Quantization` struct (next to the other manifest structs, e.g. after `ManifestHeader`):

```rust
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
```

Add `quantization` to `Manifest` (after `supersedes`, before `signature`):

```rust
    /// Present iff this model is a quantization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantization: Option<Quantization>,
```

- [ ] **Step 4: Fix the compile breakage** — every `Manifest { … }` and `ManifestHeader { … }` literal now needs the new fields. Build the test target to list them:

Run: `cargo build -p concord-core --tests 2>&1 | grep -E "missing field|\.rs:[0-9]"`

For each `ManifestHeader { … }` literal, add `base_model: None,`. For each `Manifest { … }` literal, add `quantization: None,`. (At minimum: the literals already in `manifest.rs` tests + `sign.rs` tests.) Then also build `concord-cli`:

Run: `cargo build -p concord-cli --tests 2>&1 | grep -E "missing field|\.rs:[0-9]"`

Fix any `Manifest`/`ManifestHeader` literals in `concord-cli` (push.rs construction + its tests, verify_e2e.rs, pull.rs tests) by adding `base_model: None,` / `quantization: None,`. (The real push.rs construction is wired properly in Task 4 — for now add `base_model: None, quantization: None` to keep it compiling.)

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test --workspace 2>&1 | grep -E "test result:|error"`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add concord-core/src/manifest.rs concord-cli
git commit -m "feat(core): optional base_model + [quantization] in the manifest"
```

---

## Task 2: `parse_quant`

**Files:**
- Modify: `concord-cli/src/push.rs`

- [ ] **Step 1: Write the failing tests** — append to the `#[cfg(test)] mod tests` in `push.rs`:

```rust
    #[test]
    fn parse_quant_variants() {
        let p = |s: &str| super::parse_quant(s).unwrap();
        assert_eq!(p("gguf:Q4_K_M"), concord_core::manifest::Quantization {
            method: "gguf".into(), scheme: Some("Q4_K_M".into()), bits: None });
        assert_eq!(p("awq/4"), concord_core::manifest::Quantization {
            method: "awq".into(), scheme: None, bits: Some(4) });
        assert_eq!(p("gptq:128g/4"), concord_core::manifest::Quantization {
            method: "gptq".into(), scheme: Some("128g".into()), bits: Some(4) });
        assert_eq!(p("nvfp4/4"), concord_core::manifest::Quantization {
            method: "nvfp4".into(), scheme: None, bits: Some(4) });
        assert_eq!(p("fp8"), concord_core::manifest::Quantization {
            method: "fp8".into(), scheme: None, bits: None });
        assert!(super::parse_quant("").is_err());
        assert!(super::parse_quant("/4").is_err()); // no method
    }
```

- [ ] **Step 2: Run — expect FAIL** (`parse_quant` undefined).

Run: `cargo test -p concord-cli --lib parse_quant_variants`
Expected: FAIL.

- [ ] **Step 3: Implement** — add to `push.rs` (top-level fn; ensure `use concord_core::manifest::Quantization;` is in scope — it's re-exported from `manifest`):

```rust
use concord_core::manifest::Quantization;

/// Parse `--quant` as `method[:scheme][/bits]`, e.g. `gguf:Q4_K_M`, `awq/4`,
/// `gptq:128g/4`, `nvfp4/4`, `fp8`.
pub fn parse_quant(s: &str) -> Result<Quantization> {
    let (rest, bits) = match s.rsplit_once('/') {
        Some((r, b)) => (r, Some(b.parse::<u8>().with_context(|| format!("quant bits in {s:?}"))?)),
        None => (s, None),
    };
    let (method, scheme) = match rest.split_once(':') {
        Some((m, sc)) => (m, Some(sc.to_string())),
        None => (rest, None),
    };
    if method.is_empty() {
        bail!("--quant needs a method, e.g. gguf:Q4_K_M, awq/4, nvfp4/4");
    }
    Ok(Quantization { method: method.to_string(), scheme, bits })
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `cargo test -p concord-cli --lib parse_quant_variants`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add concord-cli/src/push.rs
git commit -m "feat(cli): parse_quant for the --quant descriptor"
```

---

## Task 3: Auto-derive from the model dir

**Files:**
- Modify: `concord-cli/src/push.rs`

- [ ] **Step 1: Write the failing tests** — append to `push.rs` tests (uses `tempfile`, already a dev-dep):

```rust
    #[test]
    fn gguf_scheme_from_filename() {
        assert_eq!(super::gguf_scheme("model.Q4_K_M.gguf").as_deref(), Some("Q4_K_M"));
        assert_eq!(super::gguf_scheme("foo.Q8_0.gguf").as_deref(), Some("Q8_0"));
        assert_eq!(super::gguf_scheme("model.gguf"), None); // no scheme segment
        assert_eq!(super::gguf_scheme("model.safetensors"), None);
    }

    #[test]
    fn derive_quant_from_dir() {
        // one .gguf → gguf + scheme, no bits.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("model.Q5_K_M.gguf"), b"x").unwrap();
        assert_eq!(super::derive_quant(d.path()).unwrap(),
            concord_core::manifest::Quantization { method: "gguf".into(), scheme: Some("Q5_K_M".into()), bits: None });

        // two .gguf → ambiguous → None.
        std::fs::write(d.path().join("model.Q8_0.gguf"), b"y").unwrap();
        assert!(super::derive_quant(d.path()).is_none());

        // config.json quantization_config → method + bits.
        let d2 = tempfile::tempdir().unwrap();
        std::fs::write(d2.path().join("config.json"),
            br#"{"quantization_config":{"quant_method":"awq","bits":4},"base_model":"org/base"}"#).unwrap();
        assert_eq!(super::derive_quant(d2.path()).unwrap(),
            concord_core::manifest::Quantization { method: "awq".into(), scheme: None, bits: Some(4) });
        assert_eq!(super::derive_base_model(d2.path()).as_deref(), Some("org/base"));

        // plain dir → no quant, no base.
        let d3 = tempfile::tempdir().unwrap();
        std::fs::write(d3.path().join("config.json"), br#"{"hidden_size":4}"#).unwrap();
        assert!(super::derive_quant(d3.path()).is_none());
        assert_eq!(super::derive_base_model(d3.path()), None);
    }
```

- [ ] **Step 2: Run — expect FAIL** (`gguf_scheme`/`derive_quant`/`derive_base_model` undefined).

Run: `cargo test -p concord-cli --lib gguf_scheme_from_filename derive_quant_from_dir`
Expected: FAIL.

- [ ] **Step 3: Implement** — add to `push.rs` (`serde_json` is a dep):

```rust
/// GGUF scheme from a `*.<SCHEME>.gguf` filename (e.g. `model.Q4_K_M.gguf` →
/// `Q4_K_M`). `None` when there's no scheme segment.
fn gguf_scheme(fname: &str) -> Option<String> {
    let stem = fname.strip_suffix(".gguf")?;
    stem.rsplit_once('.').map(|(_, sc)| sc.to_string())
}

/// Best-effort quantization from a single unambiguous source signal. `None` if
/// nothing clear (caller falls back to a base model). Never errors.
fn derive_quant(dir: &Path) -> Option<Quantization> {
    let ggufs: Vec<String> = std::fs::read_dir(dir).ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".gguf"))
        .collect();
    if ggufs.len() == 1 {
        return Some(Quantization { method: "gguf".into(), scheme: gguf_scheme(&ggufs[0]), bits: None });
    }
    if ggufs.len() > 1 {
        return None; // ambiguous — pusher must declare via --quant
    }
    let cfg = std::fs::read(dir.join("config.json")).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&cfg).ok()?;
    let qc = v.get("quantization_config")?;
    let method = qc.get("quant_method")?.as_str()?.to_string();
    let bits = qc.get("bits").or_else(|| qc.get("w_bit"))
        .and_then(|b| b.as_u64()).and_then(|b| u8::try_from(b).ok());
    Some(Quantization { method, scheme: None, bits })
}

/// Base model from `config.json.base_model`, when present.
fn derive_base_model(dir: &Path) -> Option<String> {
    let cfg = std::fs::read(dir.join("config.json")).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&cfg).ok()?;
    v.get("base_model")?.as_str().map(|s| s.to_string())
}
```

(`Path` is already imported in push.rs via `use std::path::{Path, PathBuf};`.)

- [ ] **Step 4: Run — expect PASS**

Run: `cargo test -p concord-cli --lib gguf_scheme_from_filename derive_quant_from_dir`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add concord-cli/src/push.rs
git commit -m "feat(cli): auto-derive quant + base_model from a model dir"
```

---

## Task 4: Wire flags + manifest population

**Files:**
- Modify: `concord-cli/src/push.rs`, `concord-cli/src/main.rs`

- [ ] **Step 1: Add fields to `PushArgs`** — in `push.rs`, extend the struct:

```rust
    /// RFC 3339 UTC timestamp ending in `Z`. `None` ⇒ `now`.
    pub issued_at: Option<String>,
    /// `--base-model`: the base this is a quantization of (authoritative).
    pub base_model: Option<String>,
    /// `--quant` descriptor (`method[:scheme][/bits]`), authoritative.
    pub quant: Option<String>,
```

- [ ] **Step 2: Resolve + set on the manifest** — in `push_with_progress`, just before `let unsigned = Manifest {`, resolve the values:

```rust
    // Quantization: flag authoritative, else a single unambiguous source signal.
    let quantization = match &args.quant {
        Some(s) => Some(parse_quant(s).context("parse --quant")?),
        None => derive_quant(&args.model_dir),
    };
    let base_model = args.base_model.clone().or_else(|| derive_base_model(&args.model_dir));
```

Then set them in the `Manifest`/`ManifestHeader` literal (replacing the placeholder `base_model: None`/`quantization: None` added in Task 1):

```rust
    let unsigned = Manifest {
        manifest: ManifestHeader {
            name: args.name.clone(),
            version: args.version.clone(),
            protocol: concord_core::PROTOCOL_VERSION.to_string(),
            issuer,
            issued_at,
            base_model,
        },
        license: License {
            spdx: args.license_spdx.clone(),
            residency: args.residency.clone(),
            export: "unrestricted".to_string(),
        },
        shards,
        pull_policy: None,
        supersedes: None,
        quantization,
        signature: None,
    };
```

- [ ] **Step 3: Add the CLI flags** — in `main.rs`, in the `Cmd::Push { … }` variant, add after `license`:

```rust
        /// Base model this is a quantization of, e.g. `zai-org/GLM-5.2`.
        #[arg(long = "base-model")]
        base_model: Option<String>,
        /// Quantization descriptor `method[:scheme][/bits]`, e.g. `gguf:Q4_K_M`,
        /// `awq/4`, `nvfp4/4`.
        #[arg(long)]
        quant: Option<String>,
```

In the `Cmd::Push { … } =>` match arm, add `base_model` + `quant` to the destructure, and to the `PushArgs { … }`:

```rust
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
```

- [ ] **Step 4: Update other `PushArgs { … }` literals** — push.rs tests + `tests/push_pull_e2e.rs` construct `PushArgs`; add `base_model: None, quant: None,` to each. Find them:

Run: `grep -rn "PushArgs {" concord-cli`
Add the two fields to every literal.

- [ ] **Step 5: Write the integration test** — append to `push.rs` tests (drives `push` against `MemoryStore`, then reads the manifest back and checks the fields). Model it on the existing `push_into_memory_store_roundtrip` test (reuse its store/key setup); the key assertions:

```rust
    #[tokio::test]
    async fn push_records_quant_and_base_model() {
        use concord_core::store::{MemoryStore, Store};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("model.Q4_K_M.gguf"), b"weights-bytes").unwrap();
        let store = MemoryStore::new();
        let sk = concord_core::sign::generate_keypair().0; // adapt to the real keygen used by other tests
        let args = PushArgs {
            model_dir: dir.path().to_path_buf(),
            name: "org/m-GGUF-Q4_K_M".into(),
            version: "v1".into(),
            key_id: "eu:concordfaces:k/test".into(),
            residency: "eu".into(),
            license_spdx: "MIT".into(),
            issued_at: Some("2026-06-17T00:00:00Z".into()),
            base_model: Some("org/m".into()),
            quant: None, // auto-derive from the .gguf
        };
        push(&store, &args, &sk).await.unwrap();
        let raw = store.get_manifest("org/m-GGUF-Q4_K_M", "v1").await.unwrap();
        let m = concord_core::manifest::Manifest::parse(&raw).unwrap();
        assert_eq!(m.manifest.base_model.as_deref(), Some("org/m"));
        let q = m.quantization.unwrap();
        assert_eq!(q.method, "gguf");
        assert_eq!(q.scheme.as_deref(), Some("Q4_K_M"));
    }
```

Adapt the keypair construction + `push(...)` signature to match the existing `push_into_memory_store_roundtrip` test in this file (do NOT invent APIs — copy its setup).

- [ ] **Step 6: Run the full gate**

Run: `cargo build -p concord-cli && cargo test --workspace 2>&1 | grep -E "test result:|error" && cargo clippy --workspace --all-targets -- -D warnings`
Expected: builds, all tests pass, clippy clean.

- [ ] **Step 7: Commit**

```bash
git add concord-cli/src/push.rs concord-cli/src/main.rs concord-cli/tests
git commit -m "feat(cli): --quant/--base-model flags populate manifest quantization"
```

---

## Self-Review

- **Spec coverage:** manifest `base_model` + `[quantization]{method,scheme,bits}` (T1) ✓; signature covers them + backward-compat None (T1 test) ✓; `--quant` parse incl. nvfp4/mxfp4/gptq/fp8 (T2) ✓; flags authoritative + auto-derive single-signal gguf/quantization_config/base_model, multi-gguf→unset, bits only bit-exact (T3/T4) ✓; push prints/sets them (T4) ✓; no catalogue/pull/UI (out of scope) ✓.
- **No placeholders:** all code shown; the only "adapt to existing setup" notes (T4 Step 5 keypair/push signature) explicitly defer to the file's real `push_into_memory_store_roundtrip` rather than inventing APIs.
- **Type consistency:** `Quantization{method:String, scheme:Option<String>, bits:Option<u8>}` used identically across T1–T4; `parse_quant`/`derive_quant`/`derive_base_model`/`gguf_scheme` signatures match their call sites; `PushArgs` gains `base_model:Option<String>, quant:Option<String>` everywhere.
