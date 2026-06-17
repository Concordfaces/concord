# Quantization metadata — Design (Spec 1 of 3: foundation)

**Date:** 2026-06-17
**Status:** design

## Context

Concordfaces should represent model **quantizations** (GGUF Q4_K_M, AWQ, GPTQ,
bitsandbytes int8/int4, fp8, **NVFP4**, MXFP4, …), full and **HuggingFace-compatible**.

Chosen model (brainstorm): a quantization is a **separate, pullable model linked
to its base** — how HF represents it (a derived repo with a `base_model`
relation + `quantization_config`). It is storage-optimal: Concordfaces dedups at
the chunk/content level **globally** (`chunks/<blake3>`, push HEAD-skips
existing), so files a base and its quants share byte-for-byte (tokenizer.json,
config.json, vocab) are **stored once** automatically regardless of manifest
shape; quantized weights are unique bytes that never dedup either way.
Separate-linked therefore costs no extra storage and **reuses the existing
per-model push/pull unchanged** — a GGUF/AWQ repo already pushes + pulls
correctly now that the manifest carries per-file `path`.

**Quantization is a push-time declaration: one pushed model = one quantization.**
`--quant` is authoritative; auto-derivation handles only single, unambiguous
signals. A source repo bundling several schemes (e.g. a GGUF repo with
`Q4_K_M` + `Q8_0`) is pushed as **separate quant models** (`org/model-GGUF-Q4_K_M`,
`org/model-GGUF-Q8_0`), each `--quant gguf:Q4_K_M`, all sharing one
`--base-model`. No multi-scheme-per-manifest logic.

This spec is the **data foundation in the `concord` repo only** (manifest +
push). Two follow-on specs build on it:
- **Spec 2 — CLI quant UX:** `concord pull <base> --quant <q>` resolution +
  `concord quants <model>` listing.
- **Spec 3 — catalogue + models page (shfaces):** `concord_catalogue.models`
  gains `base_model`/`quant_method`/`quant_scheme`; `catalog_sync` + `/api/models`
  populate/expose them; the models page groups quants under their base and adds
  a Quantization facet. (Nothing consumes the catalogue field before this spec,
  so it lives here, not in Spec 1.)

## Goal

Carry quantization metadata in the signed manifest and have `push` record it.
No pull/UI/catalogue changes here. Fully backward-compatible: every field is
optional; existing manifests and non-quantized models are unaffected (a `None`
field is omitted from `to_canonical_bytes`, so already-signed manifests still
verify and re-signing one without a quant is byte-identical).

## Manifest schema (concord-core)

Two optional additions, both covered by the signature (they serialize into
`to_canonical_bytes`, which excludes only `[signature]`):

```toml
[manifest]
# … existing fields …
base_model = "zai-org/GLM-5.2"   # the model this is a quantization of; omitted for a base model

[quantization]                    # omitted entirely for an unquantized model
method = "nvfp4"                  # gguf | awq | gptq | bitsandbytes | fp8 | nvfp4 | mxfp4 | compressed-tensors | <freeform>
scheme = "Q4_K_M"                 # optional; GGUF scheme / method-specific label
bits   = 4                        # optional; ONLY for bit-exact methods (awq/gptq/nvfp4/mxfp4/bitsandbytes)
```

Rust (`concord-core/src/manifest.rs`):
- `ManifestHeader` gains `#[serde(default, skip_serializing_if = "Option::is_none")] pub base_model: Option<String>`.
- New `pub struct Quantization { pub method: String, #[serde(default, skip_serializing_if="Option::is_none")] pub scheme: Option<String>, #[serde(default, skip_serializing_if="Option::is_none")] pub bits: Option<u8> }` — derives `Clone, Debug, Serialize, Deserialize, PartialEq` (matching the other manifest structs).
- `Manifest` gains `#[serde(default, skip_serializing_if = "Option::is_none")] pub quantization: Option<Quantization>`.

`method` is intentionally **freeform** so emerging formats (NVFP4, MXFP4, future
ones) need no schema change. NVFP4/MXFP4 are named in the examples + tested so
they're first-class, not "other".

## `push` population (concord-cli)

Quantization is declared at push, in priority order:

1. **Flags (authoritative):**
   - `--base-model <name>` → `[manifest].base_model`.
   - `--quant <method[:scheme][/bits]>` → `Quantization`. Examples:
     `gguf:Q4_K_M`, `awq/4`, `gptq:128g/4`, `bitsandbytes/8`, `nvfp4/4`, `mxfp4/4`,
     `fp8`. Parsed by a pure `parse_quant(&str) -> Result<Quantization>`:
     split off `/<bits>` (a trailing `/N`), then `<method>:<scheme>` on the first
     `:`; `method` is required (empty → error with the format).
2. **Auto-derive only when `--quant` is absent, single unambiguous signal:**
   - Exactly one `*.gguf` file in the dir → `method="gguf"`, `scheme` from
     `*.<SCHEME>.gguf` (e.g. `model.Q4_K_M.gguf` → `Q4_K_M`); **no `bits`**
     (GGUF schemes aren't bit-exact). Multiple `.gguf` files → leave unset (the
     pusher must declare via `--quant`, or push per-scheme).
   - Else `config.json` has `quantization_config` → `method = quant_method`,
     `bits` = its `bits`/`w_bit` when an integer is present (bit-exact methods).
   - `--base-model` absent → `base_model` from `config.json.base_model` if present.
   - No signal → manifest omits quantization (it's a base model).
3. A flag always overrides auto-derivation. `push` prints the resolved
   `base_model` + `quantization` in its summary.

(Deliberately NOT auto-derived: NVFP4/MXFP4 from compressed-tensors/modelopt
internals, and `base_model` from README front-matter — both fragile. The
publisher passes `--quant nvfp4/4` / `--base-model` instead.)

## Error handling

- Unknown/freeform `method` accepted verbatim (don't gate emerging formats).
- `--quant` with no method → hard error stating the accepted format.
- Auto-derivation is best-effort: a parse failure logs a warning and leaves the
  field unset, never fails the push.
- A `base_model` not present in the catalogue is allowed — the link is advisory;
  resolution is Spec 2's concern.

## Testing (TDD)

`concord-core`:
- manifest roundtrip: serialize→parse preserves `base_model` + `[quantization]`;
  a manifest without them parses with `None`; a signed manifest with the fields
  verifies (they're in the canonical bytes); re-signing a manifest that has
  neither field yields byte-identical canonical bytes (backward compat).
- `Quantization` serde: `scheme`/`bits` omitted when `None`.

`concord-cli` (push):
- `parse_quant` pure unit tests: `gguf:Q4_K_M` → `{gguf, Q4_K_M, None}`;
  `awq/4` → `{awq, None, 4}`; `gptq:128g/4` → `{gptq, "128g", 4}`;
  `nvfp4/4` → `{nvfp4, None, 4}`; `mxfp4/4` → `{mxfp4, None, 4}`; `fp8` →
  `{fp8, None, None}`; empty/no-method → error.
- auto-derive: dir with one `model.Q5_K_M.gguf` → `{gguf, Q5_K_M, None}`;
  `config.json` with `quantization_config.quant_method="awq", bits=4` →
  `{awq, None, 4}`; `config.json.base_model="X"` → header `base_model="X"`.
- `--quant`/`--base-model` flags override auto-derive.
- plain (non-quant) dir → both fields unset.
- multiple `.gguf` files + no `--quant` → quantization unset (no guess).

## Out of scope (later specs)

- `concord pull <base> --quant` resolution + `concord quants` (Spec 2).
- Catalogue columns, `/api/models` exposure, models-page grouping + Quantization
  facet (Spec 3, shfaces).
- Validating/auto-linking that `base_model` exists.
- Server-side / on-demand quantization (rejected — lossy, non-HF).
- Multi-scheme-per-manifest (rejected — push per-scheme as separate models).
