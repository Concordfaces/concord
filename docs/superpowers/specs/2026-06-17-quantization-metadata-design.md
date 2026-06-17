# Quantization metadata — Design (Spec 1 of 3: foundation)

**Date:** 2026-06-17
**Status:** design

## Context

Concordfaces should represent model **quantizations** (GGUF Q4_K_M, AWQ, GPTQ,
bitsandbytes int8/int4, fp8, …), full and **HuggingFace-compatible**.

Chosen model (see brainstorm): a quantization is a **separate, pullable model
linked to its base** — exactly how HF represents it (a derived repo with a
`base_model` relation + `quantization_config`). This is also storage-optimal:
Concordfaces dedups at the chunk/content level **globally** (`chunks/<blake3>`,
push HEAD-skips existing), so the files a base model and all its quants share
byte-for-byte (tokenizer.json, config.json, vocab, merges) are **stored once**
automatically, regardless of manifest shape; quantized weights are unique bytes
that never dedup either way. Separate-linked therefore costs no extra storage
and reuses the existing per-model push/pull unchanged (a GGUF/AWQ repo already
pushes + pulls correctly now that the manifest carries per-file `path`).

This spec is the **data foundation** only. Two follow-on specs build on it:
- **Spec 2 — CLI quant UX:** `concord pull <base> --quant <q>` resolution +
  `concord quants <model>` listing.
- **Spec 3 — models page UI:** group quants under their base + a Quantization
  facet (extends the existing license/status faceting).

## Goal

Carry quantization metadata end-to-end in the **data layer**: the signed
manifest, what `push` records, and the catalogue the site reads — so later specs
can resolve, list, group, and filter quantizations. No CLI pull/UI behaviour
changes here. Fully backward-compatible: every field is optional; existing
manifests and non-quantized models are unaffected.

## Manifest schema (concord-core)

Two optional additions, both covered by the signature (they serialize into
`to_canonical_bytes`, which already excludes only `[signature]`):

```toml
[manifest]
# … existing fields …
base_model = "zai-org/GLM-5.2"   # the model this is a quantization of; omitted for a base model

[quantization]                    # omitted entirely for an unquantized model
method = "nvfp4"                  # gguf | awq | gptq | bitsandbytes | fp8 | nvfp4 | mxfp4 | compressed-tensors | <other>
scheme = "Q4_K_M"                 # optional; GGUF scheme or method-specific label
bits   = 4                        # optional; integer bit width when meaningful
```

**NVFP4 is first-class.** NVFP4 (NVIDIA 4-bit float, E2M1 + FP8 block scales —
the Blackwell-era format) is a primary target alongside GGUF/AWQ/GPTQ. It is
represented as `method = "nvfp4"`, `bits = 4` (sibling FP4 format `mxfp4` —
the OCP microscaling variant — likewise `method = "mxfp4"`, `bits = 4`). The
`method` field is intentionally freeform so emerging formats need no schema
change; nvfp4/mxfp4 are named here so push derivation + tests cover them
explicitly rather than treating them as "other".

Rust:
- `ManifestHeader` gains `#[serde(default, skip_serializing_if = "Option::is_none")] pub base_model: Option<String>`.
- New `pub struct Quantization { pub method: String, #[serde(default, skip_serializing_if=Option::is_none)] pub scheme: Option<String>, #[serde(default, skip_serializing_if=Option::is_none)] pub bits: Option<u8> }`.
- `Manifest` gains `#[serde(default, skip_serializing_if = "Option::is_none")] pub quantization: Option<Quantization>`.

Derives match existing manifest structs (Clone, Debug, Serialize, Deserialize,
PartialEq). Legacy manifests parse with both `None` (serde default).

## `push` population (concord-cli)

`push` records quantization metadata, in priority order:

1. **Explicit CLI flags (authoritative):**
   - `--base-model <name>` sets `[manifest].base_model`.
   - `--quant <method[:scheme][/bits]>` e.g. `gguf:Q4_K_M`, `awq/4`, `gptq:128g/4`,
     `bitsandbytes/8`. Parsed into `Quantization{method, scheme, bits}`.
2. **Auto-derive from the source dir when flags are absent:**
   - If any `*.gguf` file: `method = "gguf"`, `scheme` from the filename
     (`*.<SCHEME>.gguf`, e.g. `model.Q4_K_M.gguf` → `Q4_K_M`); `bits` parsed from
     the scheme digit when present (`Q4…` → 4).
   - Else if `config.json` has `quantization_config`: `method = quant_method`
     (`awq`/`gptq`/`bitsandbytes`/`fp8`/…), `bits` = its `bits`/`w_bit` when present.
   - **FP4 formats:** NVFP4/MXFP4 ship via ModelOpt / compressed-tensors /
     llm-compressor, where `quantization_config.quant_method` is often
     `"modelopt"` or `"compressed-tensors"` with an FP4 weight format. Map a
     detected NVFP4 weight format → `method="nvfp4", bits=4` (MXFP4 → `mxfp4`),
     rather than the wrapper method name, so the catalogue/UI label the actual
     format. Fall back to the raw `quant_method` if the FP4 variant is ambiguous.
   - `base_model`: `config.json.base_model`, else the README front-matter
     `base_model:` (first entry), else unset.
3. If neither flag nor signal yields quantization, the manifest omits it (base
   model).

A `--quant`/`--base-model` flag always overrides auto-derivation. Push prints
the resolved `base_model` + `quantization` in its summary.

## Catalogue (shfaces)

The catalogue carries the same metadata so the site can group/filter without
re-reading manifests:

- `concord_catalogue.models` schema (`tools/catalog_sync.py`) gains
  `base_model text, quant_method text, quant_scheme text`.
- `catalog_sync.py` populates them from each model's manifest (it already has
  per-repo data; it reads the pushed manifest or the source list). For models
  added via `launch_models.json`, allow optional `base_model` / `quant` keys per
  entry; otherwise null.
- `catalog.rs` (`/api/models`) SELECT + `ModelRow` add `base_model`,
  `quant_method`, `quant_scheme` (all `Option`), serialized into the JSON so the
  models page (Spec 3) can consume them. Null/absent for base + legacy rows.

## Error handling

- Unknown/freeform `method` is accepted verbatim (HF invents methods; don't gate).
- Malformed `--quant` (no method) → hard error with the accepted format.
- Auto-derivation is best-effort: any parse failure logs a warning and leaves
  the field unset rather than failing the push.
- A `base_model` that doesn't exist in the catalogue is allowed (the link is
  advisory; resolution/validation is Spec 2's concern).

## Testing (TDD)

concord-core:
- manifest roundtrip: serialize→parse preserves `base_model` + `[quantization]`;
  a manifest without them parses with `None`; signature verifies with the fields
  present (they're in the canonical bytes).
- `Quantization` serde: optional `scheme`/`bits` omitted when `None`.

concord-cli (push):
- `--quant gguf:Q4_K_M` → `{method:"gguf", scheme:"Q4_K_M", bits:Some(4)}`.
- `--quant awq/4` → `{method:"awq", scheme:None, bits:Some(4)}`.
- `--quant nvfp4/4` → `{method:"nvfp4", scheme:None, bits:Some(4)}`; `--quant mxfp4/4`
  likewise. Derivation: a compressed-tensors/modelopt `config.json` with an FP4
  weight format → `{method:"nvfp4", bits:Some(4)}`.
- auto-derive: a dir with `model.Q5_K_M.gguf` → gguf/Q5_K_M/5; a `config.json`
  with `quantization_config.quant_method="awq", bits=4` → awq/None/4.
- `--base-model X` sets the header; flag overrides auto-derive.
- a plain (non-quant) dir → both fields unset.
- `parse_quant(s)` pure fn unit-tested across the format variants + the
  malformed/no-method error.

catalogue (shfaces): `catalog_sync` writes the three columns; `/api/models`
returns them; a base/legacy row returns null — assert against a seeded row.

## Out of scope (later specs)

- `concord pull <base> --quant` resolution + `concord quants` (Spec 2).
- Models-page grouping under base + Quantization facet (Spec 3).
- Validating/enforcing that `base_model` exists, or auto-linking quants whose
  base isn't in the catalogue.
- Server-side / on-demand quantization (explicitly rejected — lossy, non-HF).
