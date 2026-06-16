# Resumable, Fault-Tolerant `concord pull` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `concord pull` retry transient CDN errors (no abort on a blip) and resume fast (skip completed shards, resume partial shards mid-stream) with O(chunk) memory.

**Architecture:** A dependency-free retry layer wraps each CDN GET in `cdn.rs`. A new `resume.rs` holds per-shard resume state under `<out_dir>/.concord/`. `pull_shard` streams chunks straight to `<out_dir>/.concord/<file>.part` (fsync before advancing the on-disk marker), fetches with bounded ordered look-ahead, and atomic-renames to the final path on completion. The renderer initializes each bar at the resumed offset.

**Tech Stack:** Rust, tokio, futures (`buffered`), reqwest, serde/serde_json, blake3 (`ChunkHash`), indicatif. All deps already in `concord-cli`/`concord-store-s3`.

**Spec:** `docs/superpowers/specs/2026-06-16-cli-downloader-resume-design.md`

---

## File Structure

- `concord-cli/src/cdn.rs` — MODIFY: add `RetryPolicy`, `is_transient`, `backoff`, `Attempt`, `retry`, `get_once`; rewrite `fetch` to retry + per-request timeout; add `policy` field.
- `concord-cli/src/resume.rs` — CREATE: `ResumeMarker`, `Status`, `ShardPaths`, atomic load/save.
- `concord-cli/src/lib.rs` — MODIFY: `pub mod resume;`.
- `concord-cli/src/pull.rs` — MODIFY: add `reverify` to `PullArgs`; add `resumed_chunks`/`resumed_bytes` to `PullEvent::ShardStart`; factor `resolve_chunk_hashes`; add `fetch_one_chunk`; rewrite `pull_shard` (streaming + skip-done + resume + ordered look-ahead); thread `total`/`reverify` through `download_shards`/`pull_with_progress`; env knobs `chunk_concurrency`/`commit_every`.
- `concord-cli/src/main.rs` — MODIFY: `--reverify` flag → `PullArgs.reverify`; renderer sets bar position to `resumed_bytes` and computes honest avg.

---

## Task 1: Retry decision helpers (`cdn.rs`)

**Files:**
- Modify: `concord-cli/src/cdn.rs`

- [ ] **Step 1: Write the failing tests** — append to the `tests` module in `cdn.rs`:

```rust
    #[test]
    fn is_transient_truth_table() {
        for s in [408u16, 429, 500, 502, 503, 504] {
            assert!(is_transient(s), "{s} should be transient");
        }
        for s in [200u16, 204, 301, 400, 403, 404, 410] {
            assert!(!is_transient(s), "{s} should NOT be transient");
        }
    }

    #[test]
    fn backoff_is_monotonic_capped_and_zero_for_zero_base() {
        use std::time::Duration;
        assert_eq!(backoff(0, Duration::ZERO), Duration::ZERO);
        let base = Duration::from_millis(250);
        let b0 = backoff(0, base);
        let b1 = backoff(1, base);
        let b2 = backoff(2, base);
        assert_eq!(b0, Duration::from_millis(250));
        assert_eq!(b1, Duration::from_millis(500));
        assert_eq!(b2, Duration::from_millis(1000));
        assert!(b1 > b0 && b2 > b1, "backoff must grow");
        // Capped at 30s regardless of attempt.
        assert!(backoff(20, base) <= Duration::from_millis(30_000));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p concord-cli --lib cdn::tests::is_transient_truth_table cdn::tests::backoff_`
Expected: FAIL — `cannot find function is_transient` / `backoff`.

- [ ] **Step 3: Implement the helpers** — add near the top of `cdn.rs` (after the `use` block, before `struct CdnStore`):

```rust
use std::time::Duration;

/// HTTP status codes worth retrying — transient server/overload signals.
pub(crate) fn is_transient(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Exponential backoff: `base * 2^attempt` (0-based), capped at 30s. A zero
/// base disables sleeping (used by tests to avoid real-time waits).
pub(crate) fn backoff(attempt: u32, base: Duration) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let factor = 1u64 << attempt.min(6); // cap the shift so we never overflow
    let ms = (base.as_millis() as u64).saturating_mul(factor);
    Duration::from_millis(ms.min(30_000))
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p concord-cli --lib cdn::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add concord-cli/src/cdn.rs
git commit -m "feat(cli): retry decision helpers (is_transient, backoff)"
```

---

## Task 2: `RetryPolicy` + generic `retry` loop (`cdn.rs`)

**Files:**
- Modify: `concord-cli/src/cdn.rs`

- [ ] **Step 1: Write the failing tests** — append to the `tests` module:

```rust
    fn no_sleep_policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            base: std::time::Duration::ZERO,
            http_timeout: std::time::Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn retry_succeeds_after_transient_failures() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let op = || {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n < 3 {
                    Attempt::Transient(format!("boom {n}"))
                } else {
                    Attempt::Ok(Bytes::from_static(b"ok"))
                }
            }
        };
        let out = retry(op, &no_sleep_policy(5)).await.unwrap();
        assert_eq!(out.as_ref(), b"ok");
        assert_eq!(calls.get(), 3, "two failures then success");
    }

    #[tokio::test]
    async fn retry_gives_up_after_max_attempts() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let op = || {
            calls.set(calls.get() + 1);
            async { Attempt::Transient("always".into()) }
        };
        let err = retry(op, &no_sleep_policy(3)).await.unwrap_err();
        assert!(matches!(err, StoreError::Backend(_)));
        assert_eq!(calls.get(), 3, "exactly max_attempts tries");
    }

    #[tokio::test]
    async fn retry_does_not_retry_not_found_or_permanent() {
        use std::cell::Cell;
        let nf_calls = Cell::new(0u32);
        let nf = || {
            nf_calls.set(nf_calls.get() + 1);
            async { Attempt::NotFound }
        };
        assert!(matches!(retry(nf, &no_sleep_policy(5)).await, Err(StoreError::NotFound)));
        assert_eq!(nf_calls.get(), 1, "NotFound is terminal — no retry");

        let p_calls = Cell::new(0u32);
        let p = || {
            p_calls.set(p_calls.get() + 1);
            async { Attempt::Permanent("403".into()) }
        };
        assert!(matches!(retry(p, &no_sleep_policy(5)).await, Err(StoreError::Backend(_))));
        assert_eq!(p_calls.get(), 1, "permanent is terminal — no retry");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p concord-cli --lib cdn::tests::retry_`
Expected: FAIL — `cannot find type RetryPolicy` / `Attempt` / `retry`.

- [ ] **Step 3: Implement** — add to `cdn.rs` (below the helpers from Task 1):

```rust
/// Retry/timeout policy for CDN fetches. Built from env with sane defaults.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base: Duration,
    pub http_timeout: Duration,
}

impl RetryPolicy {
    pub fn from_env() -> Self {
        Self {
            max_attempts: env_u64("CONCORD_MAX_RETRIES", 4).max(1) as u32,
            base: Duration::from_millis(env_u64("CONCORD_RETRY_BASE_MS", 250)),
            http_timeout: Duration::from_secs(env_u64("CONCORD_HTTP_TIMEOUT_SECS", 60).max(1)),
        }
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Outcome of one fetch attempt, classified for the retry loop.
pub(crate) enum Attempt {
    Ok(Bytes),
    NotFound,
    Transient(String),
    Permanent(String),
}

/// Drive `op` until it succeeds, hits a terminal outcome, or exhausts attempts.
/// Sleeps `backoff(attempt, base)` between transient failures.
pub(crate) async fn retry<F, Fut>(mut op: F, policy: &RetryPolicy) -> Result<Bytes, StoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Attempt>,
{
    let mut last = String::new();
    for attempt in 0..policy.max_attempts {
        match op().await {
            Attempt::Ok(b) => return Ok(b),
            Attempt::NotFound => return Err(StoreError::NotFound),
            Attempt::Permanent(m) => return Err(StoreError::Backend(m)),
            Attempt::Transient(m) => {
                last = m;
                if attempt + 1 < policy.max_attempts {
                    tokio::time::sleep(backoff(attempt, policy.base)).await;
                }
            }
        }
    }
    Err(StoreError::Backend(format!("exhausted retries: {last}")))
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p concord-cli --lib cdn::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add concord-cli/src/cdn.rs
git commit -m "feat(cli): RetryPolicy + generic dependency-free retry loop"
```

---

## Task 3: Wire `fetch` through `get_once` + retry + timeout (`cdn.rs`)

**Files:**
- Modify: `concord-cli/src/cdn.rs`

- [ ] **Step 1: Add the `policy` field + classify GET** — change the `CdnStore` struct to add a field and rewrite `fetch`. Replace the struct definition's fields:

```rust
#[derive(Debug, Clone)]
pub struct CdnStore {
    base: String,
    http: reqwest::Client,
    policy: RetryPolicy,
}
```

In `CdnStore::new`, set the field (after `http` is built):

```rust
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http,
            policy: RetryPolicy::from_env(),
        })
```

Replace the whole `fetch` method with a classifying `get_once` + retry wrapper:

```rust
    /// One GET attempt, classified for the retry loop. A per-request timeout
    /// (so the origin's known zero-body hang trips a timeout → retry, instead
    /// of wedging the connection).
    async fn get_once(&self, url: &str) -> Attempt {
        let resp = match self.http.get(url).timeout(self.policy.http_timeout).send().await {
            Ok(r) => r,
            // Connect/timeout/transport errors are transient — retry.
            Err(e) => return Attempt::Transient(format!("http get {url}: {e}")),
        };
        let status = resp.status();
        if status.is_success() {
            return match resp.bytes().await {
                Ok(b) => Attempt::Ok(b),
                Err(e) => Attempt::Transient(format!("read body {url}: {e}")),
            };
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Attempt::NotFound;
        }
        if is_transient(status.as_u16()) {
            return Attempt::Transient(format!("HTTP {status} from {url}"));
        }
        Attempt::Permanent(format!("HTTP {status} from {url}"))
    }

    async fn fetch(&self, url: &str) -> Result<Bytes, StoreError> {
        retry(|| self.get_once(url), &self.policy).await
    }
```

- [ ] **Step 2: Build + run existing cdn tests**

Run: `cargo test -p concord-cli --lib cdn::`
Expected: PASS (existing `writes_error_out`, url tests, plus Task 1/2 tests). The `manifest_url_has_no_bucket_segment` etc. still pass — `fetch` signature unchanged from callers' view.

- [ ] **Step 3: Build the whole crate to catch field-init breaks**

Run: `cargo build -p concord-cli`
Expected: success. (`CdnStore::new` is the only constructor; the new field is set there.)

- [ ] **Step 4: Commit**

```bash
git add concord-cli/src/cdn.rs
git commit -m "feat(cli): CDN fetch retries transient errors + per-request timeout"
```

---

## Task 4: Resume state module (`resume.rs`)

**Files:**
- Create: `concord-cli/src/resume.rs`
- Modify: `concord-cli/src/lib.rs`

- [ ] **Step 1: Register the module** — add to `concord-cli/src/lib.rs` after `pub mod pull;`:

```rust
pub mod resume;
```

- [ ] **Step 2: Write the failing tests** — create `concord-cli/src/resume.rs` with ONLY the test module first:

```rust
//! Per-shard resume state for `concord pull`, stored under `<out_dir>/.concord/`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_paths_layout() {
        let p = ShardPaths::new(std::path::Path::new("/out"), "model.safetensors");
        assert_eq!(p.final_path, std::path::Path::new("/out/model.safetensors"));
        assert_eq!(
            p.part_path,
            std::path::Path::new("/out/.concord/model.safetensors.part")
        );
        assert_eq!(
            p.marker_path,
            std::path::Path::new("/out/.concord/model.safetensors.json")
        );
    }

    #[test]
    fn marker_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.json");
        let m = ResumeMarker {
            version: MARKER_VERSION,
            merkle: "b3:abc".into(),
            chunks_done: 3,
            bytes_done: 12_582_912,
            status: Status::Partial,
        };
        m.save(&path).unwrap();
        assert_eq!(ResumeMarker::load(&path), Some(m));
    }

    #[test]
    fn load_missing_is_none() {
        assert_eq!(ResumeMarker::load(std::path::Path::new("/no/such.json")), None);
    }

    #[test]
    fn load_rejects_wrong_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.json");
        std::fs::write(
            &path,
            br#"{"version":999,"merkle":"b3:x","chunks_done":0,"bytes_done":0,"status":"partial"}"#,
        )
        .unwrap();
        assert_eq!(ResumeMarker::load(&path), None, "future version → ignored");
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p concord-cli --lib resume::`
Expected: FAIL — `cannot find type ShardPaths` / `ResumeMarker` / `Status` / `MARKER_VERSION`.

- [ ] **Step 4: Implement** — add ABOVE the `#[cfg(test)] mod tests` block in `resume.rs`:

```rust
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Hidden state directory inside the pull's `out_dir`.
pub const STATE_DIR: &str = ".concord";
/// On-disk marker schema version. Bump on incompatible changes; older/newer
/// markers are treated as absent (safe: re-fetch).
pub const MARKER_VERSION: u32 = 1;

/// Completion status of a shard's download.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Partial,
    Complete,
}

/// Durable per-shard progress. The marker is advanced ONLY after the `.part`
/// bytes it references are fsync'd (see `pull_shard`), so on resume
/// `.part`'s length is always >= `bytes_done`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeMarker {
    pub version: u32,
    pub merkle: String,
    pub chunks_done: usize,
    pub bytes_done: u64,
    pub status: Status,
}

impl ResumeMarker {
    /// A fresh marker for a shard with the given merkle (nothing downloaded).
    pub fn fresh(merkle: &str) -> Self {
        Self {
            version: MARKER_VERSION,
            merkle: merkle.to_string(),
            chunks_done: 0,
            bytes_done: 0,
            status: Status::Partial,
        }
    }

    /// Load a marker. Returns `None` if absent, unparseable, or a different
    /// schema version — all "treat as no progress" cases.
    pub fn load(path: &Path) -> Option<Self> {
        let raw = std::fs::read(path).ok()?;
        let m: ResumeMarker = serde_json::from_slice(&raw).ok()?;
        if m.version != MARKER_VERSION {
            return None;
        }
        Some(m)
    }

    /// Atomically persist the marker (temp file + rename) so a crash mid-write
    /// never leaves a corrupt marker.
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec(self).context("serialize resume marker")?;
        std::fs::write(&tmp, &data).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename marker → {}", path.display()))?;
        Ok(())
    }
}

/// Resolved filesystem paths for one shard's artifacts.
#[derive(Debug)]
pub struct ShardPaths {
    /// Final output: `<out_dir>/<filename>`.
    pub final_path: PathBuf,
    /// In-progress data: `<out_dir>/.concord/<filename>.part`.
    pub part_path: PathBuf,
    /// Progress marker: `<out_dir>/.concord/<filename>.json`.
    pub marker_path: PathBuf,
}

impl ShardPaths {
    pub fn new(out_dir: &Path, filename: &str) -> Self {
        let state = out_dir.join(STATE_DIR);
        Self {
            final_path: out_dir.join(filename),
            part_path: state.join(format!("{filename}.part")),
            marker_path: state.join(format!("{filename}.json")),
        }
    }

    /// The `.concord/` state directory for an out_dir.
    pub fn state_dir(out_dir: &Path) -> PathBuf {
        out_dir.join(STATE_DIR)
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p concord-cli --lib resume::`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add concord-cli/src/resume.rs concord-cli/src/lib.rs
git commit -m "feat(cli): per-shard resume marker + .concord state paths"
```

---

## Task 5: `PullEvent::ShardStart` resumed offsets + `PullArgs.reverify`

**Files:**
- Modify: `concord-cli/src/pull.rs`

This task only changes the event/args shape so later tasks + the renderer compile. It deliberately does NOT yet populate non-zero values.

- [ ] **Step 1: Add fields to `ShardStart`** — in `pull.rs`, in `enum PullEvent`, replace the `ShardStart` variant with:

```rust
    /// Starting a shard (one output file). `resumed_chunks`/`resumed_bytes`
    /// report how much was already on disk from a prior run (0 for a fresh
    /// pull) so the renderer can start the bar at the right offset.
    ShardStart {
        idx: usize,
        total: usize,
        role: String,
        format: String,
        size: u64,
        parts: usize,
        resumed_chunks: usize,
        resumed_bytes: u64,
    },
```

- [ ] **Step 2: Add `reverify` to `PullArgs`** — replace the `PullArgs` struct:

```rust
/// Required arguments for [`pull`].
#[derive(Clone, Debug)]
pub struct PullArgs {
    pub name: String,
    pub version: String,
    pub out_dir: PathBuf,
    /// Ignore resume state + skip-done: re-fetch and rebuild every shard from
    /// scratch (cache hits still re-verify). For when a local file is suspect.
    pub reverify: bool,
}
```

- [ ] **Step 3: Patch existing emit sites + the renderer signature break** — in `pull.rs`, the `download_shards` `emit(PullEvent::ShardStart { ... })` call must include the new fields. For now (pre-rewrite) emit zeros — Task 6 replaces this call entirely. Update the existing emit in `download_shards`:

```rust
            emit(PullEvent::ShardStart {
                idx,
                total,
                role: shard.role.clone(),
                format: shard.format.clone(),
                size: shard.size,
                parts: shard.parts.unwrap_or(1) as usize,
                resumed_chunks: 0,
                resumed_bytes: 0,
            });
```

- [ ] **Step 4: Build the lib to find all break sites**

Run: `cargo build -p concord-cli --lib`
Expected: FAIL — `main.rs` and any `PullArgs { .. }` construction now miss `reverify`, and the renderer's `ShardStart { idx, total, role, format, size, parts }` pattern is non-exhaustive. These are fixed in Task 7. The *lib* itself should build once `download_shards` is patched (Step 3) — if the lib still errors, it's only inside `pull.rs`; fix those. (The binary `main.rs` errors are expected and handled in Task 7.)

- [ ] **Step 5: Commit**

```bash
git add concord-cli/src/pull.rs
git commit -m "feat(cli): add resumed offsets to ShardStart + reverify to PullArgs"
```

---

## Task 6: Streaming + resumable `pull_shard`

**Files:**
- Modify: `concord-cli/src/pull.rs`

- [ ] **Step 1: Write the failing tests** — append these to the `tests` module in `pull.rs`. They use the existing `CountingStore`, `MemoryStore`, `seed_shards`, `shard_merkle`, `ChunkHash` already in that module.

```rust
    use crate::resume::{ResumeMarker, ShardPaths, Status};

    /// Build a 3-chunk shard in `store` + return (shard, chunk bodies).
    async fn three_chunk_shard(
        store: &concord_core::store::MemoryStore,
    ) -> (Shard, Vec<Vec<u8>>) {
        let bodies: Vec<Vec<u8>> = vec![vec![1u8; 100], vec![2u8; 80], vec![3u8; 50]];
        let mut hashes = Vec::new();
        for b in &bodies {
            let h = ChunkHash::of(b.as_slice());
            store.put_chunk(&h, bytes::Bytes::from(b.clone())).await.unwrap();
            hashes.push(h);
        }
        let shard = Shard {
            role: "weights".into(),
            format: "bin".into(),
            parts: Some(3),
            size: 230,
            merkle: shard_merkle(&hashes).to_string(),
            chunks: hashes.iter().map(|h| h.to_string()).collect(),
        };
        (shard, bodies)
    }

    #[tokio::test]
    async fn fresh_pull_streams_full_file() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let (written, wire) =
            pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {}).await.unwrap();
        assert_eq!((written, wire), (230, 230));
        assert_eq!(store.gets(), 3);
        let got = std::fs::read(out.path().join("weights.bin")).unwrap();
        assert_eq!(got, bodies.concat());
        // Marker flipped to complete.
        let p = ShardPaths::new(out.path(), "weights.bin");
        assert_eq!(ResumeMarker::load(&p.marker_path).unwrap().status, Status::Complete);
    }

    #[tokio::test]
    async fn skip_done_does_not_refetch() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, _bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        // First pull completes.
        pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {}).await.unwrap();
        let after_first = store.gets();
        // Second pull: complete marker + final file present → zero new gets.
        let (written, wire) =
            pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {}).await.unwrap();
        assert_eq!((written, wire), (230, 0));
        assert_eq!(store.gets(), after_first, "skip-done must not re-fetch");
    }

    #[tokio::test]
    async fn resume_fetches_only_remaining_chunks() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        // Simulate an interrupted pull: first chunk written to .part + marker partial.
        let p = ShardPaths::new(out.path(), "weights.bin");
        std::fs::create_dir_all(ShardPaths::state_dir(out.path())).unwrap();
        std::fs::write(&p.part_path, &bodies[0]).unwrap();
        ResumeMarker {
            version: crate::resume::MARKER_VERSION,
            merkle: shard.merkle.clone(),
            chunks_done: 1,
            bytes_done: bodies[0].len() as u64,
            status: Status::Partial,
        }
        .save(&p.marker_path)
        .unwrap();

        let (written, wire) =
            pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {}).await.unwrap();
        assert_eq!(written, 230);
        assert_eq!(wire, (bodies[1].len() + bodies[2].len()) as u64, "only tail on the wire");
        assert_eq!(store.gets(), 2, "chunk 0 already done → only 2 fetched");
        assert_eq!(std::fs::read(out.path().join("weights.bin")).unwrap(), bodies.concat());
    }

    #[tokio::test]
    async fn stale_merkle_discards_part_and_refetches() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let p = ShardPaths::new(out.path(), "weights.bin");
        std::fs::create_dir_all(ShardPaths::state_dir(out.path())).unwrap();
        // .part from a DIFFERENT version (wrong merkle) — must be discarded.
        std::fs::write(&p.part_path, b"garbage from another version").unwrap();
        ResumeMarker {
            version: crate::resume::MARKER_VERSION,
            merkle: "b3:0000000000000000000000000000000000000000000000000000000000000000".into(),
            chunks_done: 1,
            bytes_done: 999,
            status: Status::Partial,
        }
        .save(&p.marker_path)
        .unwrap();

        let (written, _wire) =
            pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {}).await.unwrap();
        assert_eq!(written, 230);
        assert_eq!(store.gets(), 3, "stale .part → full re-fetch");
        assert_eq!(std::fs::read(out.path().join("weights.bin")).unwrap(), bodies.concat());
    }

    #[tokio::test]
    async fn torn_write_is_truncated_then_resumed() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let p = ShardPaths::new(out.path(), "weights.bin");
        std::fs::create_dir_all(ShardPaths::state_dir(out.path())).unwrap();
        // .part has chunk0 + a torn partial tail beyond bytes_done.
        let mut torn = bodies[0].clone();
        torn.extend_from_slice(b"torn-partial-write");
        std::fs::write(&p.part_path, &torn).unwrap();
        ResumeMarker {
            version: crate::resume::MARKER_VERSION,
            merkle: shard.merkle.clone(),
            chunks_done: 1,
            bytes_done: bodies[0].len() as u64,
            status: Status::Partial,
        }
        .save(&p.marker_path)
        .unwrap();

        let (written, _wire) =
            pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {}).await.unwrap();
        assert_eq!(written, 230);
        assert_eq!(std::fs::read(out.path().join("weights.bin")).unwrap(), bodies.concat(),
                   "torn tail truncated, file reassembles correctly");
    }

    #[tokio::test]
    async fn reverify_ignores_complete_marker() {
        let inner = concord_core::store::MemoryStore::new();
        let (shard, _bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {}).await.unwrap();
        let after_first = store.gets();
        // reverify=true → re-fetch despite complete marker.
        pull_shard(&store, &shard, out.path(), None, 1, 1, true, &|_| {}).await.unwrap();
        assert!(store.gets() > after_first, "reverify must re-fetch");
    }

    #[tokio::test]
    async fn ordered_assembly_with_concurrency() {
        std::env::set_var("CONCORD_CHUNK_CONCURRENCY", "4");
        let inner = concord_core::store::MemoryStore::new();
        let (shard, bodies) = three_chunk_shard(&inner).await;
        let store = CountingStore::new(inner);
        let out = tempfile::tempdir().unwrap();
        let (written, _w) =
            pull_shard(&store, &shard, out.path(), None, 1, 1, false, &|_| {}).await.unwrap();
        assert_eq!(written, 230);
        assert_eq!(std::fs::read(out.path().join("weights.bin")).unwrap(), bodies.concat(),
                   "buffered(C) preserves chunk order");
        std::env::remove_var("CONCORD_CHUNK_CONCURRENCY");
    }
```

- [ ] **Step 2: Update the EXISTING `pull_shard` tests** to the new 8-arg signature (they currently call with 6 args). In the same `tests` module, change the three call sites:
  - `multi_chunk_shard_reassembles_in_order`: `pull_shard(&store, &shard, dir.path(), None, 1, &|_| {})` → `pull_shard(&store, &shard, dir.path(), None, 1, 1, false, &|_| {})`
  - `multi_chunk_list_not_matching_merkle_is_rejected`: same trailing-args change → `..., 1, 1, false, &|_| {})`
  - `cache_hit_avoids_wire_refetch`: both `pull_shard(..., Some(cache.path()), 1, &|_| {})` calls → `pull_shard(..., Some(cache.path()), 1, 1, false, &|_| {})`

- [ ] **Step 3: Run to verify the new tests fail (signature/behavior)**

Run: `cargo test -p concord-cli --lib pull::tests::fresh_pull_streams_full_file`
Expected: FAIL — `pull_shard` takes 6 args, not 8 (compile error) until Step 4.

- [ ] **Step 4: Rewrite `pull_shard` + add helpers** — in `pull.rs`:

First add imports at the top of the file (alongside existing `use` lines):

```rust
use std::io::{Seek, SeekFrom, Write};

use crate::resume::{ResumeMarker, ShardPaths, Status};
```

Add the env-knob helpers near `download_concurrency`:

```rust
/// Intra-shard chunk look-ahead. Chunks are fetched up to this many at once
/// (ordered commit), pipelining the network. Override `CONCORD_CHUNK_CONCURRENCY`;
/// default 4.
fn chunk_concurrency() -> usize {
    std::env::var("CONCORD_CHUNK_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(4)
}

/// How many chunks to commit before fsync+marker advance. 1 = safest (a crash
/// re-fetches at most 0 extra chunks); higher = fewer fsyncs. Override
/// `CONCORD_COMMIT_EVERY`; default 1.
fn commit_every() -> u32 {
    std::env::var("CONCORD_COMMIT_EVERY")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1)
}
```

Factor the chunk-hash resolution out of the old `pull_shard` into a free function (it is unchanged logic, lifted verbatim):

```rust
/// Resolve + authenticate the ordered chunk-hash list for a shard against its
/// signed merkle root. (Lifted from the old `pull_shard`.)
fn resolve_chunk_hashes(shard: &Shard) -> Result<Vec<ChunkHash>> {
    let chunk_hashes: Vec<ChunkHash> = if !shard.chunks.is_empty() {
        shard
            .chunks
            .iter()
            .map(|h| h.parse::<ChunkHash>().with_context(|| format!("parse chunk hash {h}")))
            .collect::<Result<Vec<_>>>()?
    } else {
        let parts = shard.parts.unwrap_or(1);
        if parts > 1 {
            bail!(
                "shard {} has {} chunks but the manifest carries no chunk list \
                 (predates RFC 0001 chunk-index) — re-push to migrate",
                shard.role,
                parts
            );
        }
        vec![shard
            .merkle
            .parse::<ChunkHash>()
            .with_context(|| format!("parse shard merkle: {}", shard.merkle))?]
    };
    let recomputed = shard_merkle(&chunk_hashes);
    if recomputed.to_string() != shard.merkle {
        bail!(
            "shard {} chunk list does not match signed merkle: manifest={} computed={}",
            shard.role,
            shard.merkle,
            recomputed
        );
    }
    Ok(chunk_hashes)
}

/// Fetch one chunk: cache-hit (re-verified) or wire (verified + cached).
/// Returns `(bytes, cache_hit)`.
async fn fetch_one_chunk<S: Store + ?Sized>(
    store: &S,
    h: &ChunkHash,
    cache_path: Option<&Path>,
) -> Result<(bytes::Bytes, bool)> {
    if let Some(p) = cache_path {
        if let Ok(b) = std::fs::read(p) {
            if ChunkHash::of(&b).to_string() == h.to_string() {
                return Ok((bytes::Bytes::from(b), true));
            }
        }
    }
    let b = store.get_chunk(h).await.map_err(|e| anyhow!("get chunk {h}: {e}"))?;
    let got = ChunkHash::of(&b);
    if got.to_string() != h.to_string() {
        bail!("chunk {h} content hash mismatch: got {got}");
    }
    if let Some(p) = cache_path {
        let tmp = p.with_extension("partial");
        if std::fs::write(&tmp, &b).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
    Ok((b, false))
}
```

Now replace the ENTIRE old `pull_shard` function with the streaming version:

```rust
/// Fetch all chunks for `shard`, streaming them to a `.part` file under
/// `<out_dir>/.concord/`, then atomic-rename to the final output. Resumes from
/// the durable marker; skips shards already complete. Returns
/// `(bytes_written, bytes_on_wire)` — `bytes_written` is the full shard size,
/// `bytes_on_wire` only what was fetched THIS run.
#[allow(clippy::too_many_arguments)]
async fn pull_shard<S: Store + ?Sized>(
    store: &S,
    shard: &Shard,
    out_dir: &Path,
    cache_dir: Option<&Path>,
    idx: usize,
    total: usize,
    reverify: bool,
    emit: &(impl Fn(PullEvent) + Sync),
) -> Result<(u64, u64)> {
    use futures::stream::{self, StreamExt};

    let chunk_hashes = resolve_chunk_hashes(shard)?;
    let filename = shard_filename(shard);
    let paths = ShardPaths::new(out_dir, &filename);

    let shard_start = |resumed_chunks: usize, resumed_bytes: u64| {
        emit(PullEvent::ShardStart {
            idx,
            total,
            role: shard.role.clone(),
            format: shard.format.clone(),
            size: shard.size,
            parts: shard.parts.unwrap_or(1) as usize,
            resumed_chunks,
            resumed_bytes,
        });
    };

    // Skip-done: trust only a marker WE wrote (complete + matching merkle) with
    // the final file present. Guards against stale-version / old-CLI / modified
    // files that merely share the name.
    if !reverify {
        if let Some(m) = ResumeMarker::load(&paths.marker_path) {
            if m.status == Status::Complete && m.merkle == shard.merkle && paths.final_path.exists()
            {
                shard_start(chunk_hashes.len(), shard.size);
                emit(PullEvent::ShardDone { idx, filename });
                return Ok((shard.size, 0));
            }
        }
    }

    std::fs::create_dir_all(ShardPaths::state_dir(out_dir))
        .with_context(|| format!("mkdir {}", ShardPaths::state_dir(out_dir).display()))?;

    // Resume point: a partial marker with the SAME merkle, else fresh.
    let mut marker = if reverify {
        ResumeMarker::fresh(&shard.merkle)
    } else {
        match ResumeMarker::load(&paths.marker_path) {
            Some(m) if m.status == Status::Partial && m.merkle == shard.merkle => m,
            _ => ResumeMarker::fresh(&shard.merkle),
        }
    };

    // Open `.part`, truncate down to the durable boundary (drops any torn tail),
    // and position the cursor for appending. Never reset to 0 on a short file:
    // the durability invariant guarantees `.part` len >= bytes_done.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&paths.part_path)
        .with_context(|| format!("open {}", paths.part_path.display()))?;
    file.set_len(marker.bytes_done)
        .with_context(|| format!("truncate {} to {}", paths.part_path.display(), marker.bytes_done))?;
    file.seek(SeekFrom::End(0)).context("seek part to end")?;

    shard_start(marker.chunks_done, marker.bytes_done);

    let start = marker.chunks_done;
    let remaining: Vec<(usize, ChunkHash)> =
        chunk_hashes.iter().cloned().enumerate().skip(start).collect();

    let concurrency = chunk_concurrency();
    let commit_n = commit_every();

    // Ordered look-ahead: `buffered(C)` yields results in input order, so we can
    // append + commit sequentially while fetching ahead.
    let mut fetches = stream::iter(remaining.into_iter().map(|(_i, h)| {
        let cache_path = cache_dir.map(|d| d.join(h.to_string()));
        async move { fetch_one_chunk(store, &h, cache_path.as_deref()).await }
    }))
    .buffered(concurrency.max(1));

    let mut on_wire: u64 = 0;
    let mut since_commit: u32 = 0;
    while let Some(item) = fetches.next().await {
        let (bytes, cache_hit) = item?;
        if !cache_hit {
            on_wire += bytes.len() as u64;
        }
        file.write_all(&bytes)
            .with_context(|| format!("append to {}", paths.part_path.display()))?;
        marker.chunks_done += 1;
        marker.bytes_done += bytes.len() as u64;
        since_commit += 1;
        if since_commit >= commit_n {
            // Durability: fsync the data BEFORE advancing the marker.
            file.flush().context("flush part")?;
            file.sync_all().context("fsync part")?;
            marker.save(&paths.marker_path)?;
            since_commit = 0;
        }
        emit(PullEvent::ChunkDone {
            idx,
            bytes: bytes.len() as u64,
            cache_hit,
        });
    }

    // Final durability for any uncommitted tail, then publish atomically.
    file.flush().context("flush part")?;
    file.sync_all().context("fsync part")?;
    drop(file);
    std::fs::rename(&paths.part_path, &paths.final_path)
        .with_context(|| format!("rename {} → {}", paths.part_path.display(), paths.final_path.display()))?;
    marker.status = Status::Complete;
    marker.save(&paths.marker_path)?;

    emit(PullEvent::ShardDone { idx, filename });
    Ok((shard.size, on_wire))
}
```

Finally, update `download_shards` to pass `total` + `reverify` and drop its now-duplicate `ShardStart` emit (the rewritten `pull_shard` emits `ShardStart` itself). Replace the closure body inside `download_shards`'s `.map(...)`:

```rust
        .map(|(i, shard)| async move {
            let idx = i + 1;
            let (written, wire) =
                pull_shard(store, shard, out_dir, cache_dir, idx, total, reverify, emit).await?;
            Ok::<(u64, u64), anyhow::Error>((written, wire))
        })
```

and change `download_shards`'s signature to accept `reverify`:

```rust
async fn download_shards<S: Store + ?Sized>(
    store: &S,
    shards: &[Shard],
    out_dir: &Path,
    cache_dir: Option<&Path>,
    concurrency: usize,
    reverify: bool,
    emit: &(impl Fn(PullEvent) + Sync),
) -> Result<(u64, u64, u64)> {
```

and its caller `pull_with_progress` passes `args.reverify`:

```rust
    let (files, bytes, on_wire) = download_shards(
        store,
        &manifest.shards,
        &args.out_dir,
        cache_dir.as_deref(),
        concurrency,
        args.reverify,
        &emit,
    )
    .await?;
```

(Remove the old standalone `emit(PullEvent::ShardStart { .. })` and `emit(PullEvent::ShardDone { .. })` calls from `download_shards` — `pull_shard` now owns both.)

- [ ] **Step 5: Update the `shards_download_in_parallel` test** — it calls `download_shards(&store, &shards, out.path(), None, 4, &|_| {})` (6 args). Change to `download_shards(&store, &shards, out.path(), None, 4, false, &|_| {})`.

- [ ] **Step 6: Run the full pull test suite**

Run: `cargo test -p concord-cli --lib pull::`
Expected: PASS — all new tests (fresh/skip-done/resume/stale-merkle/torn-write/reverify/ordered) plus the updated existing tests.

- [ ] **Step 7: Commit**

```bash
git add concord-cli/src/pull.rs
git commit -m "feat(cli): streaming, resumable pull_shard (skip-done, .part resume, ordered look-ahead)"
```

---

## Task 7: Renderer resumed offset + `--reverify` flag (`main.rs`)

**Files:**
- Modify: `concord-cli/src/main.rs`

- [ ] **Step 1: Add the `--reverify` flag** — in the `Cmd::Pull` variant struct, add after `cdn_endpoint`:

```rust
        /// Re-fetch and rebuild every shard from scratch, ignoring resume
        /// state and skip-done. Use if a local file is suspected corrupt.
        #[arg(long)]
        reverify: bool,
```

- [ ] **Step 2: Thread it into `PullArgs`** — in the `Cmd::Pull { .. }` match arm, add `reverify` to the destructure and to the `PullArgs`:

Destructure:
```rust
        Cmd::Pull {
            target,
            out,
            pubkey,
            cdn_endpoint,
            reverify,
        } => {
```
Args:
```rust
            let args = PullArgs {
                name: model.name.clone(),
                version: model.version.clone(),
                out_dir: out_dir.clone(),
                reverify,
            };
```

- [ ] **Step 3: Update the renderer to honor resumed offsets + honest avg** — replace the `make_pull_progress` body's `bars` map type and the three relevant arms. Change the map to hold the resumed baseline:

```rust
    let bars: Arc<Mutex<HashMap<usize, (ProgressBar, u64)>>> = Arc::new(Mutex::new(HashMap::new()));
```

`ShardStart` arm (now with resumed fields) — replace it with:

```rust
        PullEvent::ShardStart {
            idx,
            total,
            role,
            format,
            size,
            parts,
            resumed_chunks,
            resumed_bytes,
        } => {
            let pb = mp.add(ProgressBar::new(size));
            let style = ProgressStyle::with_template(
                "  {prefix} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) {msg}",
            )
            .expect("progress template")
            .progress_chars("=>-");
            pb.set_style(style);
            pb.set_prefix(format!("[{idx}/{total}] {role}.{format}"));
            // Start the bar at what's already on disk so resume doesn't replay.
            pb.set_position(resumed_bytes);
            if resumed_chunks > 0 {
                pb.set_message(format!("resumed {}", concord_cli::fmt::human_bytes(resumed_bytes)));
            } else if parts > 1 {
                pb.set_message(format!("{parts} parts"));
            }
            bars.lock().unwrap().insert(idx, (pb, resumed_bytes));
        }
```

`ChunkDone` arm — replace with (tuple value now):

```rust
        PullEvent::ChunkDone {
            idx,
            bytes,
            cache_hit,
        } => {
            if let Some((pb, _resumed)) = bars.lock().unwrap().get(&idx) {
                pb.inc(bytes);
                if cache_hit {
                    pb.set_message("cache-hit");
                }
            }
        }
```

`ShardDone` arm — replace with (subtract resumed baseline so avg reflects only THIS run's wire bytes):

```rust
        PullEvent::ShardDone { idx, filename } => {
            let avg = bars.lock().unwrap().remove(&idx).map(|(pb, resumed)| {
                let transferred = pb.position().saturating_sub(resumed);
                let r = concord_cli::fmt::rate(transferred, pb.elapsed().as_secs_f64());
                pb.finish_and_clear();
                r
            });
            match avg {
                Some(speed) => {
                    let _ = mp.println(format!("  [{idx}] {filename}  ✓  avg {speed}"));
                }
                None => {
                    let _ = mp.println(format!("  [{idx}] {filename}  ✓"));
                }
            }
        }
```

- [ ] **Step 4: Build the binary**

Run: `cargo build -p concord-cli`
Expected: success (the `ShardStart` pattern is now exhaustive; `PullArgs` has `reverify`).

- [ ] **Step 5: Run the whole workspace test suite + clippy**

Run: `cargo test -p concord-cli && cargo clippy -p concord-cli -- -D warnings`
Expected: PASS, no warnings. (If `too_many_arguments` fires on `pull_shard`, the `#[allow(clippy::too_many_arguments)]` from Task 6 covers it.)

- [ ] **Step 6: Commit**

```bash
git add concord-cli/src/main.rs
git commit -m "feat(cli): --reverify flag + resume-aware progress bars"
```

---

## Task 8: End-to-end resume integration test

**Files:**
- Create/Modify: `concord-cli/tests/push_pull_e2e.rs` (add a test; follow the file's existing harness — it already drives push+pull against `MemoryStore`).

- [ ] **Step 1: Read the existing e2e harness**

Run: `sed -n '1,60p' concord-cli/tests/push_pull_e2e.rs`
Expected: see how it builds a `MemoryStore`, pushes a model, and calls `pull`/`pull_with_progress`. Mirror that setup.

- [ ] **Step 2: Add a resume integration test** — append a test that pulls into an out_dir, deletes the final file + flips the marker to partial (simulating an interrupt mid-shard is harder e2e; instead assert the cheaper invariant: a second pull into the SAME out_dir is a skip-done no-op). Use the existing harness's store/manifest/pubkey setup; the shape:

```rust
#[tokio::test]
async fn second_pull_skips_completed_shards() {
    // ... reuse this file's existing setup to get (store, args-name/version, pubkey) ...
    // First pull: full download into out_dir.
    let out = tempfile::tempdir().unwrap();
    let args1 = concord_cli::pull::PullArgs {
        name: NAME.into(), version: VERSION.into(), out_dir: out.path().into(), reverify: false,
    };
    let (_m, s1) = concord_cli::pull::pull(&store, &args1, &pubkey).await.unwrap();
    assert!(s1.on_wire > 0, "first pull fetches over the wire");

    // Second pull into the same dir: every shard skip-done → zero wire bytes.
    let (_m2, s2) = concord_cli::pull::pull(&store, &args1, &pubkey).await.unwrap();
    assert_eq!(s2.on_wire, 0, "second pull is fully skip-done");
    assert_eq!(s2.bytes, s1.bytes, "same logical bytes reported");
}
```

Adapt `NAME`/`VERSION`/`store`/`pubkey` to whatever the existing tests in this file already construct (do NOT invent new fixtures — reuse the file's helpers).

- [ ] **Step 3: Run the e2e test**

Run: `cargo test -p concord-cli --test push_pull_e2e second_pull_skips_completed_shards`
Expected: PASS.

- [ ] **Step 4: Full suite green**

Run: `cargo test -p concord-cli`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add concord-cli/tests/push_pull_e2e.rs
git commit -m "test(cli): e2e — second pull skips completed shards"
```

---

## Manual verification (after all tasks)

Against the live EU operator (CDN must be serving — coordinate with whoever owns the cluster/origin fix):

```bash
cargo build -p concord-cli --release
# Cold pull into a fresh dir:
./target/release/concord pull google/electra-base-discriminator:v1 --out /tmp/m
# Interrupt with Ctrl-C partway, then re-run the SAME command:
./target/release/concord pull google/electra-base-discriminator:v1 --out /tmp/m
#   → completed shards show "✓" immediately (skip-done); the interrupted shard
#     resumes from its bar offset (no replay, no cache-hit flood).
# Force a clean rebuild:
./target/release/concord pull google/electra-base-discriminator:v1 --out /tmp/m --reverify
# Simulate transient errors (point at a flaky/own endpoint) → pull retries
# instead of aborting; CONCORD_MAX_RETRIES=1 disables retry to confirm contrast.
```

---

## Self-review notes (done while writing)

- **Spec coverage:** retry layer (T1-3) ✓; `.concord/` per-shard state (T4) ✓; skip-done marker (T6) ✓; mid-shard resume + truncate-not-reset (T6) ✓; durability fsync-before-marker (T6) ✓; streaming O(chunk) + ordered `buffered(C)` (T6) ✓; stale-merkle discard (T6 test) ✓; `ShardStart` resumed offsets + renderer (T5/T7) ✓; `--reverify` (T5/T7) ✓; stats accounting written=size/wire=this-run (T6) ✓; env knobs (T2/T6) ✓; TDD test list (T1,2,4,6,8) ✓.
- **Type consistency:** `pull_shard` is 8-arg `(store, shard, out_dir, cache_dir, idx, total, reverify, emit)` everywhere; `ResumeMarker`/`Status`/`ShardPaths`/`MARKER_VERSION` names match resume.rs; `Attempt`/`RetryPolicy`/`retry`/`is_transient`/`backoff` match cdn.rs; renderer `bars` map is `(ProgressBar, u64)` in all three arms.
- **No placeholders:** every code step is complete; the only "adapt to existing fixtures" note is Task 8 Step 2, which explicitly defers to the file's real helpers rather than inventing types.
