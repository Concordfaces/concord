# CLI downloader — resumable, fault-tolerant pull

**Date:** 2026-06-16
**Scope:** `concord pull` (`concord-cli`) + the CDN store (`concord-store-s3` / `cdn.rs`).
**Goal:** make `concord pull` resume **fast** (skip work already done) and **smooth**
(a transient CDN error must not abort a multi-GB pull).

## Problem

Today `concord pull` (see `concord-cli/src/pull.rs`, `concord-cli/src/cdn.rs`):

1. **One transient error aborts the whole pull.** `CdnStore::fetch` (cdn.rs:83) does a
   single GET with no retry and no per-request timeout. Any `503/502/504/429`, connect
   error, or hang maps to `StoreError::Backend` → bubbles up → the entire pull fails. A
   real `503` from the origin under load killed a multi-GB pull mid-flight.
2. **Resume re-does everything.** `pull_shard` (pull.rs:267) builds the whole shard in
   one in-RAM `Vec` (`Vec::with_capacity(shard.size)` — 420 MB for a large shard), then
   writes the file. On a re-run it re-walks every shard and every chunk, re-reads +
   re-hashes all cached chunks (the "cache-hit" flood), rebuilds the full `Vec`, and
   rewrites the file — **even for shards already fully downloaded**. There is no
   "this file is done, skip it" and no mid-shard resume.

Net: the cache makes resume *correct* but not *fast*, and a single blip forces a manual
restart that then re-grinds all prior work.

## Goals / non-goals

**Goals**
- Transient CDN failures are retried with backoff; a pull survives blips.
- A re-run skips shards already complete (O(1) per done shard).
- A re-run resumes a partially-downloaded shard from where it stopped (no re-fetch, no
  re-hash, no rewrite of the committed prefix).
- Peak memory is O(chunk · look-ahead), not O(shard).
- Integrity guarantees preserved: every chunk hash-verified; shard merkle verified.

**Non-goals**
- Concurrent pulls into the *same* out_dir (single-writer assumed; documented).
- Out-of-order / sparse chunk writes within a shard (sequential commit only).
- Changing the push side or manifest format.

## Design

### Component 1 — retry layer (`cdn.rs`)

Split the single GET into a dependency-free, unit-testable retry:

- `get_once(url) -> Result<Bytes, FetchError>` — one attempt. Classifies the outcome:
  `Ok(bytes)`, `NotFound` (404, terminal), `Transient` (connect/timeout errors + HTTP
  `408/429/500/502/503/504`), `Permanent` (403, other 4xx, body-read error).
- `retry(op, policy)` — generic over an async closure returning the classified result.
  Retries `Transient` up to `policy.max_attempts`, sleeping `backoff(attempt)` between;
  returns immediately on `Ok`/`NotFound`/`Permanent`/attempts-exhausted.
- `fetch(url)` = `retry(|| self.get_once(url), policy)`.
- Per-request **timeout** via reqwest request `.timeout(policy.http_timeout)` so the
  origin's known zero-body 30 s hang trips a timeout (→ `Transient` → retry) instead of
  wedging.

Pure helpers, unit-tested without HTTP:
- `is_transient(status) -> bool`
- `backoff(attempt) -> Duration` — exponential (base × 2^attempt) capped, small jitter
  from a cheap non-crypto source (no new dep).

Config (env, sane defaults):
- `CONCORD_MAX_RETRIES` (default 4)
- `CONCORD_RETRY_BASE_MS` (default 250)
- `CONCORD_HTTP_TIMEOUT_SECS` (default 60)

The manifest + `keys.json` fetches go through the same `fetch`, so they get retry too.

### Component 2 — resume state (`.concord/` in out_dir)

A single hidden state dir inside `out_dir`, with **per-shard** files (parallel shards
never touch the same file → no contention):

```
<out_dir>/.concord/<filename>.part    # reassembled bytes so far (data)
<out_dir>/.concord/<filename>.json     # progress marker (small, atomically replaced)
```

Marker JSON:
```json
{ "version": 1, "merkle": "<shard merkle>", "chunks_done": <n>, "bytes_done": <n>, "status": "partial" | "complete" }
```

- `merkle` pins the shard identity. If a re-run's shard merkle ≠ marker merkle, the
  `.part` is from a different version → discard `.part`, start fresh.
- On completion the data is atomic-renamed `.concord/<filename>.part` → `out_dir/<filename>`
  (same filesystem → atomic), then the marker is set `status:"complete"`.
- out_dir only ever receives fully-assembled final files.

### Component 3 — streaming reassembly + resume (`pull_shard`)

Replaces the in-RAM `Vec`. Per shard:

1. **Skip-done.** If `.concord/<filename>.json` exists with `status:"complete"` AND
   `merkle` matches AND `out_dir/<filename>` exists → emit `ShardDone`, return
   `(written = shard.size, wire = 0)`. (We trust only the marker we wrote, not bare file
   presence/size — guards against stale-version / old-CLI / user-modified files.)
2. Verify the chunk list against the signed merkle (unchanged, pull.rs:308).
3. Open/create `.concord/<filename>.part`; read the marker.
   - Stale `merkle` or no marker → `chunks_done = bytes_done = 0`, truncate `.part` to 0.
   - Else **truncate `.part` down to `bytes_done`** (drops any torn trailing write).
     Never reset to 0 on a short `.part` — see durability below.
4. Fetch chunks `chunks_done..N` with **bounded look-ahead concurrency**: a `buffered(C)`
   stream over the remaining chunk hashes (ordered output preserved). Each item:
   cache-hit (re-verify hash) or `store.get_chunk` (retry layer, verify hash, best-effort
   cache write). Memory = O(C · chunk).
   For each yielded chunk **in order**:
   - append bytes to `.part`
   - **`fsync` `.part`**
   - update marker `{chunks_done += 1, bytes_done += len}` and write it atomically
     (temp + rename) — i.e. the marker is advanced **only after** the data it references
     is durable.
   - emit `ChunkDone { idx, bytes, cache_hit }`.
5. On finish: `fsync` `.part`, atomic-rename → `out_dir/<filename>`, set marker
   `status:"complete"`. Emit `ShardDone`.

**Durability invariant:** `.part` is fsync'd to ≥ `bytes_done` *before* the marker
records `bytes_done`. Therefore on resume `.part` length ≥ `bytes_done` always (a longer
`.part` = a torn write past the last committed chunk). Resume truncates to `bytes_done`
and continues from `chunks_done`. Optional `CONCORD_COMMIT_EVERY` (default 1) batches the
marker advance every K chunks (fewer fsyncs, at most K-1 chunks re-fetched after a crash).

Config:
- `CONCORD_CHUNK_CONCURRENCY` — intra-shard look-ahead `C` (default 4).
- `CONCORD_DOWNLOAD_CONCURRENCY` — existing shard-level parallelism (unchanged).
- `CONCORD_COMMIT_EVERY` — marker-advance batching (default 1).

### Component 4 — progress + escape hatch

- `PullEvent::ShardStart` gains `resumed_chunks: usize` and `resumed_bytes: u64`. The
  renderer (`concord-cli/src/main.rs`) initializes the shard's bar to `resumed_bytes`
  instead of 0. Because the committed prefix is skipped (not replayed), the "cache-hit"
  flood disappears.
- `--reverify` flag (and/or `CONCORD_NO_RESUME=1`): ignore skip-done + ignore `.part`
  resume → clean full re-fetch (cache hits still re-verify on read). For when a local
  file is suspected corrupt.

### Stats accounting

`pull_shard` returns `(written, on_wire)` where `written = shard.size` (the final file is
complete) and `on_wire` counts only bytes fetched **this run**. Resumed prefix + cache
hits are the savings `dedup_pct` reports. Skip-done returns `(shard.size, 0)`.

## Integrity

Fast resume trusts the `.part` prefix for speed. Justification: every chunk was
hash-verified before it was appended; the chunk list was merkle-verified up front; the
marker's `merkle` rejects a `.part` from a different version. The only un-rechecked risk
is on-disk bit-rot of `.part` between runs — bounded by `--reverify` for the paranoid.
This matches the existing trust level of the chunk cache (verified on read, not
continuously).

## Testing (TDD)

Pure / unit (no network):
- `is_transient` truth table; `backoff` monotonic + capped.
- `retry`: succeeds after N transient failures; gives up after `max_attempts`; does NOT
  retry `NotFound`/`Permanent` (fake op closure counts calls).
- skip-done: marker `complete` + matching merkle → zero `get_chunk` calls.
- resume: marker `partial {chunks_done=k}` + a `.part` of `bytes_done` → only chunks
  `k..N` fetched; reassembled file equals full concat.
- stale-merkle: marker merkle ≠ shard merkle → `.part` discarded, full re-fetch.
- torn-write: `.part` longer than `bytes_done` → truncated to `bytes_done`, resumes
  correctly.
- ordered buffered assembly: `C>1` still produces bytes in chunk order.
- atomic completion: final file appears only after all chunks; marker flips to `complete`.

Reuse the existing `CountingStore` / `MemoryStore` test harness in pull.rs for the
fetch-count assertions; use a temp dir for `.concord/` state.

## Out of scope / follow-ups

- Intra-shard out-of-order writes (sparse + bitmap) for even higher cold throughput.
- Concurrent pulls into one out_dir (lockfile) — currently single-writer assumed.
- Range/partial-byte resume *within* a single chunk (chunks are ≤4 MB; whole-chunk
  granularity is sufficient).
