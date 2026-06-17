//! End-to-end push/pull test: push a tiny synthetic model dir into a
//! [`MemoryStore`], pull it back through the same store, assert
//! byte-for-byte equality of each file. No network required.

use std::collections::BTreeMap;
use std::path::Path;

use concord_cli::pull::{pull, PullArgs};
use concord_cli::push::{push, PushArgs};
use concord_core::sign;
use concord_core::store::MemoryStore;

/// A canonical mini-model: weights + tokenizer + config, deterministic
/// bodies so the test is reproducible.
fn write_model(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert(
        "model.safetensors".into(),
        b"pretend these are weights".to_vec(),
    );
    files.insert(
        "tokenizer.json".into(),
        br#"{"vocab":["a","b","c"]}"#.to_vec(),
    );
    files.insert(
        "config.json".into(),
        br#"{"hidden_size":128,"num_layers":2}"#.to_vec(),
    );
    for (name, body) in &files {
        std::fs::write(dir.join(name), body).unwrap();
    }
    files
}

#[tokio::test]
async fn push_then_pull_roundtrip_preserves_bytes() {
    let (sk, vk) = sign::generate_keypair();
    let store = MemoryStore::new();

    let src = tempfile::tempdir().unwrap();
    let originals = write_model(src.path());

    let push_args = PushArgs {
        model_dir: src.path().to_path_buf(),
        name: "concord/e2e-model".into(),
        version: "v1.0.0".into(),
        key_id: "eu:test-operator:k/2026-01".into(),
        residency: "eu".into(),
        license_spdx: "Apache-2.0".into(),
        issued_at: Some("2026-05-26T12:00:00Z".into()),
        base_model: None,
        quant: None,
    };
    let (manifest, _signed_bytes, pstats) = push(&store, &push_args, &sk).await.unwrap();

    assert_eq!(manifest.shards.len(), originals.len());
    assert_eq!(pstats.chunks_total, originals.len() as u64);
    // First push: every chunk is new.
    assert_eq!(pstats.chunks_uploaded, originals.len() as u64);
    assert_eq!(pstats.chunks_skipped, 0);
    assert!(manifest.signature.is_some());

    // Pull into a fresh dir.
    let dst = tempfile::tempdir().unwrap();
    let pull_args = PullArgs {
        name: "concord/e2e-model".into(),
        version: "v1.0.0".into(),
        out_dir: dst.path().to_path_buf(),
        reverify: false,
    };
    let (pulled_manifest, pull_stats) = pull(&store, &pull_args, &vk).await.unwrap();

    assert_eq!(pull_stats.files, originals.len() as u64);
    let total_bytes: u64 = originals.values().map(|b| b.len() as u64).sum();
    assert_eq!(pull_stats.bytes, total_bytes);
    assert_eq!(pulled_manifest.manifest.name, "concord/e2e-model");

    // Byte-for-byte check on each file. push renames by role+format, so
    // we look the file up by what `shard_filename` produces; the test
    // model uses the canonical names so they match the originals 1:1.
    for (name, original) in &originals {
        let p = dst.path().join(name);
        assert!(p.exists(), "missing pulled file: {}", p.display());
        let got = std::fs::read(&p).unwrap();
        assert_eq!(
            &got,
            original,
            "byte mismatch for {} (got {} bytes, original {} bytes)",
            name,
            got.len(),
            original.len()
        );
    }
}

#[tokio::test]
async fn pull_rejects_wrong_pubkey() {
    let (sk, _vk) = sign::generate_keypair();
    let (_, other_vk) = sign::generate_keypair();
    let store = MemoryStore::new();

    let src = tempfile::tempdir().unwrap();
    write_model(src.path());

    push(
        &store,
        &PushArgs {
            model_dir: src.path().to_path_buf(),
            name: "concord/wrong-key".into(),
            version: "v1".into(),
            key_id: "eu:t:k".into(),
            residency: "eu".into(),
            license_spdx: "Apache-2.0".into(),
            issued_at: Some("2026-05-26T12:00:00Z".into()),
            base_model: None,
            quant: None,
        },
        &sk,
    )
    .await
    .unwrap();

    let dst = tempfile::tempdir().unwrap();
    let err = pull(
        &store,
        &PullArgs {
            name: "concord/wrong-key".into(),
            version: "v1".into(),
            out_dir: dst.path().to_path_buf(),
            reverify: false,
        },
        &other_vk,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("verify signature"),
        "expected verify failure, got: {err}"
    );
}

#[tokio::test]
async fn second_push_is_full_dedup() {
    // Same dir, second push → store byte-count unchanged.
    let (sk, _vk) = sign::generate_keypair();
    let store = MemoryStore::new();
    let src = tempfile::tempdir().unwrap();
    write_model(src.path());

    let args = PushArgs {
        model_dir: src.path().to_path_buf(),
        name: "concord/dedup".into(),
        version: "v1".into(),
        key_id: "eu:t:k".into(),
        residency: "eu".into(),
        license_spdx: "Apache-2.0".into(),
        issued_at: Some("2026-05-26T12:00:00Z".into()),
        base_model: None,
        quant: None,
    };

    let (_, _, s1) = push(&store, &args, &sk).await.unwrap();
    let chunks_after_first = store.chunk_count();
    assert!(s1.chunks_uploaded > 0);

    let (_, _, s2) = push(&store, &args, &sk).await.unwrap();
    // PUT-always behaviour: second push re-uploads every chunk, but
    // because the storage layer is content-addressed by blake3 the on-disk
    // chunk count is unchanged. This guards the backend-side dedup
    // guarantee even though client-side skip is gone.
    assert_eq!(s2.chunks_uploaded, s2.chunks_total);
    assert_eq!(s2.chunks_skipped, 0);
    assert_eq!(store.chunk_count(), chunks_after_first);
}

#[tokio::test]
async fn second_pull_skips_completed_shards() {
    // Push a tiny model into a MemoryStore, then pull it twice into the
    // same out_dir.  The second pull must be a no-op (on_wire == 0)
    // because pull_shard detects the Complete ResumeMarker + final file
    // and returns early before any chunk or cache lookup.
    //
    // We do NOT assert s1.on_wire > 0 for the first pull because
    // chunk_cache_dir() reads XDG_CACHE_HOME/HOME from the process env —
    // environment mutation is unsafe in multi-threaded async tests, so we
    // cannot safely isolate the chunk cache here.  The first pull may be
    // served from the cache (on_wire == 0) or from the store (on_wire > 0)
    // depending on the local cache state.  That is acceptable: the key
    // invariant under test is that the SECOND pull into the same out_dir
    // yields on_wire == 0 regardless of how the first one was served.
    // (Skip-done triggers before any cache or store access; it returns 0
    // wire bytes whether the prior pull was a store fetch or a cache hit.)
    let (sk, vk) = sign::generate_keypair();
    let store = MemoryStore::new();

    let src = tempfile::tempdir().unwrap();
    let originals = write_model(src.path());

    push(
        &store,
        &PushArgs {
            model_dir: src.path().to_path_buf(),
            name: "concord/resume-model".into(),
            version: "v1.0.0".into(),
            key_id: "eu:test-operator:k/2026-01".into(),
            residency: "eu".into(),
            license_spdx: "Apache-2.0".into(),
            issued_at: Some("2026-05-26T12:00:00Z".into()),
            base_model: None,
            quant: None,
        },
        &sk,
    )
    .await
    .unwrap();

    let out = tempfile::tempdir().unwrap();
    let args = PullArgs {
        name: "concord/resume-model".into(),
        version: "v1.0.0".into(),
        out_dir: out.path().to_path_buf(),
        reverify: false,
    };

    // First pull: completes the shards (store fetch or cache hit).
    let (_m1, s1) = pull(&store, &args, &vk).await.unwrap();
    let total_bytes: u64 = originals.values().map(|b| b.len() as u64).sum();
    assert_eq!(
        s1.bytes, total_bytes,
        "first pull reports correct logical bytes"
    );

    // Second pull into the SAME out_dir: ResumeMarker is Complete and the
    // final files exist → pull_shard short-circuits before any fetch.
    // This holds regardless of the chunk cache: skip-done fires first.
    let (_m2, s2) = pull(&store, &args, &vk).await.unwrap();
    assert_eq!(
        s2.on_wire, 0,
        "second pull is fully skip-done — zero wire bytes"
    );
    assert_eq!(
        s2.bytes, s1.bytes,
        "same logical bytes reported on second pull"
    );
}
