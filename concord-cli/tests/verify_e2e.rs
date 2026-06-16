//! End-to-end test: sign a manifest in-process, write to a temp file,
//! invoke the `concord` binary's `verify` subcommand against it.

use std::path::PathBuf;
use std::process::Command;

use concord_core::manifest::{License, Manifest, ManifestHeader, Shard};
use concord_core::sign;

fn bin() -> PathBuf {
    // `cargo test` puts the binary at target/{debug,release}/concord
    // (or .../examples/...). Prefer CARGO_BIN_EXE_<bin-name> when set
    // (cargo provides this for integration tests).
    if let Some(p) = option_env!("CARGO_BIN_EXE_concord") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_BIN_EXE_concord"))
}

fn sample() -> Manifest {
    Manifest {
        manifest: ManifestHeader {
            name: "test/e2e-model".into(),
            version: "v1.0.0".into(),
            protocol: "concord/1".into(),
            issuer: "eu:test-operator".into(),
            issued_at: "2026-05-26T12:00:00Z".into(),
        },
        license: License {
            spdx: "Apache-2.0".into(),
            residency: "eu".into(),
            export: "unrestricted".into(),
        },
        shards: vec![Shard {
            role: "weights".into(),
            format: "safetensors".into(),
            path: None,
            parts: Some(1),
            size: 4096,
            merkle: "b3:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
            chunks: vec![],
        }],
        pull_policy: None,
        supersedes: None,
        signature: None,
    }
}

#[test]
fn cli_verify_succeeds_with_correct_pubkey() {
    let (sk, vk) = sign::generate_keypair();
    let signed = sign::sign(sample(), "eu:test-operator:k/2026-01", &sk).unwrap();
    let bytes = signed.to_signed_bytes().unwrap();

    let tmp = tempfile_path("manifest_ok.toml");
    std::fs::write(&tmp, &bytes).unwrap();

    let pubkey_hex = hex::encode(vk.to_bytes());
    let out = Command::new(bin())
        .args(["verify", tmp.to_str().unwrap(), "--pubkey", &pubkey_hex])
        .output()
        .expect("run concord verify");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "verify should succeed; stdout={stdout}\nstderr={stderr}"
    );
    assert!(stdout.contains("signature: OK"), "stdout was: {stdout}");
    assert!(stdout.contains("test/e2e-model"));

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn cli_verify_fails_with_wrong_pubkey() {
    let (sk, _) = sign::generate_keypair();
    let (_, other_vk) = sign::generate_keypair();
    let signed = sign::sign(sample(), "eu:test-operator:k/2026-01", &sk).unwrap();
    let bytes = signed.to_signed_bytes().unwrap();

    let tmp = tempfile_path("manifest_bad.toml");
    std::fs::write(&tmp, &bytes).unwrap();

    let wrong_pubkey_hex = hex::encode(other_vk.to_bytes());
    let out = Command::new(bin())
        .args([
            "verify",
            tmp.to_str().unwrap(),
            "--pubkey",
            &wrong_pubkey_hex,
        ])
        .output()
        .expect("run concord verify");

    assert!(
        !out.status.success(),
        "verify should fail with wrong pubkey"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("signature verification failed"),
        "expected failure message; got: {combined}"
    );

    let _ = std::fs::remove_file(&tmp);
}

fn tempfile_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("concord-test-{}-{}", std::process::id(), name));
    p
}
