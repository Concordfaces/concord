//! Per-shard resume state for `concord pull`, stored under `<out_dir>/.concord/`.

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
        let m: ResumeMarker = serde_json::from_slice(&raw)
            .inspect_err(|e| tracing::warn!(?path, %e, "corrupt resume marker — starting fresh"))
            .ok()?;
        if m.version != MARKER_VERSION {
            tracing::debug!(
                ?path,
                version = m.version,
                "resume marker version mismatch — starting fresh"
            );
            return None;
        }
        Some(m)
    }

    /// Atomically persist the marker (temp file + rename) so a crash mid-write
    /// never leaves a corrupt marker.
    /// Marker durability depends on OS write-back; worst case on power-loss is a re-download (the .part is fsync'd separately), never corruption.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec(self).context("serialize resume marker")?;
        std::fs::write(&tmp, &data).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename marker → {}", path.display()))?;
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
    /// Compute the final output path (`<out_dir>/<output_name>`) plus the
    /// transient `.part`/marker paths under `<out_dir>/.concord/`. The transient
    /// files are keyed on the shard INDEX (not the output name) so two shards
    /// resolving to the same output name never collide on a `.part`.
    pub fn new(out_dir: &Path, idx: usize, output_name: &str) -> Self {
        let state = out_dir.join(STATE_DIR);
        Self {
            final_path: out_dir.join(output_name),
            part_path: state.join(format!("{idx}.part")),
            marker_path: state.join(format!("{idx}.json")),
        }
    }

    /// The `.concord/` state directory for an out_dir.
    pub fn state_dir(out_dir: &Path) -> PathBuf {
        out_dir.join(STATE_DIR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_paths_layout() {
        let p = ShardPaths::new(std::path::Path::new("/out"), 3, "tok/tokenizer.json");
        assert_eq!(
            p.final_path,
            std::path::Path::new("/out/tok/tokenizer.json")
        );
        // Transient files keyed on the shard index, not the (possibly colliding)
        // output name.
        assert_eq!(p.part_path, std::path::Path::new("/out/.concord/3.part"));
        assert_eq!(p.marker_path, std::path::Path::new("/out/.concord/3.json"));
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
        assert_eq!(
            ResumeMarker::load(std::path::Path::new("/no/such.json")),
            None
        );
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
