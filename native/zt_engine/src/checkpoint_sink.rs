//! Step 1.4a: crash-resume checkpoint storage for non-Linux platforms.
//!
//! The Linux engine keeps its historic checkpoint writer in
//! `crate::execute` (sudo/pkexec ownership, `O_EXCL` temp file, JSON shape).
//! Windows has no such module, so this file provides the same **on-disk
//! contract** behind the platform-neutral [`CheckpointSink`] trait that
//! `wipe_core` consumes:
//!
//! ```json
//! {
//!   "job_id": "...",
//!   "device_size": 0,
//!   "device_id_hash": "<sha256(serial) lowercase hex>",
//!   "bytes_done": 0,
//!   "timestamp": 0
//! }
//! ```
//!
//! The directory comes from `ZT_CHECKPOINT_DIR` when set (the Flutter app
//! always sets it); otherwise `%PROGRAMDATA%\ZeroTrace\checkpoints` on
//! Windows, then the OS temp directory. No device access, no Win32 calls.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The checkpoint payload. Field order and names are part of the contract
/// with the Dart side (`test/fixtures/active_checkpoint.json`): keep them
/// identical to the Linux writer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckpointData {
    pub job_id: String,
    pub device_size: u64,
    pub device_id_hash: String,
    pub bytes_done: u64,
    pub timestamp: u64,
}

/// Crash-resume checkpoint destination. `wipe_core` only ever calls these
/// two methods; the implementation owns all storage details.
pub trait CheckpointSink: Send + Sync {
    /// Persist progress. Implementations must never fail the wipe: errors
    /// are swallowed (a checkpoint is best effort by contract).
    fn write(&self, job_id: &str, device_serial: &str, device_size: u64, bytes_done: u64);
    /// Remove the checkpoint after a fully successful wipe.
    fn remove(&self);
}

/// File-based sink: one `active_checkpoint.json` per checkpoint directory.
pub struct FileCheckpointSink {
    dir: PathBuf,
}

impl FileCheckpointSink {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Directory resolution: `ZT_CHECKPOINT_DIR`, then
    /// `%PROGRAMDATA%\ZeroTrace\checkpoints`, then the OS temp directory.
    pub fn from_env() -> Self {
        Self::new(checkpoint_dir_from(
            std::env::var("ZT_CHECKPOINT_DIR").ok(),
            std::env::var("PROGRAMDATA").ok(),
            std::env::var("TEMP")
                .ok()
                .or_else(|| std::env::var("TMP").ok()),
        ))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn final_path(&self) -> PathBuf {
        self.dir.join("active_checkpoint.json")
    }

    fn tmp_path(&self) -> PathBuf {
        self.dir
            .join(format!("active_checkpoint.{}.tmp", std::process::id()))
    }
}

/// Pure directory policy (unit-tested without touching the environment).
pub fn checkpoint_dir_from(
    env_dir: Option<String>,
    program_data: Option<String>,
    temp: Option<String>,
) -> PathBuf {
    if let Some(dir) = env_dir {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir.trim());
        }
    }
    if let Some(base) = program_data {
        if !base.trim().is_empty() {
            return PathBuf::from(base.trim())
                .join("ZeroTrace")
                .join("checkpoints");
        }
    }
    if let Some(temp) = temp {
        if !temp.trim().is_empty() {
            return PathBuf::from(temp.trim()).join("zero_trace");
        }
    }
    std::env::temp_dir().join("zero_trace")
}

impl CheckpointSink for FileCheckpointSink {
    fn write(&self, job_id: &str, device_serial: &str, device_size: u64, bytes_done: u64) {
        let _ = fs::create_dir_all(&self.dir);

        let checkpoint = CheckpointData {
            job_id: job_id.to_string(),
            device_size,
            device_id_hash: format!("{:x}", Sha256::digest(device_serial.as_bytes())),
            bytes_done,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        let payload = match serde_json::to_string_pretty(&checkpoint) {
            Ok(payload) => payload,
            Err(_) => return,
        };

        let tmp = self.tmp_path();
        let _ = fs::remove_file(&tmp);
        if fs::write(&tmp, payload).is_err() {
            return;
        }
        // Windows `fs::rename` uses MoveFileExW(MOVEFILE_REPLACE_EXISTING),
        // but an antivirus/indexer can briefly hold the destination; retry
        // once after deleting it.
        if fs::rename(&tmp, self.final_path()).is_err() {
            let _ = fs::remove_file(self.final_path());
            let _ = fs::rename(&tmp, self.final_path());
        }
    }

    fn remove(&self) {
        let _ = fs::remove_file(self.final_path());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(path).expect("read checkpoint"))
            .expect("parse checkpoint")
    }

    #[test]
    fn checkpoint_dir_precedence() {
        assert_eq!(
            checkpoint_dir_from(Some(" D:\\state ".into()), Some("C:\\PD".into()), None),
            PathBuf::from("D:\\state")
        );
        assert_eq!(
            checkpoint_dir_from(Some("  ".into()), Some("C:\\PD".into()), None),
            PathBuf::from("C:\\PD")
                .join("ZeroTrace")
                .join("checkpoints")
        );
        assert_eq!(
            checkpoint_dir_from(None, None, Some("C:\\Temp".into())),
            PathBuf::from("C:\\Temp").join("zero_trace")
        );
        assert!(!checkpoint_dir_from(None, None, None).as_os_str().is_empty());
    }

    #[test]
    fn file_sink_writes_the_linux_checkpoint_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = FileCheckpointSink::new(dir.path());
        sink.write("job-1", "SERIAL-1", 16_000_000_000, 3_500_000_000);

        let path = dir.path().join("active_checkpoint.json");
        let value = read_json(&path);

        let mut keys: Vec<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "bytes_done",
                "device_id_hash",
                "device_size",
                "job_id",
                "timestamp"
            ]
        );
        assert_eq!(value["job_id"], "job-1");
        assert_eq!(value["device_size"], 16_000_000_000u64);
        assert_eq!(value["bytes_done"], 3_500_000_000u64);
        assert_eq!(
            value["device_id_hash"],
            format!("{:x}", Sha256::digest(b"SERIAL-1"))
        );
        assert!(value["timestamp"].as_u64().is_some());

        // No temp file may linger.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files linger: {leftovers:?}");

        // A second write replaces the payload atomically.
        sink.write("job-2", "SERIAL-1", 16_000_000_000, 4_000_000_000);
        let value = read_json(&path);
        assert_eq!(value["job_id"], "job-2");
        assert_eq!(value["bytes_done"], 4_000_000_000u64);

        sink.remove();
        assert!(!path.exists(), "remove() must delete the checkpoint");
        // Removing twice is a no-op, never a panic.
        sink.remove();
    }
}
