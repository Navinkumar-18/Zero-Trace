//! Phase C: cross-platform core types shared by the guard chain
//! (`crate::guard`), the backends (`crate::backend`) and the Linux-only
//! execution module (`crate::execute`).
//!
//! Everything here must compile on **every** target — the Windows/Android
//! stub backends and `cargo check` for those targets rely on it. Only pure
//! data types, traits and string/policy helpers live here; no syscalls.

use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum ExecuteError {
    #[error("Boot disk protection: refusing to operate on OS root device {0}")]
    BootDiskProtection(String),
    #[error("Confirmation token mismatch: expected serial of target device")]
    ConfirmationMismatch,
    #[error("Command execution failed: {0}")]
    CommandFailed(String),
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Hardware I/O error (EIO): {0}")]
    HardwareIo(String),
    #[error("Device disconnected (ENODEV): {0}")]
    DeviceDisconnected(String),
    #[error("Premature end of device (ENOSPC): {0}")]
    PrematureEndOfDevice(String),
    #[error("Progress channel closed")]
    ChannelClosed,
    #[error("Identity mismatch: {0}")]
    IdentityMismatch(String),
    /// Phase F: filesystem recreation is only allowed after this exact target
    /// was wiped and verification passed in the current job.
    #[error("Filesystem recreation refused: target was not just wiped and verified in this job")]
    NotWipedAndVerified,
    /// Phase F: formatting a partition that is currently mounted (or swap
    /// active) would corrupt a live filesystem.
    #[error("Filesystem recreation refused: target is mounted or active as swap: {0}")]
    TargetMounted(String),
    /// Phase F: the target is (or belongs to) the running system/live disk.
    #[error("Filesystem recreation refused: target is a system partition: {0}")]
    SystemPartition(String),
    /// Phase F: the validated scope and the node handed to the formatter do
    /// not agree (e.g. partition scope with the whole-disk device node).
    #[error("Filesystem recreation refused: target scope mismatch: {0}")]
    FilesystemScopeMismatch(String),
    /// Phase F: unsupported filesystem/table type.
    #[error("Unsupported filesystem recreation: {0}")]
    UnsupportedFilesystem(String),
    /// Phase F: partition-table creation/format cannot proceed for this target.
    #[error("Filesystem recreation failed: {0}")]
    FilesystemRecreationFailed(String),
}

// ---------------------------------------------------------------------------
// Phase F: optional filesystem recreation after a verified wipe
// ---------------------------------------------------------------------------

/// Filesystem types supported by the post-wipe recreate step. Parsing is
/// deliberately strict: aliases are normalized, anything else is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilesystemType {
    Vfat32,
    Exfat,
    Ntfs,
    Ext4,
}

impl FilesystemType {
    /// Stable certificate/UI token.
    pub fn as_str(self) -> &'static str {
        match self {
            FilesystemType::Vfat32 => "vfat",
            FilesystemType::Exfat => "exfat",
            FilesystemType::Ntfs => "ntfs",
            FilesystemType::Ext4 => "ext4",
        }
    }

    /// Human-readable name used in reports.
    pub fn display_name(self) -> &'static str {
        match self {
            FilesystemType::Vfat32 => "FAT32",
            FilesystemType::Exfat => "exFAT",
            FilesystemType::Ntfs => "NTFS",
            FilesystemType::Ext4 => "ext4",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, ExecuteError> {
        match raw
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_', ' '], "")
            .as_str()
        {
            "vfat" | "fat" | "fat32" | "vfat32" => Ok(FilesystemType::Vfat32),
            "exfat" => Ok(FilesystemType::Exfat),
            "ntfs" => Ok(FilesystemType::Ntfs),
            "ext4" => Ok(FilesystemType::Ext4),
            other => Err(ExecuteError::UnsupportedFilesystem(format!(
                "filesystem type '{}' (supported: vfat/FAT32, exfat, ntfs, ext4)",
                other
            ))),
        }
    }
}

/// Partition-table type for the optional whole-device recreation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionTableType {
    Gpt,
    Mbr,
}

impl PartitionTableType {
    pub fn as_str(self) -> &'static str {
        match self {
            PartitionTableType::Gpt => "gpt",
            PartitionTableType::Mbr => "mbr",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, ExecuteError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "gpt" => Ok(PartitionTableType::Gpt),
            "mbr" | "msdos" | "dos" => Ok(PartitionTableType::Mbr),
            other => Err(ExecuteError::UnsupportedFilesystem(format!(
                "partition table type '{}' (supported: gpt, mbr)",
                other
            ))),
        }
    }
}

/// Phase F: signed certificate/audit record for the optional format step.
/// Kept separate from the wipe evidence so it can be included only when the
/// operator actually created a filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemRecreationRecord {
    /// External formatter tool that was executed.
    pub tool: String,
    pub fs_type: String,
    pub label: String,
    /// RFC3339/ISO-8601 timestamp of the format step.
    pub time: String,
    /// Always true for a record that reached the tool; explicit evidence that
    /// the wipe was verified before formatting.
    pub sanitization_verified_before_format: bool,
    /// "full" or "partial" (the wipe scope).
    pub scope: String,
    /// True when this record also created a new partition table.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partition_table_created: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_table_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Guard identity & boot environment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GuardIdentity {
    pub canonical_path: String,
    pub st_rdev: libc::dev_t,
    pub major: u32,
    pub minor: u32,
    pub is_block: bool,
    pub device_serial: String,
    pub st_ino: u64,
}

/// Boot environment classification (A3b). The backend *reports* the
/// environment (cmdline markers, root fs type); the shared guard chain
/// decides what each classification allows:
/// - `Normal`: the booted system's own disks are protected; other disks may
///   be sanitized.
/// - `Live`: booted from a live medium — the medium itself and anything
///   still mounted/swap-active stay protected.
/// - `Container`: overlay root with no live marker — refuse everything
///   (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootEnvironment {
    Normal,
    Live,
    Container,
}

// ---------------------------------------------------------------------------
// Partition target params / validated views
// ---------------------------------------------------------------------------

/// Expected partition identity captured at UI selection time and re-checked
/// immediately before every destructive open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionTargetParams {
    pub expected_partition_num: u32,
    pub expected_start_sector: u64,
    pub expected_size_sectors: u64,
    pub expected_partuuid: Option<String>,
    pub expected_table_fingerprint: String,
}

/// Validated partition target: geometry cross-checked against sysfs, PARTUUID
/// and partition-table fingerprint, MBR extended containers refused, sizes
/// aligned to the logical block size, plus the pinned guard identity.
/// Shared by the partition overwrite and A6 discard execution paths.
pub struct ValidatedPartitionTarget {
    pub parent_name: String,
    pub start_bytes: u64,
    pub size_bytes: u64,
    pub logical_block_size: u64,
    pub guard_identity: GuardIdentity,
}

// ---------------------------------------------------------------------------
// Block writer trait (backends supply an implementation; execution paths
// consume it)
// ---------------------------------------------------------------------------

pub trait BlockWriter: Send + Sync {
    fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<usize, io::Error>;
    fn sync_data(&mut self) -> Result<(), io::Error>;
    fn flush_buffers(&mut self) -> Result<(), io::Error>;
    fn total_size(&self) -> Result<u64, io::Error>;
    fn logical_block_size(&self) -> u32 {
        512
    }
    fn io_mode(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Pure helpers used by the guard chain and backends (no I/O)
// ---------------------------------------------------------------------------

/// Helper to decode major number from st_rdev / dev_t (u64-normalized so
/// the guard chain compiles on targets where `libc::dev_t` is 32-bit).
pub fn dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

/// Helper to decode minor number from st_rdev / dev_t.
pub fn dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

/// Parse a "major:minor" decimal ASCII string into a (major, minor) tuple.
pub fn parse_major_minor(s: &str) -> Option<(u32, u32)> {
    let trimmed = s.trim();
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let maj = parts[0].trim().parse::<u32>().ok()?;
    let min = parts[1].trim().parse::<u32>().ok()?;
    Some((maj, min))
}

/// Determine if a mount point is allowlisted as an unmountable target.
/// Only mounts under /mnt, /media, or /run/media/* are unmountable.
/// Live-media mounts (/run/live/medium, /run/archiso, etc.) are explicitly protected.
pub fn is_mount_unmountable_allowlisted(mount_point: &str) -> bool {
    // Explicitly protect live-media mounts
    if mount_point.starts_with("/run/live")
        || mount_point.starts_with("/run/archiso")
        || mount_point.contains("/live/")
        || mount_point.contains("/archiso/")
        || mount_point.contains("/casper/")
    {
        return false;
    }

    if mount_point == "/mnt" || mount_point.starts_with("/mnt/") {
        return true;
    }
    if mount_point == "/media" || mount_point.starts_with("/media/") {
        return true;
    }
    if mount_point == "/run/media" || mount_point.starts_with("/run/media/") {
        return true;
    }

    false
}
