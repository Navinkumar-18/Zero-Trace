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
