//! Zero Trace 2.0 — Rust Execution Engine
//!
//! This crate is the source of truth for all destructive sanitization operations
//! and post-sanitization verification.
//!
//! Modules:
//! - `detect`: Device capability probing via smartctl, hdparm, nvme-cli, sedutil-cli, mmc-utils
//! - `execute`: Firmware/software sanitize command execution with dry-run support
//! - `verify`: Raw LBA sector sampling with O_DIRECT and SHA-256 fingerprinting
//! - `partitions`: A2 partition enumeration (sysfs + mountinfo + swaps)
//!
//! Note: audit certificates are signed by the Flutter application itself with a
//! local ECDSA P-256 / SHA-256 keypair (`lib/services/certificate_service.dart`).
//! The engine does not sign certificates.

// Phase C: cross-platform core — the shared guard chain, the backend trait
// and its Linux/stub implementations compile on every target. The engine
// modules below are Linux-only (the sole real backend).
pub mod backend;
pub mod guard;
pub mod types;

#[cfg(target_os = "linux")]
pub mod detect;
#[cfg(target_os = "linux")]
pub mod execute;
#[cfg(target_os = "linux")]
pub mod partitions;
#[cfg(target_os = "linux")]
pub mod verify;

// Cross-platform core types (guard chain + backends; moved out of `execute`
// so Windows/Android stub targets compile).
pub use types::{
    BlockWriter, BootEnvironment, ValidatedPartitionTarget, PartitionTargetParams,
};

/// Re-export primary types for FFI consumers
#[cfg(target_os = "linux")]
pub use detect::{DeviceCapabilities, BusType, SmartHealth, DurationClass};
#[cfg(target_os = "linux")]
pub use execute::{
    ExecutionReport, ProgressEvent, ExecutionPhase, SanitizeAction, AtaSanitizeAction,
    OverwritePattern, FsContext, check_boot_disk_protection, check_boot_disk_protection_ctx,
    PartitionRangeWriter, compute_partition_table_fingerprint,
    software_overwrite_partition, software_overwrite_partition_ctx, ALLOWED_PARTITION_METHODS,
    is_mbr_extended_partition, unmount_target_partition_and_holders,
    EngineMethod, validate_partition_method, FileBlockWriter, execute_writer_overwrite,
    resolve_parent_disk, resolve_parent_serial, map_open_excl_error,
    detect_boot_environment_ctx,
    // A6: discard execution path
    DiscardChunk, build_discard_chunks, read_discard_geometry,
    discard_erase, discard_erase_ctx, discard_erase_partition, discard_erase_partition_ctx,
    validate_partition_target,
};
#[cfg(target_os = "linux")]
pub use verify::{VerificationReport, SampleResult};
#[cfg(target_os = "linux")]
pub use partitions::{
    detect_table_type, enumerate_partitions_ctx, DiskEnumerationReport, PartitionEntry,
    // B1: Windows-friendly partition-type classification + volume probing
    classify_gpt_guid, classify_mbr_type, classify_mbr_partition, format_guid_mixed_endian,
    parse_gpt_header, parse_gpt_entry, parse_mbr_entries, probe_volume_header,
    GptHeader, GptPartitionEntry, MbrPartitionEntry, VolumeProbe,
    // B1 optional: read-only Windows-install probe
    classify_windows_root, probe_windows_volume, WindowsProbe,
};
