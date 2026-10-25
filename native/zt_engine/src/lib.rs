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
pub use types::{BlockWriter, BootEnvironment, PartitionTargetParams, ValidatedPartitionTarget};

/// Re-export primary types for FFI consumers
#[cfg(target_os = "linux")]
pub use detect::{BusType, DeviceCapabilities, DurationClass, SmartHealth};
#[cfg(target_os = "linux")]
pub use execute::{
    adopt_verified_wipe_receipt,
    build_discard_chunks,
    check_boot_disk_protection,
    check_boot_disk_protection_ctx,
    compute_partition_table_fingerprint,
    detect_boot_environment_ctx,
    discard_erase,
    discard_erase_ctx,
    discard_erase_partition,
    discard_erase_partition_ctx,
    execute_writer_overwrite,
    is_mbr_extended_partition,
    map_open_excl_error,
    mark_wiped_and_verified,
    read_discard_geometry,
    read_verified_wipe_receipt,
    record_verified_wipe,
    recreate_filesystem,
    recreate_filesystem_with,
    recreate_whole_device,
    recreate_whole_device_with,
    resolve_parent_disk,
    resolve_parent_serial,
    software_overwrite_partition,
    software_overwrite_partition_ctx,
    unmount_target_partition_and_holders,
    validate_partition_method,
    validate_partition_target,
    verified_wipe_stamp_for_path,
    write_verified_wipe_receipt,
    AtaSanitizeAction,
    // A6: discard execution path
    DiscardChunk,
    EngineMethod,
    ExecutionPhase,
    ExecutionReport,
    FileBlockWriter,
    // Phase F: optional post-wipe filesystem recreation
    FilesystemRecreationReport,
    FsContext,
    OverwritePattern,
    PartitionRangeWriter,
    ProgressEvent,
    SanitizeAction,
    VerifiedWipeStamp,
    ALLOWED_PARTITION_METHODS,
};
#[cfg(target_os = "linux")]
pub use partitions::{
    // B1: Windows-friendly partition-type classification + volume probing
    classify_gpt_guid,
    classify_mbr_partition,
    classify_mbr_type,
    // B1 optional: read-only Windows-install probe
    classify_windows_root,
    detect_table_type,
    enumerate_partitions_ctx,
    format_guid_mixed_endian,
    parse_gpt_entry,
    parse_gpt_header,
    parse_mbr_entries,
    probe_volume_header,
    probe_windows_volume,
    DiskEnumerationReport,
    GptHeader,
    GptPartitionEntry,
    MbrPartitionEntry,
    PartitionEntry,
    VolumeProbe,
    WindowsProbe,
};
#[cfg(target_os = "linux")]
pub use types::{FilesystemRecreationRecord, FilesystemType, PartitionTableType};
#[cfg(target_os = "linux")]
pub use verify::{SampleResult, VerificationReport};
