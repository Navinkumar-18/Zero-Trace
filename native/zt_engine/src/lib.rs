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

pub mod detect;
pub mod execute;
pub mod partitions;
pub mod verify;

/// Re-export primary types for FFI consumers
pub use detect::{DeviceCapabilities, BusType, SmartHealth, DurationClass};
pub use execute::{
    ExecutionReport, ProgressEvent, ExecutionPhase, SanitizeAction, AtaSanitizeAction,
    OverwritePattern, FsContext, check_boot_disk_protection, check_boot_disk_protection_ctx,
    PartitionRangeWriter, PartitionTargetParams, compute_partition_table_fingerprint,
    software_overwrite_partition, software_overwrite_partition_ctx, ALLOWED_PARTITION_METHODS,
    is_mbr_extended_partition, unmount_target_partition_and_holders,
    EngineMethod, validate_partition_method, BlockWriter, FileBlockWriter, execute_writer_overwrite,
    resolve_parent_disk, resolve_parent_serial, map_open_excl_error,
    BootEnvironment, detect_boot_environment_ctx,
    // A6: discard execution path
    DiscardChunk, build_discard_chunks, read_discard_geometry,
    discard_erase, discard_erase_ctx, discard_erase_partition, discard_erase_partition_ctx,
    validate_partition_target, ValidatedPartitionTarget,
};
pub use verify::{VerificationReport, SampleResult};
pub use partitions::{
    detect_table_type, enumerate_partitions_ctx, DiskEnumerationReport, PartitionEntry,
};
