//! Zero Trace 2.0 — Rust Execution Engine
//!
//! This crate is the source of truth for all destructive sanitization operations,
//! post-sanitization verification, and cryptographic certificate signing.
//!
//! Modules:
//! - `detect`: Device capability probing via smartctl, hdparm, nvme-cli, sedutil-cli, mmc-utils
//! - `execute`: Firmware/software sanitize command execution with dry-run support
//! - `verify`: Raw LBA sector sampling with O_DIRECT and SHA-256 fingerprinting
//! - `certificate`: HMAC-SHA256 and Ed25519 certificate signing

pub mod detect;
pub mod execute;
pub mod verify;
pub mod certificate;

/// Re-export primary types for FFI consumers
pub use detect::{DeviceCapabilities, BusType, SmartHealth, DurationClass};
pub use execute::{
    ExecutionReport, ProgressEvent, ExecutionPhase, SanitizeAction, AtaSanitizeAction,
    OverwritePattern, FsContext, check_boot_disk_protection, check_boot_disk_protection_ctx,
    PartitionRangeWriter, PartitionTargetParams, compute_partition_table_fingerprint,
    software_overwrite_partition, software_overwrite_partition_ctx, ALLOWED_PARTITION_METHODS,
    is_mbr_extended_partition, unmount_target_partition_and_holders,
    EngineMethod, validate_partition_method, BlockWriter, FileBlockWriter, execute_writer_overwrite,
};
pub use verify::{VerificationReport, SampleResult};
pub use certificate::{SignedCertificate, SigningMethod};
