//! Step 1.4a: Windows `sanitize --dry-run` — full guard validation, then the
//! same simulated report as the Linux dry run, with **no handle opened for
//! write, no lock and no dismount**. Step 1.4b adds the real volume writer
//! behind this same validation.
//!
//! `device_serial` is deliberately absent: a Windows volume target is pinned
//! by its volume GUID + disk/partition identity, not by a drive serial. The
//! CLI still accepts the Linux positional argument for parity and ignores it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::backend::BlockBackend;
use crate::guard::{
    resolve_windows_volume_target, validate_windows_volume_target, WindowsVolumeTargetParams,
};
use crate::types::ExecuteError;
use crate::wipe_core::{ExecutionPhase, ExecutionReport, OverwritePattern, ProgressEvent};

/// Simulated progress events (in order) plus the Linux-shaped report.
pub struct DryRunOutcome {
    pub events: Vec<ProgressEvent>,
    pub report: ExecutionReport,
}

fn progress_event(phase: ExecutionPhase, message: &str) -> ProgressEvent {
    ProgressEvent {
        schema_version: 2,
        phase,
        bytes_done: 0,
        bytes_total: 0,
        percent: None,
        speed_bytes_per_sec: 0.0,
        eta_seconds: None,
        message: message.to_string(),
        is_heartbeat: false,
    }
}

fn parse_method(method: &str) -> Result<(u8, OverwritePattern), ExecuteError> {
    match method {
        "overwrite-zero" => Ok((1, OverwritePattern::Zeros)),
        "overwrite-random" => Ok((1, OverwritePattern::Random)),
        "overwrite-3pass" => Ok((3, OverwritePattern::MultiPass3)),
        other => Err(ExecuteError::UnsupportedOperation(format!(
            "Method '{}' is not available for a Windows volume target; use overwrite-zero, overwrite-random or overwrite-3pass",
            other
        ))),
    }
}

fn cancelled(start: Instant, method_name: &str, mut events: Vec<ProgressEvent>) -> DryRunOutcome {
    events.push(progress_event(
        ExecutionPhase::FirmwareCommand,
        "Sanitization cancelled by user",
    ));
    DryRunOutcome {
        events,
        report: ExecutionReport {
            success: false,
            method_used: method_name.to_string(),
            command_log: vec![format!(
                "[DRY RUN] Native block overwrite (cancelled) ({})",
                method_name
            )],
            stdout: String::new(),
            stderr: "Sanitization cancelled by user: partially wiped".to_string(),
            exit_code: 130,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: true,
            bytes_written: 0,
            io_mode: "dry_run".to_string(),
        },
    }
}

/// Runs the real guard validation for the volume selector, then simulates the
/// overwrite without touching the device.
pub fn windows_volume_dry_run(
    backend: &dyn BlockBackend,
    selector: &str,
    method: &str,
    confirmation_token: &str,
    same_disk_confirmation: Option<&str>,
    cancel_flag: Arc<AtomicBool>,
) -> Result<DryRunOutcome, ExecuteError> {
    let start = Instant::now();
    let (total_passes, pattern) = parse_method(method)?;

    // Full guard chain exactly as the real write path will run it.
    let volume_guid = resolve_windows_volume_target(backend, selector)?;
    validate_windows_volume_target(
        backend,
        &WindowsVolumeTargetParams {
            volume_guid,
            confirmation_token: confirmation_token.to_string(),
            same_disk_confirmation: same_disk_confirmation.map(str::to_string),
        },
    )?;

    let method_name = format!("Software Overwrite ({}-pass, {:?})", total_passes, pattern);
    let mut events = Vec::new();

    if cancel_flag.load(Ordering::SeqCst) {
        return Ok(cancelled(start, &method_name, events));
    }

    events.push(progress_event(
        ExecutionPhase::FirmwareCommand,
        "[DRY RUN] Starting simulated overwrite...",
    ));
    for pass in 1..=total_passes {
        if cancel_flag.load(Ordering::SeqCst) {
            return Ok(cancelled(start, &method_name, events));
        }
        events.push(progress_event(
            ExecutionPhase::FirmwareCommand,
            &format!(
                "[DRY RUN] Overwrite pass {} of {} complete",
                pass, total_passes
            ),
        ));
    }
    if cancel_flag.load(Ordering::SeqCst) {
        return Ok(cancelled(start, &method_name, events));
    }
    events.push(progress_event(
        ExecutionPhase::Flushing,
        "[DRY RUN] Flushing complete",
    ));
    if cancel_flag.load(Ordering::SeqCst) {
        return Ok(cancelled(start, &method_name, events));
    }
    events.push(progress_event(
        ExecutionPhase::Verification,
        "[DRY RUN] Post-verification complete",
    ));

    Ok(DryRunOutcome {
        events,
        report: ExecutionReport {
            success: true,
            method_used: method_name,
            command_log: vec![format!(
                "[DRY RUN] Native block overwrite: {} passes ({:?}) on {}",
                total_passes, pattern, selector
            )],
            stdout: "[DRY RUN] Overwrite simulated successfully".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: true,
            bytes_written: 0,
            io_mode: "dry_run".to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::mock::MockBackend;
    use crate::backend::windows_parse::{ParsedDriveLayout, ParsedPartition, PartitionStyle};
    use crate::backend::{
        BackendCapabilities, BitLockerLockState, DiskSetFact, ElevationFact, VolumeDriveType,
        VolumeFact, VolumeGuidSetFact, WindowsBootFacts, WindowsVolumeFacts,
    };
    use crate::wipe_core::report_exit_code;

    const GUID_E: &str = r"\\?\Volume{33333333-3333-3333-3333-333333333333}\";
    const BASIC_DATA_GUID: &str = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
    const SIZE_32GB: u64 = 32_000_000_000;

    fn volume_facts(disk: u32) -> WindowsVolumeFacts {
        WindowsVolumeFacts {
            volume_guid_path: GUID_E.to_string(),
            mount_points: VolumeFact::Known(vec![r"E:\".to_string()]),
            drive_letters: VolumeFact::Known(vec!['E']),
            label: VolumeFact::Known(Some("BACKUP".to_string())),
            filesystem: VolumeFact::Known(Some("NTFS".to_string())),
            total_bytes: VolumeFact::Known(SIZE_32GB),
            free_bytes: VolumeFact::Known(SIZE_32GB / 2),
            drive_type: VolumeFact::Known(VolumeDriveType::Removable),
            extent_count: VolumeFact::Known(1),
            disk_number: VolumeFact::Known(Some(disk)),
            partition_number: VolumeFact::Known(Some(1)),
            is_bitlocker: VolumeFact::Known(false),
            bitlocker_state: BitLockerLockState::NotEncrypted,
            is_system_volume: VolumeFact::Known(false),
            hosts_running_app: VolumeFact::Known(false),
        }
    }

    fn boot_facts(system_disks: Vec<u32>) -> WindowsBootFacts {
        WindowsBootFacts {
            system_disks: DiskSetFact::known(system_disks),
            boot_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            pagefile_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            hibernation_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            crashdump_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            app_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            pagefile_volumes: VolumeGuidSetFact::known(std::iter::empty::<String>()),
            hibernation_volumes: VolumeGuidSetFact::known(std::iter::empty::<String>()),
            crashdump_volumes: VolumeGuidSetFact::known(std::iter::empty::<String>()),
            elevated: ElevationFact::Known(true),
        }
    }

    fn backend(volume: &WindowsVolumeFacts, boot: WindowsBootFacts) -> MockBackend {
        let disk = volume
            .disk_number
            .as_known()
            .copied()
            .flatten()
            .unwrap_or(1);
        MockBackend::new()
            .with_capabilities(BackendCapabilities::full())
            .with_windows_boot_facts(boot)
            .with_windows_volumes(vec![volume.clone()])
            .with_windows_disk_layout(
                disk,
                ParsedDriveLayout {
                    style: PartitionStyle::Gpt,
                    partitions: vec![ParsedPartition {
                        partition_number: 1,
                        starting_offset: 1_048_576,
                        partition_length: SIZE_32GB,
                        start_sector: 2048,
                        size_sectors: SIZE_32GB / 512,
                        partition_type_guid: Some(BASIC_DATA_GUID.to_string()),
                        partition_type_mbr: None,
                    }],
                },
            )
            .with_windows_device(disk, Some("usb"))
            .with_geometry(&volume.volume_guid_path, SIZE_32GB, 512)
    }

    fn flag(set: bool) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(set))
    }

    #[test]
    fn dry_run_reports_the_linux_shape_without_writing() {
        let volume = volume_facts(1);
        let backend = backend(&volume, boot_facts(vec![0]));
        let outcome = windows_volume_dry_run(
            &backend,
            "E:",
            "overwrite-3pass",
            "E: BACKUP 32.0GB",
            None,
            flag(false),
        )
        .expect("dry run must succeed");

        assert!(outcome.report.success);
        assert!(outcome.report.dry_run);
        assert_eq!(outcome.report.exit_code, 0);
        assert_eq!(outcome.report.bytes_written, 0);
        assert_eq!(outcome.report.io_mode, "dry_run");
        assert_eq!(report_exit_code(&outcome.report), 0);
        assert!(outcome
            .report
            .command_log
            .iter()
            .all(|line| line.starts_with("[DRY RUN]")));

        // 1 start + 3 passes + flush + verification.
        assert_eq!(outcome.events.len(), 6);
        assert!(outcome
            .events
            .iter()
            .all(|event| event.message.starts_with("[DRY RUN]")));
        assert_eq!(
            outcome.events.last().unwrap().phase,
            ExecutionPhase::Verification
        );
    }

    #[test]
    fn dry_run_runs_the_full_guard_validation() {
        let volume = volume_facts(1);
        let backend = backend(&volume, boot_facts(vec![0]));

        let wrong_token = windows_volume_dry_run(
            &backend,
            "E:",
            "overwrite-zero",
            "E: WRONG 32.0GB",
            None,
            flag(false),
        );
        assert!(matches!(
            wrong_token,
            Err(ExecuteError::ConfirmationMismatch)
        ));

        let same_disk = windows_volume_dry_run(
            &backend_with_system_disk(&volume),
            "E:",
            "overwrite-zero",
            "E: BACKUP 32.0GB",
            None,
            flag(false),
        );
        assert!(matches!(
            same_disk,
            Err(ExecuteError::WindowsVolumeSameDiskConfirmation(_))
        ));

        let unknown_selector = windows_volume_dry_run(
            &backend,
            "Z:",
            "overwrite-zero",
            "Z: X 1.0GB",
            None,
            flag(false),
        );
        assert!(matches!(
            unknown_selector,
            Err(ExecuteError::DeviceNotFound(_))
        ));
    }

    fn backend_with_system_disk(volume: &WindowsVolumeFacts) -> MockBackend {
        backend(volume, boot_facts(vec![1]))
    }

    #[test]
    fn dry_run_refuses_methods_that_are_not_volume_overwrites() {
        let volume = volume_facts(1);
        let backend = backend(&volume, boot_facts(vec![0]));
        for method in [
            "discard",
            "ata-secure-erase",
            "nvme-sanitize-crypto",
            "not-a-method",
        ] {
            let result = windows_volume_dry_run(
                &backend,
                "E:",
                method,
                "E: BACKUP 32.0GB",
                None,
                flag(false),
            );
            assert!(
                matches!(result, Err(ExecuteError::UnsupportedOperation(_))),
                "method {} must be refused",
                method
            );
        }
    }

    #[test]
    fn cancelled_dry_run_maps_to_130() {
        let volume = volume_facts(1);
        let backend = backend(&volume, boot_facts(vec![0]));
        let outcome = windows_volume_dry_run(
            &backend,
            "E:",
            "overwrite-zero",
            "E: BACKUP 32.0GB",
            None,
            flag(true),
        )
        .expect("cancellation is a report");
        assert!(!outcome.report.success);
        assert!(outcome.report.dry_run);
        assert_eq!(outcome.report.exit_code, 130);
        assert_eq!(report_exit_code(&outcome.report), 130);
        assert_eq!(outcome.report.bytes_written, 0);
    }
}
