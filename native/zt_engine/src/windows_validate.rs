//! Step 1.4a: `windows-validate` — read-only validation report.
//!
//! The CLI is a thin wrapper: this module owns the JSON shape and the exit
//! code so it can be unit-tested with [`MockBackend`](crate::backend::mock)
//! on every host. It never opens a handle, never locks, never dismounts and
//! never writes: the only backend calls are the read-only fact methods used
//! by the shared guard chain.

use serde::Serialize;

use crate::backend::BlockBackend;
use crate::backend::WindowsVolumeFacts;
use crate::guard::{
    inspect_windows_volume_target, resolve_windows_volume_target, validate_windows_volume_target,
    WindowsVolumeIdentity, WindowsVolumeInspection, WindowsVolumeTargetParams,
    WindowsVolumeWarnings,
};
use crate::types::ExecuteError;

/// Machine-readable refusal (variant + human message).
#[derive(Debug, Clone, Serialize)]
pub struct RefusalInfo {
    pub variant: String,
    pub message: String,
}

/// One `WINDOWS_VALIDATE:{json}` payload.
#[derive(Debug, Clone, Serialize)]
pub struct ValidateReport {
    /// `"ok"` only when the **full** guard validation (including every typed
    /// confirmation) passed; `"refused"` otherwise.
    pub result: &'static str,
    pub refusal: Option<RefusalInfo>,
    /// The selector exactly as the caller typed it.
    pub selector: String,
    /// Resolved `\\?\Volume{GUID}\` when the selector resolved.
    pub volume_guid: Option<String>,
    /// Canonical required token: `<letter>: <label> <size>`.
    pub required_confirmation: Option<String>,
    /// True when the volume shares a physical disk with the system volume.
    pub same_disk_confirmation_required: bool,
    /// `SAME DISK <required token>` when required.
    pub required_same_disk_confirmation: Option<String>,
    pub warnings: Option<WindowsVolumeWarnings>,
    pub identity: Option<WindowsVolumeIdentity>,
    /// Read-only volume facts for cross-checking against `Get-Volume`.
    pub volume: Option<WindowsVolumeFacts>,
}

pub struct ValidationOutcome {
    pub report: ValidateReport,
    pub exit_code: i32,
}

impl ValidateReport {
    fn new(selector: &str) -> Self {
        Self {
            result: "refused",
            refusal: None,
            selector: selector.to_string(),
            volume_guid: None,
            required_confirmation: None,
            same_disk_confirmation_required: false,
            required_same_disk_confirmation: None,
            warnings: None,
            identity: None,
            volume: None,
        }
    }
}

fn refused(mut report: ValidateReport, error: &ExecuteError) -> ValidationOutcome {
    report.result = "refused";
    report.refusal = Some(RefusalInfo {
        variant: error.variant_name().to_string(),
        message: error.to_string(),
    });
    ValidationOutcome {
        report,
        exit_code: 3,
    }
}

fn refused_with(mut report: ValidateReport, variant: &str, message: String) -> ValidationOutcome {
    report.result = "refused";
    report.refusal = Some(RefusalInfo {
        variant: variant.to_string(),
        message,
    });
    ValidationOutcome {
        report,
        exit_code: 3,
    }
}

fn fill_inspection(report: &mut ValidateReport, inspection: WindowsVolumeInspection) {
    report.required_confirmation = Some(inspection.required_confirmation);
    report.same_disk_confirmation_required = inspection.required_same_disk_confirmation.is_some();
    report.required_same_disk_confirmation = inspection.required_same_disk_confirmation;
    report.warnings = Some(inspection.warnings);
    report.identity = Some(inspection.identity);
    report.volume = Some(inspection.facts);
}

/// Runs the real guard validation for `selector`.
///
/// * `--confirm` supplied → [`validate_windows_volume_target`] is the
///   decision: exit 0 only when the typed confirmation (and the same-disk
///   confirmation when required) passes.
/// * no `--confirm` → the read-only inspection still runs and the report is
///   `refused` with `ConfirmationMismatch` plus the required token, so the
///   UI can show what to type.
pub fn run_validation(
    backend: &dyn BlockBackend,
    selector: &str,
    confirm: Option<&str>,
    same_disk_confirm: Option<&str>,
) -> ValidationOutcome {
    let mut report = ValidateReport::new(selector);

    let volume_guid = match resolve_windows_volume_target(backend, selector) {
        Ok(guid) => guid,
        Err(error) => return refused(report, &error),
    };
    report.volume_guid = Some(volume_guid.clone());

    if let Some(confirmation_token) = confirm {
        let params = WindowsVolumeTargetParams {
            volume_guid: volume_guid.clone(),
            confirmation_token: confirmation_token.to_string(),
            same_disk_confirmation: same_disk_confirm.map(str::to_string),
        };
        match validate_windows_volume_target(backend, &params) {
            Ok(target) => {
                report.result = "ok";
                report.refusal = None;
                // Display context: the validator's pinned identity/warnings
                // are authoritative; the inspection only adds the required
                // tokens and raw facts.
                if let Ok(inspection) = inspect_windows_volume_target(backend, &volume_guid) {
                    fill_inspection(&mut report, inspection);
                }
                report.identity = target.windows_volume_identity().cloned();
                report.warnings = Some(target.windows_warnings());
                ValidationOutcome {
                    report,
                    exit_code: 0,
                }
            }
            Err(error) => {
                if let Ok(inspection) = inspect_windows_volume_target(backend, &volume_guid) {
                    fill_inspection(&mut report, inspection);
                }
                refused(report, &error)
            }
        }
    } else {
        match inspect_windows_volume_target(backend, &volume_guid) {
            Ok(inspection) => {
                let required = inspection.required_confirmation.clone();
                fill_inspection(&mut report, inspection);
                refused_with(
                    report,
                    ExecuteError::ConfirmationMismatch.variant_name(),
                    format!(
                        "No --confirm token was supplied; the required token is '{}'",
                        required
                    ),
                )
            }
            Err(error) => refused(report, &error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::mock::MockBackend;
    use crate::backend::windows_parse::{ParsedDriveLayout, ParsedPartition, PartitionStyle};
    use crate::backend::{
        BackendCapabilities, BitLockerLockState, DiskSetFact, ElevationFact, VolumeDriveType,
        VolumeFact, VolumeGuidSetFact, WindowsBootFacts,
    };

    const GUID_E: &str = r"\\?\Volume{22222222-2222-2222-2222-222222222222}\";
    const BASIC_DATA_GUID: &str = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
    const SIZE_32GB: u64 = 32_000_000_000;

    fn volume_facts(label: &str, disk: u32, part: u32, size: u64) -> WindowsVolumeFacts {
        WindowsVolumeFacts {
            volume_guid_path: GUID_E.to_string(),
            mount_points: VolumeFact::Known(vec![r"E:\".to_string()]),
            drive_letters: VolumeFact::Known(vec!['E']),
            label: VolumeFact::Known(Some(label.to_string())),
            filesystem: VolumeFact::Known(Some("NTFS".to_string())),
            total_bytes: VolumeFact::Known(size),
            free_bytes: VolumeFact::Known(size / 2),
            drive_type: VolumeFact::Known(VolumeDriveType::Removable),
            extent_count: VolumeFact::Known(1),
            disk_number: VolumeFact::Known(Some(disk)),
            partition_number: VolumeFact::Known(Some(part)),
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

    fn layout(part: u32, start: u64, len: u64) -> ParsedDriveLayout {
        ParsedDriveLayout {
            style: PartitionStyle::Gpt,
            partitions: vec![ParsedPartition {
                partition_number: part,
                starting_offset: start,
                partition_length: len,
                start_sector: start / 512,
                size_sectors: len / 512,
                partition_type_guid: Some(BASIC_DATA_GUID.to_string()),
                partition_type_mbr: None,
            }],
        }
    }

    fn backend(volume: &WindowsVolumeFacts, boot: WindowsBootFacts) -> MockBackend {
        let disk = volume
            .disk_number
            .as_known()
            .copied()
            .flatten()
            .unwrap_or(1);
        let size = volume.total_bytes.as_known().copied().unwrap_or(SIZE_32GB);
        MockBackend::new()
            .with_capabilities(BackendCapabilities::full())
            .with_windows_boot_facts(boot)
            .with_windows_volumes(vec![volume.clone()])
            .with_windows_disk_layout(disk, layout(1, 1_048_576, SIZE_32GB))
            .with_windows_device(disk, Some("usb"))
            .with_geometry(&volume.volume_guid_path, size, 512)
    }

    #[test]
    fn ok_when_the_full_validation_passes() {
        let volume = volume_facts("BACKUP", 1, 1, SIZE_32GB);
        let backend = backend(&volume, boot_facts(vec![0]));
        let outcome = run_validation(&backend, "E:", Some("E: BACKUP 32.0GB"), None);

        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.report.result, "ok");
        assert!(outcome.report.refusal.is_none());
        assert_eq!(outcome.report.volume_guid.as_deref(), Some(GUID_E));
        assert_eq!(
            outcome.report.required_confirmation.as_deref(),
            Some("E: BACKUP 32.0GB")
        );
        assert!(!outcome.report.same_disk_confirmation_required);
        let identity = outcome.report.identity.expect("identity pinned");
        assert_eq!(identity.disk_number, 1);
        assert_eq!(identity.partition_number, 1);
        assert_eq!(identity.partition_start_bytes, 1_048_576);
        assert_eq!(identity.size_bytes, SIZE_32GB);
        assert_eq!(identity.volume_guid, GUID_E);
        assert!(!identity.partition_table_fingerprint.is_empty());
        assert_eq!(
            outcome.report.warnings,
            Some(WindowsVolumeWarnings::default())
        );
        let facts = outcome.report.volume.expect("facts reported");
        assert_eq!(facts.label, VolumeFact::Known(Some("BACKUP".into())));
    }

    #[test]
    fn no_confirm_token_still_reports_the_required_token() {
        let volume = volume_facts("BACKUP", 1, 1, SIZE_32GB);
        let backend = backend(&volume, boot_facts(vec![0]));
        let outcome = run_validation(&backend, "E:", None, None);

        assert_eq!(outcome.exit_code, 3);
        assert_eq!(outcome.report.result, "refused");
        assert_eq!(
            outcome.report.required_confirmation.as_deref(),
            Some("E: BACKUP 32.0GB")
        );
        assert!(outcome.report.identity.is_some());
        let refusal = outcome.report.refusal.expect("refusal");
        assert_eq!(refusal.variant, "ConfirmationMismatch");
        assert!(refusal.message.contains("E: BACKUP 32.0GB"));
    }

    #[test]
    fn wrong_token_is_a_confirmation_refusal() {
        let volume = volume_facts("BACKUP", 1, 1, SIZE_32GB);
        let backend = backend(&volume, boot_facts(vec![0]));
        let outcome = run_validation(&backend, "E:", Some("E: WRONG 32.0GB"), None);

        assert_eq!(outcome.exit_code, 3);
        let refusal = outcome.report.refusal.expect("refusal");
        assert_eq!(refusal.variant, "ConfirmationMismatch");
        // Context is still reported for the dialog.
        assert_eq!(
            outcome.report.required_confirmation.as_deref(),
            Some("E: BACKUP 32.0GB")
        );
    }

    #[test]
    fn non_existent_letter_is_device_not_found() {
        let volume = volume_facts("BACKUP", 1, 1, SIZE_32GB);
        let backend = backend(&volume, boot_facts(vec![0]));
        let outcome = run_validation(&backend, "Z:", Some("Z: X 1.0GB"), None);

        assert_eq!(outcome.exit_code, 3);
        let refusal = outcome.report.refusal.expect("refusal");
        assert_eq!(refusal.variant, "DeviceNotFound");
        assert!(outcome.report.volume_guid.is_none());
        assert!(outcome.report.required_confirmation.is_none());
    }

    #[test]
    fn system_volume_is_protected() {
        let mut volume = volume_facts("Windows", 1, 1, SIZE_32GB);
        volume.is_system_volume = VolumeFact::Known(true);
        let backend = backend(&volume, boot_facts(vec![1]));
        let outcome = run_validation(&backend, "E:", Some("E: Windows 32.0GB"), None);

        assert_eq!(outcome.exit_code, 3);
        assert_eq!(
            outcome.report.refusal.expect("refusal").variant,
            "WindowsVolumeProtected"
        );
        assert_eq!(outcome.report.volume_guid.as_deref(), Some(GUID_E));
    }

    #[test]
    fn same_disk_volume_demands_the_extra_token_then_succeeds() {
        let volume = volume_facts("BACKUP", 1, 1, SIZE_32GB);
        let backend = backend(&volume, boot_facts(vec![1]));

        let first = run_validation(&backend, "E:", Some("E: BACKUP 32.0GB"), None);
        assert_eq!(first.exit_code, 3);
        assert_eq!(
            first.report.refusal.expect("refusal").variant,
            "WindowsVolumeSameDiskConfirmation"
        );
        assert!(first.report.same_disk_confirmation_required);
        assert_eq!(
            first.report.required_same_disk_confirmation.as_deref(),
            Some("SAME DISK E: BACKUP 32.0GB")
        );
        assert_eq!(
            first.report.warnings.map(|w| w.same_disk_as_system),
            Some(true)
        );

        let second = run_validation(
            &backend,
            "E:",
            Some("E: BACKUP 32.0GB"),
            Some("SAME DISK E: BACKUP 32.0GB"),
        );
        assert_eq!(second.exit_code, 0);
        assert_eq!(second.report.result, "ok");
        let warnings = second.report.warnings.expect("warnings");
        assert!(warnings.same_disk_as_system);
        assert!(!warnings.bitlocker_unlocked);

        // The report is a single JSON line payload for the CLI.
        let json = serde_json::to_string(&second.report).expect("serialize");
        assert!(json.contains("\"result\":\"ok\""));
        assert!(json.contains("\"same_disk_as_system\":true"));
    }
}
