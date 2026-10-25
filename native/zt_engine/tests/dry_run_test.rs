//! Dry-run smoke tests for execute.rs.
//!
//! These tests verify that:
//! 1. No destructive syscalls fire when dry_run = true
//! 2. command_log contains the expected command strings
//! 3. Boot-disk protection rejects the OS root device
//! 4. Confirmation token mismatch is rejected
//! 5. ProgressEvents are streamed correctly

use tokio::sync::mpsc;
use zt_engine::execute::*;

#[tokio::test]
async fn test_nvme_sanitize_dry_run_logs_commands() {
    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(32);

    let result = nvme_sanitize(
        "/dev/nvme99n1", // non-existent device
        SanitizeAction::BlockErase,
        "TEST_SERIAL", // confirmation token
        "TEST_SERIAL", // device serial (matches)
        true,          // dry_run
        tx,
    )
    .await;

    let report = result.expect("Dry run should not fail");
    assert!(report.success);
    assert!(report.dry_run);
    assert!(!report.command_log.is_empty());
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("nvme sanitize")));
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("start-block-erase")));

    // Verify progress events were sent
    let mut events = Vec::new();
    while let Ok(evt) = rx.try_recv() {
        events.push(evt);
    }
    assert!(!events.is_empty(), "Should have received progress events");
    assert!(events
        .iter()
        .any(|e| e.phase == ExecutionPhase::FirmwareCommand));
    assert!(events
        .iter()
        .any(|e| e.phase == ExecutionPhase::Verification));
}

#[tokio::test]
async fn test_nvme_sanitize_crypto_erase_dry_run() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(32);

    let result = nvme_sanitize(
        "/dev/nvme99n1",
        SanitizeAction::CryptoErase,
        "SERIAL_ABC",
        "SERIAL_ABC",
        true,
        tx,
    )
    .await;

    let report = result.unwrap();
    assert!(report.success);
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("start-crypto-erase")));
}

#[tokio::test]
async fn test_ata_secure_erase_dry_run_logs_hdparm_commands() {
    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(32);

    let result = ata_secure_erase(
        "/dev/sdb", false, // not enhanced
        "SER123", "SER123", true, tx,
    )
    .await;

    let report = result.unwrap();
    assert!(report.success);
    assert!(report.dry_run);
    // Should log hdparm -I, --security-set-pass, --security-erase
    assert!(report.command_log.iter().any(|c| c.contains("hdparm -I")));
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("--security-set-pass")));
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("--security-erase")));
    // Should NOT contain --security-erase-enhanced
    assert!(!report
        .command_log
        .iter()
        .any(|c| c.contains("--security-erase-enhanced")));

    let mut events = Vec::new();
    while let Ok(evt) = rx.try_recv() {
        events.push(evt);
    }
    assert!(events
        .iter()
        .any(|e| e.phase == ExecutionPhase::SecurityUnlock));
}

#[tokio::test]
async fn test_ata_secure_erase_enhanced_dry_run() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(32);

    let result = ata_secure_erase(
        "/dev/sdb", true, // enhanced
        "SER456", "SER456", true, tx,
    )
    .await;

    let report = result.unwrap();
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("--security-erase-enhanced")));
}

#[tokio::test]
async fn test_ata_sanitize_block_erase_dry_run() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(32);

    let result = ata_sanitize(
        "/dev/sdb",
        AtaSanitizeAction::BlockErase,
        "SER789",
        "SER789",
        true,
        tx,
    )
    .await;

    let report = result.unwrap();
    assert!(report.success);
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("--sanitize-block-erase")));
}

#[tokio::test]
async fn test_ata_sanitize_crypto_scramble_dry_run() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(32);

    let result = ata_sanitize(
        "/dev/sdb",
        AtaSanitizeAction::CryptoScramble,
        "SER789",
        "SER789",
        true,
        tx,
    )
    .await;

    let report = result.unwrap();
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("--sanitize-crypto-scramble")));
}

#[tokio::test]
async fn test_opal_revert_dry_run() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(32);

    let result = opal_revert(
        "/dev/sdb", None, // no PSID
        "SER_OPAL", "SER_OPAL", true, tx,
    )
    .await;

    let report = result.unwrap();
    assert!(report.success);
    assert!(report.command_log.iter().any(|c| c.contains("sedutil-cli")));
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("--revertTPer")));
}

#[tokio::test]
async fn test_opal_revert_with_psid_dry_run() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(32);

    let result = opal_revert(
        "/dev/sdb",
        Some("MYPSID123456789012345678901234"),
        "SER_OPAL2",
        "SER_OPAL2",
        true,
        tx,
    )
    .await;

    let report = result.unwrap();
    assert!(report.command_log.iter().any(|c| c.contains("PSID")));
}

#[tokio::test]
async fn test_emmc_sanitize_dry_run() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(32);

    let result = emmc_sanitize("/dev/mmcblk99", "EMMC_SER", "EMMC_SER", true, tx).await;

    let report = result.unwrap();
    assert!(report.success);
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("mmc sanitize")));
}

#[tokio::test]
async fn test_software_overwrite_zeros_dry_run() {
    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(64);

    let result = software_overwrite(
        "/dev/sdb",
        1,
        OverwritePattern::Zeros,
        "OVER_SER",
        "OVER_SER",
        true,
        tx,
    )
    .await;

    let report = result.unwrap();
    assert!(report.success);
    assert!(report.dry_run);
    assert!(report
        .command_log
        .iter()
        .any(|c| c.contains("Native block overwrite")));
    // Item 2 test: Prove dry run performs no unmount and never opens the target for writing
    assert!(!report
        .command_log
        .iter()
        .any(|c| c.to_lowercase().contains("umount")));
    assert_eq!(report.bytes_written, 0);
    assert_eq!(report.io_mode, "dry_run");

    let mut events = Vec::new();
    while let Ok(evt) = rx.try_recv() {
        events.push(evt);
    }
    assert!(events.len() > 3, "Should have multiple progress events");
}

#[tokio::test]
async fn test_software_overwrite_multi_pass_3_dry_run() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(64);

    let result = software_overwrite(
        "/dev/sdb",
        1, // ignored for MultiPass3
        OverwritePattern::MultiPass3,
        "NIST_SER",
        "NIST_SER",
        true,
        tx,
    )
    .await;

    let report = result.unwrap();
    assert!(report.success);
    assert!(report.dry_run);
    assert!(report.command_log.iter().any(|c| c.contains("3 passes")));
    assert!(!report
        .command_log
        .iter()
        .any(|c| c.to_lowercase().contains("umount")));
    assert_eq!(report.bytes_written, 0);
}

// =========================================================================
// Safety: Boot-disk protection tests
// =========================================================================

#[tokio::test]
async fn test_boot_disk_protection_blocks_root_device() {
    // Read /proc/mounts to find the actual root device
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let root_device = mounts
        .lines()
        .find(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.len() >= 2 && parts[1] == "/"
        })
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or("/dev/sda1");

    // Extract base device (e.g., /dev/sda from /dev/sda1, /dev/nvme0n1 from /dev/nvme0n1p6)
    let base = if (root_device.starts_with("/dev/nvme") || root_device.starts_with("/dev/mmcblk"))
        && root_device.contains('p')
    {
        let idx = root_device.rfind('p').unwrap();
        &root_device[..idx]
    } else {
        root_device.trim_end_matches(|c: char| c.is_ascii_digit())
    };

    let (tx, _rx) = mpsc::channel::<ProgressEvent>(16);

    // Test whole disk
    let result = nvme_sanitize(
        base,
        SanitizeAction::BlockErase,
        "any_token",
        "any_token",
        true, // even in dry-run, boot protection should fire
        tx.clone(),
    )
    .await;

    assert!(
        result.is_err(),
        "Boot disk protection should block root base disk: {}",
        base
    );

    // Also test root partition itself
    let part_result = nvme_sanitize(
        root_device,
        SanitizeAction::BlockErase,
        "any_token",
        "any_token",
        true,
        tx,
    )
    .await;

    assert!(
        part_result.is_err(),
        "Boot disk protection should block root partition: {}",
        root_device
    );
}

// =========================================================================
// Safety: Confirmation token mismatch tests
// =========================================================================

#[tokio::test]
async fn test_confirmation_mismatch_blocks_execution() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(16);

    let result = nvme_sanitize(
        "/dev/nvme99n1",
        SanitizeAction::BlockErase,
        "WRONG_TOKEN",
        "CORRECT_SERIAL",
        true,
        tx,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_confirmation_mismatch_on_ata_erase() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(16);

    let result = ata_secure_erase("/dev/sdb", false, "MISMATCH", "REAL_SERIAL", true, tx).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_confirmation_mismatch_on_software_overwrite() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(16);

    let result = software_overwrite(
        "/dev/sdb",
        1,
        OverwritePattern::Zeros,
        "WRONG",
        "RIGHT",
        true,
        tx,
    )
    .await;

    assert!(result.is_err());
}

// =========================================================================
// Progress event stream tests
// =========================================================================

#[tokio::test]
async fn test_progress_events_cover_all_phases() {
    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(64);

    let _ = ata_secure_erase("/dev/sdb", false, "PHASE_SER", "PHASE_SER", true, tx).await;

    let mut events = Vec::new();
    while let Ok(evt) = rx.try_recv() {
        events.push(evt);
    }

    let phases: Vec<&ExecutionPhase> = events.iter().map(|e| &e.phase).collect();
    assert!(
        phases.contains(&&ExecutionPhase::SecurityUnlock),
        "Missing SecurityUnlock phase"
    );
    assert!(
        phases.contains(&&ExecutionPhase::FirmwareCommand),
        "Missing FirmwareCommand phase"
    );
    assert!(
        phases.contains(&&ExecutionPhase::KeyDestruction),
        "Missing KeyDestruction phase"
    );
    assert!(
        phases.contains(&&ExecutionPhase::CacheFlush),
        "Missing CacheFlush phase"
    );
    assert!(
        phases.contains(&&ExecutionPhase::Verification),
        "Missing Verification phase"
    );
}

#[tokio::test]
async fn test_progress_percentages_are_monotonically_increasing() {
    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(64);

    let _ = nvme_sanitize(
        "/dev/nvme99n1",
        SanitizeAction::BlockErase,
        "MONO_SER",
        "MONO_SER",
        true,
        tx,
    )
    .await;

    let mut events = Vec::new();
    while let Ok(evt) = rx.try_recv() {
        events.push(evt);
    }

    for i in 1..events.len() {
        assert!(
            events[i].percent >= events[i - 1].percent,
            "Progress should be monotonically increasing: {:?} < {:?} at event {}",
            events[i].percent,
            events[i - 1].percent,
            i
        );
    }
}
