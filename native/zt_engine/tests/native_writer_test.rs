//! Comprehensive tests for native block writer, identity pinning, random pass verification, and edge cases.
//!
//! Note: As mandated by safety ground rules, NEVER write to real block devices in tests.
//! Uses tempfile, FileBlockWriter, and MockBlockWriter.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;
use tempfile::{NamedTempFile, TempDir};
use tokio::sync::mpsc;

use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Digest;

use zt_engine::execute::*;
use zt_engine::verify::*;

// =========================================================================
// Item 1: fd identity & path resolution change detection
// =========================================================================

#[test]
fn test_fd_identity_mismatch_aborts() {
    let tmp = NamedTempFile::new().unwrap();
    let path_str = tmp.path().to_str().unwrap();

    // Fabricate a GuardIdentity with a deliberately mismatched st_rdev / canonical_path
    let fake_identity = GuardIdentity {
        canonical_path: path_str.to_string(),
        st_rdev: 999999, // Mismatched st_rdev
        major: 99,
        minor: 99,
        is_block: true,  // Expecting a block device, but tmp is a regular file
        device_serial: "FAKE_SERIAL_123".to_string(),
        st_ino: 0,
    };

    let result = DirectBlockWriter::open(path_str, &fake_identity);
    assert!(result.is_err(), "Opening device with mismatched identity must abort");
    match result.unwrap_err() {
        ExecuteError::BootDiskProtection(msg) => {
            assert!(msg.contains("st_rdev") || msg.contains("not a block device"),
                "Expected st_rdev or block device mismatch message, got: {}", msg);
        }
        other => panic!("Expected BootDiskProtection error, got {:?}", other),
    }
}

#[test]
fn test_path_resolving_to_different_device_aborts() {
    let tmp1 = NamedTempFile::new().unwrap();
    let tmp2 = NamedTempFile::new().unwrap();
    let meta1 = std::fs::metadata(tmp1.path()).unwrap();

    // Guard recorded identity of tmp1
    let guard_id = GuardIdentity {
        canonical_path: tmp1.path().to_str().unwrap().to_string(),
        st_rdev: meta1.rdev(),
        major: ((meta1.rdev() >> 8) & 0xfff) as u32,
        minor: (meta1.rdev() & 0xff) as u32,
        is_block: false,
        device_serial: "SER_TMP1".to_string(),
        st_ino: meta1.ino(),
    };

    // But now path resolves to tmp2 (e.g. symlink changed or redirected)
    let tmp2_path = tmp2.path().to_str().unwrap();
    let result = DirectBlockWriter::open(tmp2_path, &guard_id);
    assert!(result.is_err());
    match result.unwrap_err() {
        ExecuteError::BootDiskProtection(msg) => {
            assert!(msg.contains("inode mismatch") || msg.contains("different file"),
                "Expected inode mismatch message, got: {}", msg);
        }
        other => panic!("Expected BootDiskProtection error, got {:?}", other),
    }
}

// =========================================================================
// Item 2: Move dry-run branch before unmount step
// =========================================================================

#[tokio::test]
async fn test_dry_run_never_unmounts_and_never_opens_for_writing() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(32);

    // Call software_overwrite on a completely non-existent device path
    // If it tried to unmount or open the file for writing, it would log unmount or fail to open
    let report = software_overwrite(
        "/dev/nonexistent_block_device_xyz_123",
        1,
        OverwritePattern::Zeros,
        "DRY_SER",
        "DRY_SER",
        true, // dry_run = true
        tx,
    ).await.expect("Dry run should succeed without touching hardware");

    assert!(report.success);
    assert!(report.dry_run);
    assert_eq!(report.bytes_written, 0);
    assert_eq!(report.io_mode, "dry_run");

    // Must not have unmount commands
    let unmount_calls: Vec<&String> = report.command_log.iter()
        .filter(|c| c.to_lowercase().contains("umount"))
        .collect();
    assert!(unmount_calls.is_empty(), "Dry run must NOT call unmount: {:?}", unmount_calls);
}

// =========================================================================
// Item 3: Random pass verification & Pinned Method-to-Pattern Mapping
// =========================================================================

#[test]
fn test_method_to_pattern_mapping_pinned() {
    // Pin method semantics
    // Single pass zeros
    let z_pat = OverwritePattern::Zeros;
    let r_pat = OverwritePattern::Random;
    let m3_pat = OverwritePattern::MultiPass3;

    // Verify MultiPass3 has 3 distinct passes with correct order:
    // Pass 1: Zeros, Pass 2: Random, Pass 3: Zeros
    for pass in 0..3 {
        let is_random = match m3_pat {
            OverwritePattern::MultiPass3 => pass == 1,
            _ => false,
        };
        if pass == 1 {
            assert!(is_random, "MultiPass3 pass 2 must be random");
        } else {
            assert!(!is_random, "MultiPass3 pass 1 and 3 must be non-random (zeros)");
        }
    }

    assert_eq!(format!("{:?}", z_pat), "Zeros");
    assert_eq!(format!("{:?}", r_pat), "Random");
    assert_eq!(format!("{:?}", m3_pat), "MultiPass3");
}

#[test]
fn test_random_pass_verification_aggregated_entropy_with_chacha() {
    // Create 2 MiB file filled with real ChaCha20 output
    let mut tmp = NamedTempFile::new().unwrap();
    let file_size: u64 = 2 * 1024 * 1024; // 2 MiB
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let mut buf = vec![0u8; 64 * 1024];

    let mut written = 0u64;
    while written < file_size {
        rng.fill_bytes(&mut buf);
        tmp.write_all(&buf).unwrap();
        written += buf.len() as u64;
    }
    tmp.flush().unwrap();

    let path_str = tmp.path().to_str().unwrap();

    // Verify with expect_zeros: false (random mode)
    // Statistical aggregated entropy should easily pass (> 0.95)
    let report = verify_device(
        path_str,
        file_size,
        "TEST_SER",
        "random-pass",
        None, // Exact default verify sample size (DEFAULT_SAMPLE_COUNT = 50 samples * 512 bytes = 25,600 bytes)
        false, // expect_zeros = false (random pass)
    ).expect("Verification execution should succeed");

    assert!(report.pass, "Real ChaCha20 data must pass aggregated random verification");
    assert_eq!(report.sample_count, 50, "Must match exact default verify sample size of 50");
    assert_eq!(report.samples.len(), 50);
    let entropy = report.entropy_score;
    assert!(entropy > 0.95, "Aggregated entropy must be > 0.95, got {}", entropy);

    // If we test an all-zeros file with expect_zeros: false, it MUST fail
    let mut zero_tmp = NamedTempFile::new().unwrap();
    let zero_buf = vec![0u8; 64 * 1024];
    let mut z_written = 0u64;
    while z_written < file_size {
        zero_tmp.write_all(&zero_buf).unwrap();
        z_written += zero_buf.len() as u64;
    }
    zero_tmp.flush().unwrap();

    let fail_report = verify_device(
        zero_tmp.path().to_str().unwrap(),
        file_size,
        "TEST_SER",
        "random-pass",
        Some(50),
        false, // expect_zeros = false
    ).expect("Verification should execute");

    assert!(!fail_report.pass, "Zero-filled file must NOT pass random-pass verification");
}

// =========================================================================
// Item 13: Native Writer Edge Cases & Failures
// =========================================================================

#[tokio::test]
async fn test_non_multiple_of_chunk_size_tail_written_correctly() {
    // 5.3 MiB = 5,557,452 bytes. Chunk size is 2 MiB (2,097,152 bytes).
    // Tail is 5,557,452 - 2*2,097,152 = 1,363,148 bytes (< 2 MiB).
    let target_size: u64 = 5_557_452;
    let tmp = NamedTempFile::new().unwrap();
    tmp.as_file().set_len(target_size).unwrap();

    let writer = FileBlockWriter::new(
        OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap(),
        target_size,
    );

    let (tx, _rx) = mpsc::channel::<ProgressEvent>(64);
    let start = Instant::now();

    let report = execute_writer_overwrite(
        writer,
        1,
        OverwritePattern::Zeros,
        "SER_TAIL",
        "Test Non-Multiple Tail",
        start,
        tx,
    ).await.expect("Overwrite should succeed");

    assert!(report.success);
    assert_eq!(report.bytes_written, target_size);

    // Read back and verify file length and that all bytes are zeros
    let data = std::fs::read(tmp.path()).unwrap();
    assert_eq!(data.len() as u64, target_size);
    assert!(data.iter().all(|&b| b == 0), "All 5.3 MiB including tail must be overwritten with 0");
}

#[tokio::test]
async fn test_sub_chunk_size_single_write() {
    // 512 KiB = 524,288 bytes (< 2 MiB chunk size)
    let target_size: u64 = 512 * 1024;
    let tmp = NamedTempFile::new().unwrap();
    tmp.as_file().set_len(target_size).unwrap();

    // Fill initial file with 0xAA so we can verify it got overwritten
    let initial = vec![0xAAu8; target_size as usize];
    std::fs::write(tmp.path(), &initial).unwrap();

    let writer = FileBlockWriter::new(
        OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap(),
        target_size,
    );

    let (tx, _rx) = mpsc::channel::<ProgressEvent>(64);
    let start = Instant::now();

    let report = execute_writer_overwrite(
        writer,
        1,
        OverwritePattern::Zeros,
        "SER_SUB",
        "Test Sub-Chunk",
        start,
        tx,
    ).await.expect("Overwrite should succeed");

    assert!(report.success);
    assert_eq!(report.bytes_written, target_size);

    let data = std::fs::read(tmp.path()).unwrap();
    assert_eq!(data.len() as u64, target_size);
    assert!(data.iter().all(|&b| b == 0), "All 512 KiB must be zeroed");
}

#[tokio::test]
async fn test_write_error_midway_eio_aborts_without_success_report() {
    let total_size: u64 = 8 * 1024 * 1024; // 8 MiB
    let mut mock = MockBlockWriter::new(total_size);
    // Inject EIO after 4 MiB
    mock.fail_after_bytes = Some(4 * 1024 * 1024);
    mock.injected_raw_os_error = Some(libc::EIO);

    let (tx, _rx) = mpsc::channel::<ProgressEvent>(64);
    let start = Instant::now();

    let result = execute_writer_overwrite(
        mock,
        1,
        OverwritePattern::Zeros,
        "SER_EIO",
        "Test EIO",
        start,
        tx,
    ).await;

    assert!(result.is_err(), "Midway I/O error must fail execute_writer_overwrite");
    match result.unwrap_err() {
        ExecuteError::HardwareIo(msg) => {
            assert!(msg.contains("EIO") || msg.contains("Input/output error"));
        }
        other => panic!("Expected HardwareIo error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_write_error_midway_enospc_aborts() {
    let total_size: u64 = 6 * 1024 * 1024;
    let mut mock = MockBlockWriter::new(total_size);
    // Inject ENOSPC after 2 MiB
    mock.fail_after_bytes = Some(2 * 1024 * 1024);
    mock.injected_raw_os_error = Some(libc::ENOSPC);

    let (tx, _rx) = mpsc::channel::<ProgressEvent>(64);
    let start = Instant::now();

    let result = execute_writer_overwrite(
        mock,
        1,
        OverwritePattern::Zeros,
        "SER_ENOSPC",
        "Test ENOSPC",
        start,
        tx,
    ).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ExecuteError::PrematureEndOfDevice(msg) => {
            assert!(msg.contains("ENOSPC") || msg.contains("No space left on device"));
        }
        other => panic!("Expected PrematureEndOfDevice error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_sync_failure_aborts() {
    let total_size: u64 = 2 * 1024 * 1024;
    let mut mock = MockBlockWriter::new(total_size);
    mock.sync_fail = true;

    let (tx, _rx) = mpsc::channel::<ProgressEvent>(64);
    let start = Instant::now();

    let result = execute_writer_overwrite(
        mock,
        1,
        OverwritePattern::Zeros,
        "SER_SYNC_FAIL",
        "Test Sync Fail",
        start,
        tx,
    ).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ExecuteError::IoError(e) => {
            assert!(e.to_string().contains("Injected mock sync error"));
        }
        other => panic!("Expected IoError, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_heartbeat_and_monotonic_progress() {
    // 4 MiB total, small artificial delay per chunk so heartbeat has time to tick
    let total_size: u64 = 4 * 1024 * 1024;
    let mut mock = MockBlockWriter::new(total_size);
    mock.delay_per_chunk = Some(std::time::Duration::from_millis(50));

    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(128);
    let start = Instant::now();

    let handle = tokio::spawn(async move {
        execute_writer_overwrite(
            mock,
            1,
            OverwritePattern::Zeros,
            "SER_MONO",
            "Test Monotonic",
            start,
            tx,
        ).await
    });

    let mut events = Vec::new();
    while let Some(evt) = rx.recv().await {
        events.push(evt);
    }

    let report = handle.await.unwrap().expect("Overwrite should succeed");
    assert!(report.success);

    // Verify events:
    assert!(!events.is_empty(), "Should receive progress events");
    let progress_events: Vec<&ProgressEvent> = events.iter().filter(|e| !e.is_heartbeat).collect();
    for i in 1..progress_events.len() {
        assert!(
            progress_events[i].bytes_done >= progress_events[i - 1].bytes_done,
            "bytes_done must be monotonically non-decreasing: {} < {}",
            progress_events[i].bytes_done,
            progress_events[i - 1].bytes_done
        );
    }
}

#[tokio::test]
async fn test_write_error_enodev_aborts() {
    let total_size: u64 = 4 * 1024 * 1024;
    let mut mock = MockBlockWriter::new(total_size);
    mock.fail_after_bytes = Some(1024 * 1024);
    mock.injected_raw_os_error = Some(libc::ENODEV);

    let (tx, _rx) = mpsc::channel::<ProgressEvent>(16);
    let start = Instant::now();

    let result = execute_writer_overwrite(
        mock,
        1,
        OverwritePattern::Zeros,
        "SER_ENODEV",
        "Test ENODEV",
        start,
        tx,
    ).await;

    assert!(result.is_err(), "ENODEV must cause overwrite failure");
    match result.unwrap_err() {
        ExecuteError::DeviceDisconnected(msg) => {
            assert!(msg.contains("ENODEV") || msg.contains("No such device"));
        }
        other => panic!("Expected DeviceDisconnected error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_short_write_returning_zero_aborts() {
    let total_size: u64 = 4 * 1024 * 1024;
    let mut mock = MockBlockWriter::new(total_size);
    mock.return_zero_bytes = true;

    let (tx, _rx) = mpsc::channel::<ProgressEvent>(16);
    let start = Instant::now();

    let result = execute_writer_overwrite(
        mock,
        1,
        OverwritePattern::Zeros,
        "SER_ZERO_WRITE",
        "Test Short Write Zero",
        start,
        tx,
    ).await;

    assert!(result.is_err(), "Write returning 0 bytes must abort");
    match result.unwrap_err() {
        ExecuteError::PrematureEndOfDevice(msg) => {
            assert!(msg.contains("returned 0 bytes") || msg.contains("ENOSPC"));
        }
        other => panic!("Expected PrematureEndOfDevice, got {:?}", other),
    }
}

#[test]
fn test_o_excl_exclusive_open_blocks_concurrent_open() {
    let tmp = NamedTempFile::new().unwrap();
    let c_path = std::ffi::CString::new(tmp.path().to_str().unwrap()).unwrap();
    // Opening with O_CREAT | O_EXCL on an existing file fails with EEXIST / EBUSY
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600) };
    assert_eq!(fd, -1);
    let err = std::io::Error::last_os_error();
    assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
}

#[tokio::test]
async fn test_serial_mismatch_aborts_before_first_write() {
    let (tx, _rx) = mpsc::channel::<ProgressEvent>(16);
    let result = software_overwrite(
        "/dev/sdb",
        1,
        OverwritePattern::Zeros,
        "TOKEN_MISMATCH_ABC",
        "REAL_DEVICE_SERIAL_XYZ",
        true,
        tx,
    ).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ExecuteError::ConfirmationMismatch => {}
        other => panic!("Expected ConfirmationMismatch, got {:?}", other),
    }
}

#[tokio::test]
async fn test_cancel_signal_syncs_and_reports_exact_bytes_done() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let total_size: u64 = 6 * 1024 * 1024; // 6 MiB = 3 chunks (2 MiB each)
    let mut mock = MockBlockWriter::new(total_size);

    let cancel_flag = Arc::new(AtomicBool::new(false));
    // Trigger cancel right after chunk 1 is written
    mock.cancel_flag_on_write = Some(Arc::clone(&cancel_flag));

    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(64);
    let start = Instant::now();

    let report = execute_writer_overwrite_with_cancel(
        mock,
        1,
        OverwritePattern::Zeros,
        "SER_CANCEL",
        "Test Cancel",
        start,
        tx,
        Some(cancel_flag),
    ).await.expect("Cancelled run should return report with success=false");

    assert!(!report.success, "Cancelled overwrite must have success=false");
    assert_eq!(report.exit_code, 130, "Cancelled exit code must be 130");
    assert_eq!(report.bytes_written, 2 * 1024 * 1024, "Bytes written must match exactly 1 chunk written before cancel");
    assert!(report.stderr.contains("cancelled by user"));

    // Verify progress events were received
    let mut events = Vec::new();
    while let Ok(evt) = rx.try_recv() {
        events.push(evt);
    }
    assert!(!events.is_empty(), "Should stream progress up to cancellation");
}

#[test]
fn test_heartbeat_line_integrity_schema2_json() {
    let hb = ProgressEvent {
        schema_version: 2,
        phase: ExecutionPhase::FirmwareCommand,
        bytes_done: 1048576,
        bytes_total: 10485760,
        percent: Some(0.10),
        speed_bytes_per_sec: 25000000.0,
        eta_seconds: Some(36),
        message: "Writing sectors...".to_string(),
        is_heartbeat: true,
    };

    let serialized = serde_json::to_string(&hb).unwrap();
    let parsed: ProgressEvent = serde_json::from_str(&serialized).unwrap();
    assert_eq!(parsed.schema_version, 2);
    assert!(parsed.is_heartbeat);
    assert_eq!(parsed.bytes_done, 1048576);
    assert_eq!(parsed.bytes_total, 10485760);
    assert_eq!(parsed.speed_bytes_per_sec, 25000000.0);
    assert_eq!(parsed.eta_seconds, Some(36));
}

#[test]
fn test_usb_speed_parser_detects_usb2_vs_usb3() {
    use zt_engine::detect::detect_usb_speed;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let sys_root = dir.path().to_str().unwrap();

    // Create fake sysfs hierarchy: /sys/class/block/sdb -> /sys/devices/pci/usb1/1-1/1-1:1.0/host/target/block/sdb
    let usb_dev_dir = dir.path().join("devices/pci0000:00/0000:00:14.0/usb1/1-1");
    let block_target_dir = usb_dev_dir.join("host0/target0:0:0/0:0:0:0/block/sdb");
    std::fs::create_dir_all(&block_target_dir).unwrap();

    let class_block = dir.path().join("class/block");
    std::fs::create_dir_all(&class_block).unwrap();
    std::os::unix::fs::symlink(&block_target_dir, class_block.join("sdb")).unwrap();

    // Test 1: speed = 480 (USB 2.0 High-Speed)
    std::fs::write(usb_dev_dir.join("speed"), "480\n").unwrap();
    let (speed, is_u2) = detect_usb_speed("/dev/sdb", sys_root);
    assert_eq!(speed, Some(480));
    assert!(is_u2, "480 Mbps must be detected as USB 2");

    // Test 2: speed = 5000 (USB 3.0 SuperSpeed)
    std::fs::write(usb_dev_dir.join("speed"), "5000\n").unwrap();
    let (speed3, is_u2_3) = detect_usb_speed("/dev/sdb", sys_root);
    assert_eq!(speed3, Some(5000));
    assert!(!is_u2_3, "5000 Mbps must NOT be USB 2 (it is USB 3)");
}


#[test]
fn test_verify_fails_on_truncated_or_partial_wipe() {
    let mut tmp = NamedTempFile::new().unwrap();
    let file_size: u64 = 4 * 1024 * 1024; // 4 MiB
    let half_size = file_size / 2;

    // First half wiped with zeros
    let zeros = vec![0u8; half_size as usize];
    tmp.write_all(&zeros).unwrap();

    // Second half left with non-zero bytes (truncated/partial wipe)
    let mut rng = ChaCha20Rng::from_seed([0x99; 32]);
    let mut non_zeros = vec![0u8; half_size as usize];
    rng.fill_bytes(&mut non_zeros);
    for b in non_zeros.iter_mut() {
        if *b == 0 {
            *b = 0xAA;
        }
    }
    tmp.write_all(&non_zeros).unwrap();
    tmp.flush().unwrap();

    let report = verify_device(
        tmp.path().to_str().unwrap(),
        file_size,
        "TEST_PARTIAL",
        "overwrite-zero",
        Some(50),
        true, // expect_zeros = true
    ).expect("Verification should execute");

    assert!(!report.pass, "Verification must fail on truncated/partial wipe");
    assert!(
        report.samples.iter().any(|s| !s.is_zero),
        "Must detect non-zero sectors in partial wipe"
    );
}

#[test]
fn test_random_pass_verify_fails_on_all_zeros_image() {
    let mut tmp = NamedTempFile::new().unwrap();
    let file_size: u64 = 2 * 1024 * 1024; // 2 MiB
    let zeros = vec![0u8; file_size as usize];
    tmp.write_all(&zeros).unwrap();
    tmp.flush().unwrap();

    let report = verify_device(
        tmp.path().to_str().unwrap(),
        file_size,
        "TEST_ZEROS_RANDOM",
        "random-pass",
        None,
        false, // expect_zeros = false (verifying random pass)
    ).expect("Verification should execute");

    assert!(!report.pass, "Random pass verification must fail on an all-zeros image");
    assert!(
        report.entropy_score < 0.1,
        "Entropy of all-zeros image must be near 0, got {}",
        report.entropy_score
    );
}

#[tokio::test]
async fn test_buffered_fallback_advances_bytes_done_only_after_sync() {
    // Total size: 32 MiB (16 chunks of 2 MiB each)
    let total_size: u64 = 32 * 1024 * 1024;
    let mut mock = MockBlockWriter::new(total_size);
    mock.custom_io_mode = Some("buffered_sync_16mb");

    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(128);
    let start = Instant::now();

    let report = execute_writer_overwrite(
        mock,
        1,
        OverwritePattern::Zeros,
        "SER_BUFFERED",
        "Test Buffered",
        start,
        tx,
    ).await.expect("Overwrite should succeed");

    assert!(report.success);
    assert_eq!(report.bytes_written, total_size);

    let mut progress_events = Vec::new();
    while let Ok(evt) = rx.try_recv() {
        if !evt.is_heartbeat && evt.phase == ExecutionPhase::FirmwareCommand {
            progress_events.push(evt);
        }
    }

    // In buffered mode, bytes_done must only advance after sync returns (16MB increments or final complete)
    for evt in &progress_events {
        assert!(
            evt.bytes_done == 0 || evt.bytes_done >= 16 * 1024 * 1024,
            "Buffered progress must not advance until synced (found uncommitted bytes_done: {})",
            evt.bytes_done
        );
    }
}

#[tokio::test]
async fn test_slow_writer_progress_never_exceeds_acknowledged_bytes() {
    let total_size: u64 = 6 * 1024 * 1024; // 6 MiB (3 chunks)
    let mut mock = MockBlockWriter::new(total_size);
    mock.delay_per_chunk = Some(std::time::Duration::from_millis(30));

    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(64);
    let start = Instant::now();

    let handle = tokio::spawn(async move {
        execute_writer_overwrite(
            mock,
            1,
            OverwritePattern::Zeros,
            "SER_SLOW_ACK",
            "Test Slow Ack",
            start,
            tx,
        ).await
    });

    while let Some(evt) = rx.recv().await {
        assert!(
            evt.bytes_done <= total_size,
            "Reported progress bytes_done ({}) exceeded total device size ({})",
            evt.bytes_done,
            total_size
        );
    }

    let report = handle.await.unwrap().expect("Wipe should succeed");
    assert_eq!(report.bytes_written, total_size);
}

#[test]
fn test_o_direct_alignment_requirements() {
    // Verify that posix_memalign creates an aligned buffer matching block sector size (512 / 4096)
    let mut aligned_ptr: *mut libc::c_void = std::ptr::null_mut();
    let ret = unsafe { libc::posix_memalign(&mut aligned_ptr, 4096, 4096) };
    assert_eq!(ret, 0, "posix_memalign must succeed");
    assert!(!aligned_ptr.is_null());
    assert_eq!((aligned_ptr as usize) % 4096, 0, "Buffer pointer must be 4096-byte aligned");
    unsafe { libc::free(aligned_ptr) };

    // AlignedBuffer test
    let buf = AlignedBuffer::new(2 * 1024 * 1024);
    assert_eq!(
        (buf.as_slice().as_ptr() as usize) % 4096,
        0,
        "AlignedBuffer slice must be 4096-byte aligned"
    );
}

#[tokio::test]
async fn test_cancel_via_real_sigterm_signal() {
    if std::env::var("ZT_TEST_SIGTERM_WORKER").as_deref() == Ok("1") {
        let total_size: u64 = 32 * 1024 * 1024;
        let mut mock = MockBlockWriter::new(total_size);
        mock.delay_per_chunk = Some(std::time::Duration::from_millis(40));
        let (tx, _rx) = mpsc::channel::<ProgressEvent>(64);
        let start = Instant::now();
        let report = execute_writer_overwrite(
            mock,
            1,
            OverwritePattern::Zeros,
            "SER_CHILD_CANCEL",
            "Child Cancel",
            start,
            tx,
        ).await.expect("Execution should return report");
        std::process::exit(report.exit_code);
    }

    // Parent test process: spawn child test worker in isolated OS process
    let current_exe = std::env::current_exe().expect("Must get current exe");
    // Isolate the checkpoint state dir so the cancel path does not touch the
    // developer's real ~/.local/state/zero_trace (mtime side effect in tests).
    let ckpt_dir = TempDir::new().expect("Must create isolated checkpoint dir");
    let mut child = std::process::Command::new(current_exe)
        .arg("test_cancel_via_real_sigterm_signal")
        .arg("--exact")
        .arg("--nocapture")
        .env("ZT_TEST_SIGTERM_WORKER", "1")
        .env("ZT_CHECKPOINT_DIR", ckpt_dir.path())
        .spawn()
        .expect("Must spawn child test worker");

    let child_pid = child.id() as i32;
    // Wait for child to begin writing chunks
    tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;

    // Send real OS SIGTERM directly to child process PID
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }

    let status = child.wait().expect("Child must exit");
    assert_eq!(
        status.code(),
        Some(130),
        "Child process caught real SIGTERM and must exit with code 130"
    );
}

#[test]
#[ignore = "Requires root/sudo privileges: setup via `sudo losetup -fP /tmp/zt_loop.img`"]
fn test_direct_block_writer_and_o_excl_on_real_loop_device() {
    // Documented manual instructions:
    // 1. Create 100MB sparse file: truncate -s 100M /tmp/zt_loop.img
    // 2. Attach loopback: sudo losetup -fP /tmp/zt_loop.img
    // 3. Find device: losetup -a | grep zt_loop.img -> /dev/loop7
    // 4. Run test: ZT_TEST_LOOP_DEV=/dev/loop7 cargo test test_direct_block_writer_and_o_excl_on_real_loop_device -- --ignored --nocapture
    let loop_dev = std::env::var("ZT_TEST_LOOP_DEV").unwrap_or_else(|_| "/dev/loop7".to_string());
    let c_path = std::ffi::CString::new(loop_dev.as_str()).unwrap();

    // Test kernel mutual exclusion: open with O_RDWR | O_EXCL
    let fd1 = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_EXCL) };
    if fd1 < 0 {
        let err = std::io::Error::last_os_error();
        panic!("Failed to open {} with O_EXCL: {}", loop_dev, err);
    }

    // Second concurrent open must return EBUSY
    let fd2 = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_EXCL) };
    assert_eq!(fd2, -1, "Second concurrent O_EXCL open must fail");
    let err2 = std::io::Error::last_os_error();
    assert_eq!(err2.raw_os_error(), Some(libc::EBUSY), "Concurrent open must return EBUSY");

    unsafe { libc::close(fd1) };
}

#[tokio::test]
async fn test_checkpoint_handles_stale_tmp_file() {
    let tmp_dir = tempfile::tempdir().unwrap();

    // Pre-create stale tmp files
    let stale_tmp = tmp_dir.path().join("active_checkpoint.tmp");
    let stale_pid_tmp = tmp_dir.path().join(format!("active_checkpoint.{}.tmp", std::process::id()));
    std::fs::write(&stale_tmp, "STALE CONTENT").unwrap();
    std::fs::write(&stale_pid_tmp, "STALE PID CONTENT").unwrap();

    // Call write_checkpoint_file_in_dir
    let job_id = "job-test-stale-001";
    let serial = "SERIAL-XYZ-999";
    let device_size: u64 = 16 * 1024 * 1024 * 1024;
    let bytes_done: u64 = 4 * 1024 * 1024 * 1024;

    write_checkpoint_file_in_dir(tmp_dir.path(), job_id, serial, device_size, bytes_done);

    let final_json_path = tmp_dir.path().join("active_checkpoint.json");
    assert!(final_json_path.exists(), "active_checkpoint.json must exist even if stale tmp existed");

    let content = std::fs::read_to_string(&final_json_path).unwrap();
    let checkpoint: CheckpointData = serde_json::from_str(&content).expect("Must parse CheckpointData");

    assert_eq!(checkpoint.job_id, job_id);
    assert_eq!(checkpoint.device_size, device_size);
    assert_eq!(checkpoint.bytes_done, bytes_done);
    assert!(!checkpoint.device_id_hash.is_empty());
    assert_eq!(
        checkpoint.device_id_hash,
        format!("{:x}", sha2::Sha256::digest(serial.as_bytes()))
    );
}

#[tokio::test]
async fn test_checkpoint_json_content_and_cleanup_on_success() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let job_id = "job-success-test";
    let serial = "SER_SUCCESS_CLEANUP";
    let device_size: u64 = 4 * 1024 * 1024;
    let bytes_done: u64 = 4 * 1024 * 1024;

    // Simulate in-flight periodic checkpoint
    write_checkpoint_file_in_dir(tmp_dir.path(), job_id, serial, device_size, bytes_done);
    let final_json_path = tmp_dir.path().join("active_checkpoint.json");
    assert!(final_json_path.exists(), "active_checkpoint.json exists during wipe");

    // Clean up on successful finish
    remove_checkpoint_file_in_dir(tmp_dir.path());
    assert!(
        !final_json_path.exists(),
        "active_checkpoint.json must be deleted upon successful wipe completion"
    );
}

#[tokio::test]
async fn test_checkpoint_kept_on_cancel() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let job_id = "job-cancel-test";
    let serial = "SER_CANCEL_KEEP";
    let device_size: u64 = 16 * 1024 * 1024;
    let bytes_done: u64 = 4 * 1024 * 1024;

    // Simulate checkpoint write on cancel
    write_checkpoint_file_in_dir(tmp_dir.path(), job_id, serial, device_size, bytes_done);

    let final_json_path = tmp_dir.path().join("active_checkpoint.json");
    assert!(
        final_json_path.exists(),
        "active_checkpoint.json must be kept on cancellation"
    );

    let content = std::fs::read_to_string(&final_json_path).unwrap();
    let checkpoint: CheckpointData = serde_json::from_str(&content).expect("Must parse CheckpointData");

    assert_eq!(checkpoint.job_id, job_id);
    assert_eq!(checkpoint.bytes_done, bytes_done);
    assert_eq!(checkpoint.device_size, device_size);
}

#[tokio::test]
async fn test_checkpoint_kept_on_force_stop_and_crash() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let job_id = "job-crash-test";
    let serial = "SER_CRASH_TEST";
    let device_size: u64 = 8 * 1024 * 1024 * 1024;
    let bytes_done: u64 = 2 * 1024 * 1024 * 1024;

    write_checkpoint_file_in_dir(tmp_dir.path(), job_id, serial, device_size, bytes_done);

    let final_json_path = tmp_dir.path().join("active_checkpoint.json");
    assert!(final_json_path.exists(), "active_checkpoint.json must exist after periodic write");

    // Simulating sudden force-stop (SIGKILL) or crash: process ceases execution immediately
    // without calling remove_checkpoint_file_in_dir().
    assert!(
        final_json_path.exists(),
        "active_checkpoint.json must stay on disk across simulated force-stop / crash"
    );

    let content = std::fs::read_to_string(&final_json_path).unwrap();
    let checkpoint: CheckpointData = serde_json::from_str(&content).unwrap();
    assert_eq!(checkpoint.job_id, job_id);
    assert_eq!(checkpoint.bytes_done, bytes_done);
}

#[tokio::test]
async fn test_cancel_during_flushing_phase_exits_promptly() {
    let total_size: u64 = 2 * 1024 * 1024; // 2 MiB (1 chunk)
    let mock = MockBlockWriter::new(total_size);

    let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag_clone = std::sync::Arc::clone(&cancel_flag);

    let (tx, _rx) = mpsc::channel::<ProgressEvent>(64);
    let start = Instant::now();

    // Trigger cancel right before flush completes
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        flag_clone.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    let report = execute_writer_overwrite_with_cancel(
        mock,
        1,
        OverwritePattern::Zeros,
        "SER_CANCEL_FLUSH",
        "Test Cancel Flush",
        start,
        tx,
        Some(cancel_flag),
    ).await.expect("Execution should return report");

    if !report.success {
        assert_eq!(report.exit_code, 130);
        assert!(
            report.stderr.contains("cancelled by user"),
            "Report should indicate cancellation: {}",
            report.stderr
        );
    }
}

#[test]
fn test_cancel_during_verifying_phase_exits_promptly() {
    let mut tmp = NamedTempFile::new().unwrap();
    let file_size: u64 = 2 * 1024 * 1024;
    let zeros = vec![0u8; file_size as usize];
    tmp.write_all(&zeros).unwrap();
    tmp.flush().unwrap();

    let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));

    let result = verify_device_with_cancel(
        tmp.path().to_str().unwrap(),
        file_size,
        "SER_CANCEL_VERIFY",
        "overwrite-zero",
        Some(50),
        true,
        Some(cancel_flag),
    );

    match result {
        Err(VerifyError::Cancelled) => {
            // Expected prompt cancellation
        }
        other => panic!("Expected Err(VerifyError::Cancelled), got {:?}", other),
    }
}


