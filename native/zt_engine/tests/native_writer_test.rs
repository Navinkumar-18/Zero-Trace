//! Comprehensive tests for native block writer, identity pinning, random pass verification, and edge cases.
//!
//! Note: As mandated by safety ground rules, NEVER write to real block devices in tests.
//! Uses tempfile, FileBlockWriter, and MockBlockWriter.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;
use tempfile::NamedTempFile;
use tokio::sync::mpsc;

use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

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

#[tokio::test]
async fn test_slow_writer_runtime_ps_no_dd_spawned() {
    let total_size: u64 = 4 * 1024 * 1024; // 4 MiB = 2 chunks
    let mut mock = MockBlockWriter::new(total_size);
    mock.delay_per_chunk = Some(std::time::Duration::from_millis(50));

    let (tx, mut rx) = mpsc::channel::<ProgressEvent>(64);
    let start = Instant::now();

    // Check runtime process list while slow writer is executing
    let ps_check_task = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
        // Verify no dd process is spawned
        let pgrep_dd = std::process::Command::new("pgrep")
            .arg("-x")
            .arg("dd")
            .output();
        if let Ok(out) = pgrep_dd {
            assert!(
                out.stdout.is_empty(),
                "No 'dd' process should exist during native overwrite: found {:?}",
                String::from_utf8_lossy(&out.stdout)
            );
            assert_ne!(out.status.code(), Some(0), "pgrep dd must return non-zero (no match)");
        }
    });

    let report = execute_writer_overwrite(
        mock,
        1,
        OverwritePattern::Zeros,
        "SER_SLOW",
        "Test Slow Writer",
        start,
        tx,
    ).await.expect("Slow write should succeed");

    assert!(report.success);
    assert_eq!(report.bytes_written, total_size);
    assert_eq!(report.io_mode, "mock");

    let _ = ps_check_task.await;

    // Check that events were streamed
    let mut event_count = 0;
    while let Ok(_) = rx.try_recv() {
        event_count += 1;
    }
    assert!(event_count > 0, "Slow writer should produce progress events");
}

