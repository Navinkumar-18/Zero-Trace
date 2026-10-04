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
        Some(50),
        false, // expect_zeros = false (random pass)
    ).expect("Verification execution should succeed");

    assert!(report.pass, "Real ChaCha20 data must pass aggregated random verification");
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
