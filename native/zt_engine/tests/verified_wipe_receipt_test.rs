//! Phase F: the one-shot verified-wipe receipt that authorizes the separate
//! `format` process — write → read → adopt → consume, exact target binding,
//! expiry and failure hygiene.
//!
//! Every test uses [`MockBackend`] — no real devices, no root, no loop
//! devices. The one exception is noted inline: temp *regular files* on the
//! host filesystem are used to observe receipt-file semantics (0600,
//! atomic cleanup), which never touch a block device.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::tempdir;
use zt_engine::backend::conformance::{mock_fixture, partition_params};
use zt_engine::backend::mock::MockBackend;
use zt_engine::execute::{
    adopt_verified_wipe_receipt, read_verified_wipe_receipt, recreate_filesystem_with,
    verified_wipe_stamp_for_path, write_verified_wipe_receipt,
};
use zt_engine::guard::{self, ValidatedTarget};
use zt_engine::types::ExecuteError;

const SERIAL: &str = "CONFORMANCE-SERIAL";

fn partition_target(backend: &MockBackend) -> ValidatedTarget {
    let params = partition_params(backend, "/dev/sdb1", 1, 2048, 4096).unwrap();
    guard::validate_partition_target(backend, "/dev/sdb1", &params, false, SERIAL).unwrap()
}

fn whole_target(backend: &MockBackend) -> ValidatedTarget {
    guard::validate_whole_disk_target(backend, "/dev/sdb", SERIAL, SERIAL, false).unwrap()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sorted_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn receipt_lifecycle_write_read_roundtrip() {
    let backend = mock_fixture();
    let dir = tempdir().unwrap();
    let path = dir.path().join("verified_wipe_JOB-1_p1.json");

    // Mint exactly like the `verify` CLI after a passing verification.
    let stamp = verified_wipe_stamp_for_path(&backend, "/dev/sdb1", SERIAL).unwrap();
    assert_eq!(stamp.canonical_path, "/dev/sdb1");
    assert_eq!(stamp.device_serial, SERIAL);
    assert_eq!(stamp.scope, "partial");
    assert_eq!(stamp.parent_name.as_deref(), Some("sdb"));
    assert_eq!(stamp.partition_number, Some(1));
    assert!(
        stamp.partition_table_fingerprint.is_some(),
        "partition receipts must carry the table fingerprint"
    );

    write_verified_wipe_receipt(&path, &stamp).unwrap();
    assert!(path.exists(), "receipt file must exist after a passing verify");

    // No temp debris: the atomic write committed exactly one file.
    assert_eq!(sorted_names(dir.path()), vec!["verified_wipe_JOB-1_p1.json"]);

    let read = read_verified_wipe_receipt(&path).unwrap();
    assert_eq!(
        read, stamp,
        "the format process must read back the exact minted stamp"
    );
}

#[test]
fn receipt_file_is_created_0600() {
    let backend = mock_fixture();
    let dir = tempdir().unwrap();
    let path = dir.path().join("receipt.json");

    let stamp = verified_wipe_stamp_for_path(&backend, "/dev/sdb", SERIAL).unwrap();
    write_verified_wipe_receipt(&path, &stamp).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "receipt must be private to the operator from creation"
    );
}

#[test]
fn receipt_stores_the_canonicalized_path_not_the_raw_path() {
    // The raw argv path is a by-id style symlink; the receipt must carry the
    // canonical node the guard chain re-derives for the format target.
    let backend = mock_fixture().canonicalize_map("/dev/disk/by-id/mock", "/dev/sdb");
    let dir = tempdir().unwrap();
    let path = dir.path().join("receipt.json");

    let stamp = verified_wipe_stamp_for_path(&backend, "/dev/disk/by-id/mock", SERIAL).unwrap();
    assert_eq!(
        stamp.canonical_path, "/dev/sdb",
        "stamp must store the canonicalized path, never the raw symlink"
    );
    // Facts (stat + partition probe) were resolved through the canonical node.
    assert_eq!(stamp.scope, "full");

    write_verified_wipe_receipt(&path, &stamp).unwrap();
    let read = read_verified_wipe_receipt(&path).unwrap();

    // A target minted at the canonical node adopts it — the by-id spelling
    // never reaches the formatter.
    let target = whole_target(&backend);
    adopt_verified_wipe_receipt(&backend, &target, &read).unwrap();
}

#[test]
fn receipt_is_only_adoptable_by_the_exact_target() {
    let backend = mock_fixture();
    let target = partition_target(&backend);
    let dir = tempdir().unwrap();
    let path = dir.path().join("receipt.json");

    let stamp = verified_wipe_stamp_for_path(&backend, "/dev/sdb1", SERIAL).unwrap();
    write_verified_wipe_receipt(&path, &stamp).unwrap();
    let read = read_verified_wipe_receipt(&path).unwrap();

    // Exact target: same node, serial, scope — adopted.
    adopt_verified_wipe_receipt(&backend, &target, &read).unwrap();

    // Wrong serial.
    let mut wrong = read.clone();
    wrong.device_serial = "OTHER-SERIAL".to_string();
    let err = adopt_verified_wipe_receipt(&backend, &target, &wrong).unwrap_err();
    assert!(
        matches!(err, ExecuteError::NotWipedAndVerified),
        "wrong serial must refuse, got {:?}",
        err
    );

    // Wrong partition: receipt minted for a different node on the same disk.
    let other_partition = verified_wipe_stamp_for_path(&backend, "/dev/sda1", SERIAL).unwrap();
    let err = adopt_verified_wipe_receipt(&backend, &target, &other_partition).unwrap_err();
    assert!(
        matches!(err, ExecuteError::NotWipedAndVerified),
        "wrong partition must refuse, got {:?}",
        err
    );

    // Wrong scope: whole-disk receipt vs partition target and vice versa.
    let whole_stamp = verified_wipe_stamp_for_path(&backend, "/dev/sdb", SERIAL).unwrap();
    let err = adopt_verified_wipe_receipt(&backend, &target, &whole_stamp).unwrap_err();
    assert!(
        matches!(err, ExecuteError::NotWipedAndVerified),
        "whole-disk receipt must not authorize a partition format, got {:?}",
        err
    );
    let err = adopt_verified_wipe_receipt(&backend, &whole_target(&backend), &read).unwrap_err();
    assert!(
        matches!(err, ExecuteError::NotWipedAndVerified),
        "partition receipt must not authorize a whole-disk format, got {:?}",
        err
    );
}

#[test]
fn receipt_with_a_foreign_partition_fingerprint_is_refused() {
    let backend = mock_fixture();
    let target = partition_target(&backend);
    let dir = tempdir().unwrap();
    let path = dir.path().join("receipt.json");

    let mut stamp = verified_wipe_stamp_for_path(&backend, "/dev/sdb1", SERIAL).unwrap();
    stamp.partition_table_fingerprint = Some("deadbeef".to_string());
    write_verified_wipe_receipt(&path, &stamp).unwrap();
    let read = read_verified_wipe_receipt(&path).unwrap();

    // Path/serial/scope still match — only the table fingerprint disagrees,
    // and the current table is re-checked at adoption time.
    let err = adopt_verified_wipe_receipt(&backend, &target, &read).unwrap_err();
    assert!(
        matches!(err, ExecuteError::IdentityMismatch(_)),
        "foreign fingerprint must refuse, got {:?}",
        err
    );
}

#[test]
fn receipt_expires_one_hour_after_verification() {
    let backend = mock_fixture();
    let dir = tempdir().unwrap();
    let path = dir.path().join("receipt.json");

    let mut stamp = verified_wipe_stamp_for_path(&backend, "/dev/sdb1", SERIAL).unwrap();
    stamp.verified_at_epoch_secs = now_secs().saturating_sub(60 * 60 + 1);
    write_verified_wipe_receipt(&path, &stamp).unwrap();
    let err = read_verified_wipe_receipt(&path).unwrap_err();
    assert!(
        matches!(err, ExecuteError::NotWipedAndVerified),
        "a receipt older than one hour must be refused, got {:?}",
        err
    );

    // A fresh stamp still round-trips: the expiry is age-based, not a
    // one-time read failure.
    stamp.verified_at_epoch_secs = now_secs();
    write_verified_wipe_receipt(&path, &stamp).unwrap();
    let read = read_verified_wipe_receipt(&path).unwrap();
    assert_eq!(read.verified_at_epoch_secs, stamp.verified_at_epoch_secs);
}

#[test]
fn adopted_receipt_is_one_shot() {
    let backend = mock_fixture();
    let target = partition_target(&backend);
    let dir = tempdir().unwrap();
    let path = dir.path().join("receipt.json");

    let stamp = verified_wipe_stamp_for_path(&backend, "/dev/sdb1", SERIAL).unwrap();
    write_verified_wipe_receipt(&path, &stamp).unwrap();
    let read = read_verified_wipe_receipt(&path).unwrap();

    adopt_verified_wipe_receipt(&backend, &target, &read).unwrap();
    let report = recreate_filesystem_with(&backend, &target, "ext4", "DATA", false).unwrap();
    assert!(report.success);

    // The adoption registry entry was consumed by the first format — a
    // second one, even with the receipt file still on disk, must refuse.
    let err = recreate_filesystem_with(&backend, &target, "ext4", "DATA", false).unwrap_err();
    assert!(
        matches!(err, ExecuteError::NotWipedAndVerified),
        "receipt adoption must be one-shot, got {:?}",
        err
    );
}

#[test]
fn failed_receipt_write_is_typed_and_leaves_no_temp_files() {
    let backend = mock_fixture();
    let dir = tempdir().unwrap();
    let stamp = verified_wipe_stamp_for_path(&backend, "/dev/sdb1", SERIAL).unwrap();

    // (a) Parent directory cannot be created because a regular file occupies
    // the path: typed error, nothing written.
    let blocker = dir.path().join("blocker");
    fs::write(&blocker, b"not a directory").unwrap();
    let err = write_verified_wipe_receipt(&blocker.join("receipt.json"), &stamp).unwrap_err();
    assert!(
        matches!(err, ExecuteError::VerifiedWipeReceiptFailed(_)),
        "parent-dir failure must be typed, got {:?}",
        err
    );
    assert_eq!(sorted_names(dir.path()), vec!["blocker"]);

    // (b) The final path is a non-empty directory: the temp file is written
    // and fsynced, the rename fails, and the temp file must be cleaned up.
    let occupied = dir.path().join("occupied");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("keep"), b"untouched").unwrap();

    let err = write_verified_wipe_receipt(&occupied, &stamp).unwrap_err();
    assert!(
        matches!(err, ExecuteError::VerifiedWipeReceiptFailed(_)),
        "rename failure must be typed, got {:?}",
        err
    );
    assert_eq!(
        sorted_names(dir.path()),
        vec!["blocker", "occupied"],
        "failed writes must not leave orphaned temp files"
    );
    assert_eq!(
        sorted_names(&occupied),
        vec!["keep"],
        "existing destination content must be untouched"
    );
}
