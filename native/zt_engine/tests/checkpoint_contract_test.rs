//! Contract test for the engine checkpoint writer.
//!
//! The Dart side of the contract is `test/services/checkpoint_contract_test.dart`
//! plus the fixture `test/fixtures/active_checkpoint.json`. This test calls the
//! engine's real writer into a temp dir and asserts it produces the same shape.
//!
//! Shape-only: exact key set, and the fixture's non-timestamp field values.
//! Never writes to a real block device.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// Serial whose sha256 is the fixture's `device_id_hash`.
const SERIAL: &str = "CONTRACT-SERIAL-1";
const JOB_ID: &str = "contract-job-1";
const DEVICE_SIZE: u64 = 16_000_000_000;
const BYTES_DONE: u64 = 3_500_000_000;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test")
        .join("fixtures")
        .join("active_checkpoint.json")
}

fn sorted_keys(value: &serde_json::Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("fixture must be a JSON object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

#[test]
fn checkpoint_writer_shape_matches_dart_fixture() {
    let fixture: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(fixture_path()).expect("read fixture"))
            .expect("parse fixture");

    let dir = tempfile::tempdir().expect("tempdir");
    zt_engine::execute::write_checkpoint_file_in_dir(
        dir.path(),
        JOB_ID,
        SERIAL,
        DEVICE_SIZE,
        BYTES_DONE,
    );

    let written_path = dir.path().join("active_checkpoint.json");
    assert!(
        written_path.exists(),
        "engine must write active_checkpoint.json"
    );

    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&written_path).expect("read written"))
            .expect("parse written");

    // Exact same key set = same shape.
    assert_eq!(
        sorted_keys(&written),
        sorted_keys(&fixture),
        "engine checkpoint key set must match the Dart fixture"
    );
    assert_eq!(written["job_id"], fixture["job_id"]);
    assert_eq!(written["device_size"], fixture["device_size"]);
    assert_eq!(written["device_id_hash"], fixture["device_id_hash"]);
    assert_eq!(written["bytes_done"], fixture["bytes_done"]);
    assert!(
        written["timestamp"].as_u64().is_some(),
        "timestamp must serialize as a u64"
    );

    // No leftover temp file.
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temp files may linger: {leftovers:?}"
    );
}

#[test]
fn checkpoint_hash_is_sha256_of_serial() {
    let dir = tempfile::tempdir().expect("tempdir");
    zt_engine::execute::write_checkpoint_file_in_dir(dir.path(), JOB_ID, SERIAL, DEVICE_SIZE, 0);

    let written: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(dir.path().join("active_checkpoint.json")).unwrap(),
    )
    .unwrap();

    let expected = format!("{:x}", Sha256::digest(SERIAL.as_bytes()));
    assert_eq!(
        written["device_id_hash"].as_str().unwrap(),
        expected,
        "device_id_hash must be sha256(serial) in lowercase hex"
    );

    // And it must equal the fixed value pinned in the Dart fixture.
    let fixture: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(fixture_path()).unwrap()).unwrap();
    assert_eq!(written["device_id_hash"], fixture["device_id_hash"]);
}
