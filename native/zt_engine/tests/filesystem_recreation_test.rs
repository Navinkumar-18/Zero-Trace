//! Phase F: optional filesystem recreation behind the guard chain.
//!
//! Every test uses [`MockBackend`] — no real devices or hardware.

use zt_engine::backend::conformance::{mock_fixture, partition_params};
use zt_engine::backend::mock::MockBackend;
use zt_engine::execute::{
    mark_wiped_and_verified, recreate_filesystem_with, recreate_whole_device_with,
};
use zt_engine::guard::{self, TargetScope};
use zt_engine::types::{ExecuteError, PartitionTableType};

const SERIAL: &str = "CONFORMANCE-SERIAL";

fn partition_target(backend: &MockBackend) -> zt_engine::guard::ValidatedTarget {
    let params = partition_params(backend, "/dev/sdb1", 1, 2048, 4096).unwrap();
    guard::validate_partition_target(backend, "/dev/sdb1", &params, false, SERIAL).unwrap()
}

fn whole_target(backend: &MockBackend) -> zt_engine::guard::ValidatedTarget {
    guard::validate_whole_disk_target(backend, "/dev/sdb", SERIAL, SERIAL, false).unwrap()
}

#[test]
fn refuses_when_target_was_not_just_wiped_and_verified() {
    let backend = mock_fixture();
    let target = partition_target(&backend);
    let err = recreate_filesystem_with(&backend, &target, "ext4", "DATA", false).unwrap_err();
    assert!(
        matches!(err, ExecuteError::NotWipedAndVerified),
        "got {:?}",
        err
    );
    assert!(backend.executed_commands().is_empty());
}

#[test]
fn refuses_when_target_is_mounted() {
    let mut backend = mock_fixture();
    let target = partition_target(&backend);
    mark_wiped_and_verified(&backend, &target).unwrap();
    backend.mutate_mountinfo(
        "25 30 8:0 / / rw,relatime shared:1 - ext4 /dev/sda rw\n\
         26 30 16:1 / /mnt/data rw,relatime shared:1 - ext4 /dev/sdb1 rw\n",
    );
    let err = recreate_filesystem_with(&backend, &target, "ext4", "DATA", false).unwrap_err();
    assert!(
        matches!(err, ExecuteError::TargetMounted(_)),
        "got {:?}",
        err
    );
    assert!(backend.executed_commands().is_empty());
}

#[test]
fn refuses_when_target_changed_after_verification() {
    let mut backend = mock_fixture();
    let target = partition_target(&backend);
    mark_wiped_and_verified(&backend, &target).unwrap();
    // Shrink the device: the size pinned at mint time no longer matches.
    backend.mutate_attr("sdb1", "size", "2048");
    let err = recreate_filesystem_with(&backend, &target, "ext4", "DATA", false).unwrap_err();
    assert!(
        matches!(err, ExecuteError::IdentityMismatch(_)),
        "got {:?}",
        err
    );
    assert!(backend.executed_commands().is_empty());
}

#[test]
fn refuses_partition_scope_when_whole_disk_node_is_passed() {
    let backend = mock_fixture().canonicalize_map("/dev/sdb1", "/dev/sdb");
    let target = partition_target(&backend);
    assert!(matches!(target.scope(), TargetScope::Partition { .. }));
    assert_eq!(target.canonical_path(), "/dev/sdb");
    mark_wiped_and_verified(&backend, &target).unwrap();
    let err = recreate_filesystem_with(&backend, &target, "ext4", "DATA", false).unwrap_err();
    assert!(
        matches!(err, ExecuteError::FilesystemScopeMismatch(_)),
        "got {:?}",
        err
    );
    assert!(backend.executed_commands().is_empty());
}

#[test]
fn formats_only_the_validated_partition_after_verification() {
    let backend = mock_fixture();
    let target = partition_target(&backend);
    let before = guard::compute_partition_table_fingerprint(&backend, "sdb").unwrap();
    mark_wiped_and_verified(&backend, &target).unwrap();

    let report = recreate_filesystem_with(&backend, &target, "vfat", "BOOT", false).unwrap();

    assert!(report.success);
    assert_eq!(report.tool, "mkfs.vfat");
    assert_eq!(report.fs_type, "vfat");
    assert_eq!(report.label, "BOOT");
    assert!(report.sanitization_verified_before_format);
    assert_eq!(report.scope, "partial");
    assert_eq!(
        backend.executed_commands(),
        vec!["mkfs.vfat -F 32 -n BOOT /dev/sdb1".to_string()]
    );
    assert_eq!(backend.partition_table_reread_count(), 1);
    let after = guard::compute_partition_table_fingerprint(&backend, "sdb").unwrap();
    assert_eq!(before, after, "partition table must be byte-identical");
}

#[test]
fn supports_each_allowed_filesystem_tool() {
    for (fs, expected) in [
        ("vfat", "mkfs.vfat -F 32 -n LBL /dev/sdb1"),
        ("exfat", "mkfs.exfat -n LBL /dev/sdb1"),
        ("ntfs", "mkfs.ntfs -Q -L LBL /dev/sdb1"),
        ("ext4", "mkfs.ext4 -F -L LBL /dev/sdb1"),
    ] {
        let backend = mock_fixture();
        let target = partition_target(&backend);
        mark_wiped_and_verified(&backend, &target).unwrap();
        let report = recreate_filesystem_with(&backend, &target, fs, "LBL", false).unwrap();
        assert_eq!(report.tool, expected.split(' ').next().unwrap());
        assert_eq!(backend.executed_commands(), vec![expected.to_string()]);
    }
}

#[test]
fn rejects_unknown_filesystem_type_before_any_tool() {
    let backend = mock_fixture();
    let target = partition_target(&backend);
    mark_wiped_and_verified(&backend, &target).unwrap();
    let err = recreate_filesystem_with(&backend, &target, "btrfs", "LBL", false).unwrap_err();
    assert!(
        matches!(err, ExecuteError::UnsupportedFilesystem(_)),
        "got {:?}",
        err
    );
    assert!(backend.executed_commands().is_empty());
}

#[test]
fn verification_stamp_is_consumed_by_a_successful_format() {
    let backend = mock_fixture();
    let target = partition_target(&backend);
    mark_wiped_and_verified(&backend, &target).unwrap();
    recreate_filesystem_with(&backend, &target, "ext4", "DATA", false).unwrap();
    let err = recreate_filesystem_with(&backend, &target, "ext4", "DATA", false).unwrap_err();
    assert!(
        matches!(err, ExecuteError::NotWipedAndVerified),
        "got {:?}",
        err
    );
}

#[test]
fn whole_device_recreation_requires_its_own_confirmation_token() {
    let backend = mock_fixture();
    let target = whole_target(&backend);
    mark_wiped_and_verified(&backend, &target).unwrap();
    let err = recreate_whole_device_with(
        &backend,
        &target,
        "gpt",
        "ext4",
        "NEW",
        "WRONG-TOKEN",
        false,
    )
    .unwrap_err();
    assert!(
        matches!(err, ExecuteError::ConfirmationMismatch),
        "got {:?}",
        err
    );
    assert!(backend.executed_commands().is_empty());
}

#[test]
fn whole_device_recreation_writes_one_partition_and_formats_it() {
    let backend = mock_fixture();
    let target = whole_target(&backend);
    mark_wiped_and_verified(&backend, &target).unwrap();
    let report =
        recreate_whole_device_with(&backend, &target, "gpt", "ext4", "NEW", SERIAL, false).unwrap();
    assert!(report.success);
    assert!(report.partition_table_created);
    assert_eq!(report.partition_table_type.as_deref(), Some("gpt"));
    assert_eq!(report.scope, "full");
    assert_eq!(
        backend.executed_commands(),
        vec!["mkfs.ext4 -F -L NEW /dev/sdb1".to_string()]
    );
    // Protective MBR signature + GPT header are in the device image.
    let image = backend.data();
    assert_eq!(&image[510..512], &[0x55, 0xaa]);
    assert_eq!(&image[512..520], b"EFI PART");
}

#[test]
fn whole_device_recreation_refuses_partition_scope() {
    let backend = mock_fixture();
    let target = partition_target(&backend);
    mark_wiped_and_verified(&backend, &target).unwrap();
    let err = recreate_whole_device_with(
        &backend,
        &target,
        PartitionTableType::Gpt.as_str(),
        "ext4",
        "NEW",
        SERIAL,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(err, ExecuteError::FilesystemScopeMismatch(_)),
        "got {:?}",
        err
    );
    assert!(backend.executed_commands().is_empty());
}
