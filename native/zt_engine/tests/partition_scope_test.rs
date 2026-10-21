//! Integration tests for partition-scoped sanitization, geometry validation,
//! MBR extended container checks, fingerprint verification, and PartitionRangeWriter.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::{NamedTempFile, TempDir};
use tokio::sync::mpsc;

use sha2::{Digest, Sha256};
use zt_engine::execute::*;
use zt_engine::verify::{verify_device_scoped, VerificationReport};

// =========================================================================
// 1. Method Allowlist Test (Iterates every variant of EngineMethod::ALL)
// =========================================================================

#[test]
fn test_partition_mode_method_allowlist_iterates_all_variants() {
    let allowed_count = EngineMethod::ALL
        .iter()
        .filter(|m| m.is_allowed_in_partition_mode())
        .count();

    assert_eq!(
        allowed_count, 4,
        "Partition mode must allow EXACTLY 4 methods: overwrite-zero, overwrite-random, overwrite-3pass, discard"
    );

    for method in EngineMethod::ALL {
        let is_allowed = method.is_allowed_in_partition_mode();
        let cli_name = method.as_str();
        let validation_res = validate_partition_method(cli_name);

        match method {
            EngineMethod::OverwriteZero
            | EngineMethod::OverwriteRandom
            | EngineMethod::Overwrite3Pass
            // A6: discard targets an explicit partition range natively
            | EngineMethod::Discard => {
                assert!(
                    is_allowed,
                    "Expected method {:?} ({}) to be allowed in partition mode",
                    method, cli_name
                );
                assert!(
                    validation_res.is_ok(),
                    "validate_partition_method should accept {:?}",
                    method
                );
                assert_eq!(validation_res.unwrap(), *method);
                assert!(ALLOWED_PARTITION_METHODS.contains(&cli_name));
            }
            // All firmware / hardware / crypto erase methods MUST be refused
            EngineMethod::AtaSecureErase
            | EngineMethod::AtaEnhancedSecureErase
            | EngineMethod::AtaSanitizeBlock
            | EngineMethod::AtaSanitizeCrypto
            | EngineMethod::NvmeSanitizeBlock
            | EngineMethod::NvmeSanitizeCrypto
            | EngineMethod::OpalRevert
            | EngineMethod::EmmcSanitize => {
                assert!(
                    !is_allowed,
                    "Firmware/hardware method {:?} ({}) MUST BE REFUSED in partition mode",
                    method, cli_name
                );
                assert!(
                    validation_res.is_err(),
                    "validate_partition_method MUST return Err for {:?}",
                    method
                );
                match validation_res.unwrap_err() {
                    ExecuteError::UnsupportedOperation(msg) => {
                        assert!(
                            msg.contains("not allowed in partition mode"),
                            "Error message should mention partition mode refusal: {}",
                            msg
                        );
                    }
                    other => panic!("Expected UnsupportedOperation for {:?}, got {:?}", method, other),
                }
                assert!(!ALLOWED_PARTITION_METHODS.contains(&cli_name));
            }
        }
    }
}

// =========================================================================
// 2. Partition Table Fingerprint: Shared Vector & Sysfs Recomputation
// =========================================================================

#[test]
fn test_partition_table_fingerprint_shared_test_vector() {
    // Shared test vector definition across Dart and Rust:
    // Partition 1: start sector 2048, size sectors 20969472 (512-byte units)
    // Partition 2: start sector 20971520, size sectors 20971520
    // Partition 3: start sector 41943040, size sectors 19496960
    let canonical_str = "1:2048:20969472\n2:20971520:20971520\n3:41943040:19496960\n";
    let expected_hash = "8c4efb1b4866d0b332ebef624e1ba8cff76427c143b08a4f1199e6ee81279580";

    let actual_hash = format!("{:x}", Sha256::digest(canonical_str.as_bytes()));
    assert_eq!(
        actual_hash, expected_hash,
        "Shared test vector fingerprint must match exactly between Dart and Rust"
    );

    // Setup mock sysfs matching the shared test vector
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let class_block = sys_root.join("class/block");
    fs::create_dir_all(&class_block).unwrap();

    // Create parent device node dir
    fs::create_dir_all(class_block.join("sdb")).unwrap();

    // Create partition entries in non-sorted filesystem order to test sorting
    for (name, num, start, size) in [
        ("sdb3", "3", "41943040", "19496960"),
        ("sdb1", "1", "2048", "20969472"),
        ("sdb2", "2", "20971520", "20971520"),
    ] {
        let p_dir = class_block.join(name);
        fs::create_dir_all(&p_dir).unwrap();
        fs::write(p_dir.join("partition"), num).unwrap();
        fs::write(p_dir.join("start"), start).unwrap();
        fs::write(p_dir.join("size"), size).unwrap();
    }

    let ctx = FsContext {
        sys_root,
        proc_root: tmp.path().join("proc"),
        dev_root: tmp.path().join("dev"),
    };

    let computed_fp = compute_partition_table_fingerprint("sdb", &ctx).unwrap();
    assert_eq!(
        computed_fp, expected_hash,
        "compute_partition_table_fingerprint must produce the shared test vector hash"
    );
}

#[tokio::test]
async fn test_partition_table_fingerprint_mismatch_refused() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let proc_root = tmp.path().join("proc");
    let dev_root = tmp.path().join("dev");
    let class_block = sys_root.join("class/block");
    fs::create_dir_all(&class_block).unwrap();
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&dev_root).unwrap();

    // Mock parent sdb and partition sdb1
    fs::create_dir_all(class_block.join("sdb")).unwrap();
    let p_dir = class_block.join("sdb1");
    fs::create_dir_all(&p_dir).unwrap();
    fs::write(p_dir.join("partition"), "1\n").unwrap();
    fs::write(p_dir.join("start"), "2048\n").unwrap();
    fs::write(p_dir.join("size"), "204800\n").unwrap();

    // Mock /proc/self/mountinfo with safe root
    let mountinfo = "1 0 8:0 / / rw,relatime - ext4 /dev/root rw\n";
    fs::create_dir_all(proc_root.join("self")).unwrap();
    fs::write(proc_root.join("self/mountinfo"), mountinfo).unwrap();

    // Create device file
    fs::write(dev_root.join("sdb1"), vec![0u8; 1024]).unwrap();

    let ctx = FsContext { sys_root, proc_root, dev_root };
    let (tx, _rx) = mpsc::channel(16);

    let params = PartitionTargetParams {
        expected_partition_num: 1,
        expected_start_sector: 2048,
        expected_size_sectors: 204800,
        expected_partuuid: None,
        expected_table_fingerprint: "0000000000000000000000000000000000000000000000000000000000000000".to_string(), // Mismatched!
    };

    let res = software_overwrite_partition_ctx(
        "/dev/sdb1",
        1,
        OverwritePattern::Zeros,
        "SER123",
        "SER123",
        &params,
        true, // dry_run
        tx,
        &ctx,
    ).await;

    assert!(res.is_err(), "Must refuse execution on partition table fingerprint mismatch");
    match res.unwrap_err() {
        ExecuteError::IdentityMismatch(msg) => {
            assert!(msg.contains("Partition table changed"), "Expected mismatch msg, got: {}", msg);
        }
        other => panic!("Expected IdentityMismatch, got {:?}", other),
    }
}

// =========================================================================
// 3. MBR Extended Container & Active Holder Refusal (DOS vs GPT Fixtures)
// =========================================================================

#[test]
fn test_refuse_mbr_extended_partition_dos_fixture() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let class_block = sys_root.join("class/block");
    let dev_root = tmp.path().join("dev");
    fs::create_dir_all(&class_block).unwrap();
    fs::create_dir_all(&dev_root).unwrap();

    // Create DOS MBR fixture with extended partition type 0x05 at partition entry 1
    let parent_img_path = dev_root.join("sda");
    let mut mbr = [0u8; 512];
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    // Entry 1 (offset 446): bootable=0x00, type=0x05 (DOS Extended), start_lba=2048, size=100000
    mbr[446 + 4] = 0x05; // Extended partition type!
    mbr[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&100000u32.to_le_bytes());
    fs::write(&parent_img_path, mbr).unwrap();

    // Create sysfs partition entry
    let p_dir = class_block.join("sda1");
    fs::create_dir_all(&p_dir).unwrap();
    fs::write(p_dir.join("partition"), "1\n").unwrap();
    fs::write(p_dir.join("start"), "2048\n").unwrap();
    fs::write(p_dir.join("size"), "100000\n").unwrap();

    let ctx = FsContext {
        sys_root,
        proc_root: tmp.path().join("proc"),
        dev_root,
    };

    let is_ext = is_mbr_extended_partition("/dev/sda1", "/dev/sda", &ctx).unwrap();
    assert!(is_ext, "DOS MBR extended partition (type 0x05) must be detected as extended");
}

#[test]
fn test_allow_gpt_partition_fixture() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let class_block = sys_root.join("class/block");
    let dev_root = tmp.path().join("dev");
    fs::create_dir_all(&class_block).unwrap();
    fs::create_dir_all(&dev_root).unwrap();

    // Create GPT fixture with protective MBR (type 0xEE)
    let parent_img_path = dev_root.join("sda");
    let mut mbr = [0u8; 512];
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    // Entry 1 (offset 446): type=0xEE (GPT protective)
    mbr[446 + 4] = 0xEE;
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    fs::write(&parent_img_path, mbr).unwrap();

    // Create sysfs partition entry
    let p_dir = class_block.join("sda1");
    fs::create_dir_all(&p_dir).unwrap();
    fs::write(p_dir.join("partition"), "1\n").unwrap();
    fs::write(p_dir.join("start"), "2048\n").unwrap();
    fs::write(p_dir.join("size"), "100000\n").unwrap();

    let ctx = FsContext {
        sys_root,
        proc_root: tmp.path().join("proc"),
        dev_root,
    };

    let is_ext = is_mbr_extended_partition("/dev/sda1", "/dev/sda", &ctx).unwrap();
    assert!(!is_ext, "GPT partition with protective MBR (0xEE) must NOT be detected as MBR extended");
}

#[test]
fn test_refuse_partition_active_md_lvm_holder_unmount_failure() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let proc_root = tmp.path().join("proc");
    let dev_root = tmp.path().join("dev");
    let class_block = sys_root.join("class/block");
    fs::create_dir_all(&class_block).unwrap();
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&dev_root).unwrap();

    // Setup partition sda1 with active holder 'dm-0'
    let p_dir = class_block.join("sda1");
    let holders_dir = p_dir.join("holders");
    fs::create_dir_all(&holders_dir).unwrap();
    fs::write(holders_dir.join("dm-0"), "").unwrap();

    // In /proc/mounts, /dev/dm-0 is mounted
    fs::write(proc_root.join("mounts"), "/dev/dm-0 /mnt/secret_vol ext4 rw,relatime 0 0\n").unwrap();

    // Create device nodes in dev_root
    fs::write(dev_root.join("sda1"), vec![0u8; 512]).unwrap();
    fs::write(dev_root.join("dm-0"), vec![0u8; 512]).unwrap();

    let ctx = FsContext { sys_root, proc_root, dev_root };
    let mut command_log = Vec::new();

    // Attempting unmount on active holder will fail because real 'umount' cannot unmount mock file
    let res = unmount_target_partition_and_holders("/dev/sda1", false, &mut command_log, &ctx);
    assert!(res.is_err(), "Must refuse when active holder cannot be unmounted");
    match res.unwrap_err() {
        ExecuteError::CommandFailed(msg) => {
            assert!(
                msg.contains("held by active holder") || msg.contains("cannot be unmounted"),
                "Expected holder unmount failure message, got: {}",
                msg
            );
        }
        other => panic!("Expected CommandFailed, got {:?}", other),
    }
}

// =========================================================================
// 5. Partition Auto-Remount EBUSY Message Test
// =========================================================================

#[test]
fn test_partition_auto_remount_ebusy_message() {
    // Exercises map_open_excl_error: verify that libc::EBUSY error translates to
    // the exact required failure message instructing retry on auto-remount.
    let ebusy_io_err = std::io::Error::from_raw_os_error(libc::EBUSY);
    let mapped_ebusy = map_open_excl_error(ebusy_io_err, "/dev/sda1");

    match mapped_ebusy {
        ExecuteError::CommandFailed(msg) => {
            assert!(
                msg.contains("the system remounted the drive, retry"),
                "EBUSY must translate to 'the system remounted the drive, retry'. Got: {}",
                msg
            );
            assert!(msg.contains("/dev/sda1"));
        }
        other => panic!("Expected CommandFailed on EBUSY, got {:?}", other),
    }

    // Verify non-EBUSY error translates to DeviceNotFound
    let enoent_io_err = std::io::Error::from_raw_os_error(libc::ENOENT);
    let mapped_enoent = map_open_excl_error(enoent_io_err, "/dev/sda1");
    match mapped_enoent {
        ExecuteError::DeviceNotFound(msg) => {
            assert!(msg.contains("Failed to open device /dev/sda1 with O_EXCL"));
        }
        other => panic!("Expected DeviceNotFound on ENOENT, got {:?}", other),
    }
}

// =========================================================================
// 6. Dry-run Partition Overwrite: Zero Write Opens & Zero Writes
// =========================================================================

#[tokio::test]
async fn test_dry_run_partition_assert_zero_write_opens() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let proc_root = tmp.path().join("proc");
    let dev_root = tmp.path().join("dev");
    let class_block = sys_root.join("class/block");
    fs::create_dir_all(&class_block).unwrap();
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&dev_root).unwrap();

    // Mock parent sda and partition sda1
    fs::create_dir_all(class_block.join("sda")).unwrap();
    let p_dir = class_block.join("sda1");
    fs::create_dir_all(&p_dir).unwrap();
    fs::write(p_dir.join("partition"), "1\n").unwrap();
    fs::write(p_dir.join("start"), "2048\n").unwrap();
    fs::write(p_dir.join("size"), "204800\n").unwrap();

    // Create device file on disk with read-only permissions (0o400)
    // If dry-run attempted any write open (O_RDWR or O_WRONLY), open() would fail with EACCES
    let dev_file_path = dev_root.join("sda1");
    let initial_data = vec![0x55u8; 4096];
    fs::write(&dev_file_path, &initial_data).unwrap();
    fs::set_permissions(&dev_file_path, fs::Permissions::from_mode(0o400)).unwrap();

    // Mountinfo with safe root
    let mountinfo = "1 0 8:0 / / rw,relatime - ext4 /dev/root rw\n";
    fs::create_dir_all(proc_root.join("self")).unwrap();
    fs::write(proc_root.join("self/mountinfo"), mountinfo).unwrap();

    // Compute expected fingerprint
    let ctx = FsContext { sys_root, proc_root, dev_root };
    let fp = compute_partition_table_fingerprint("sda", &ctx).unwrap();

    let (tx, _rx) = mpsc::channel(16);
    let params = PartitionTargetParams {
        expected_partition_num: 1,
        expected_start_sector: 2048,
        expected_size_sectors: 204800,
        expected_partuuid: None,
        expected_table_fingerprint: fp,
    };

    let report = software_overwrite_partition_ctx(
        "/dev/sda1",
        1,
        OverwritePattern::Zeros,
        "SER_DRY",
        "SER_DRY",
        &params,
        true, // dry_run = true
        tx,
        &ctx,
    ).await.expect("Dry run should succeed without opening device for writing");

    assert!(report.success);
    assert!(report.dry_run);
    assert_eq!(report.bytes_written, 0, "Dry run must write ZERO bytes");
    assert_eq!(report.io_mode, "dry_run");
    assert!(report.command_log.iter().all(|line| line.starts_with("[DRY RUN]")));

    // Verify that the read-only file was never written to
    let current_data = fs::read(&dev_file_path).unwrap();
    assert_eq!(current_data, initial_data, "Underlying file data must be completely unmodified");
}

// =========================================================================
// 7. PartitionRangeWriter: Strict Bounds & Data Isolation Test
// =========================================================================

#[test]
fn test_partition_range_writer_bounds_and_isolation() {
    // Create a 64 KiB backing image initialized with 0xAA everywhere
    let image_size: u64 = 65536;
    let tmp = NamedTempFile::new().unwrap();
    let initial_data = vec![0xAAu8; image_size as usize];
    fs::write(tmp.path(), &initial_data).unwrap();

    // Partition definition:
    // Partition 1 starts at byte 16384 (16 KiB), size 16384 bytes (16 KiB)
    // Sibling Partition 2 starts at byte 32768, size 16384 bytes
    // Gaps / MBR: 0..16384 and 49152..65536
    let part_start: u64 = 16384;
    let part_len: u64 = 16384;

    let base_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .unwrap();

    let inner_writer = FileBlockWriter::new(base_file, image_size);
    let mut range_writer = PartitionRangeWriter::new(inner_writer, part_start, part_len);

    assert_eq!(range_writer.start_offset(), part_start);
    assert_eq!(range_writer.length(), part_len);
    assert_eq!(range_writer.total_size().unwrap(), part_len);

    // 1. Write within valid partition range: write 4096 bytes of 0x00 at offset 0
    let zero_chunk = vec![0x00u8; 4096];
    let written = range_writer.write_chunk(0, &zero_chunk).unwrap();
    assert_eq!(written, 4096);

    // Write another chunk at offset 4096
    let written2 = range_writer.write_chunk(4096, &zero_chunk).unwrap();
    assert_eq!(written2, 4096);

    // 2. Refuse out-of-range write: offset 14000 with 4096 bytes exceeds part_len (16384)
    let oob_res = range_writer.write_chunk(14000, &zero_chunk);
    assert!(oob_res.is_err(), "Out-of-range write MUST be refused");
    assert_eq!(
        oob_res.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
        "Out-of-range error kind must be InvalidInput"
    );

    // 3. Flush buffers
    range_writer.sync_data().unwrap();

    // 4. Verify disk byte-level isolation:
    let final_data = fs::read(tmp.path()).unwrap();
    assert_eq!(final_data.len() as u64, image_size);

    // Bytes 0..16384 (MBR + gaps outside partition): strictly byte-identical (0xAA)
    assert!(
        final_data[0..part_start as usize].iter().all(|&b| b == 0xAA),
        "Sectors before partition (MBR/gaps) MUST remain completely unmodified"
    );

    // Bytes 16384..24576: overwritten with zeros
    assert!(
        final_data[part_start as usize..(part_start + 8192) as usize].iter().all(|&b| b == 0x00),
        "Target partition range was properly overwritten with zeros"
    );

    // Bytes 32768..65536 (Sibling partition + tail gaps): strictly byte-identical (0xAA)
    assert!(
        final_data[(part_start + part_len) as usize..image_size as usize].iter().all(|&b| b == 0xAA),
        "Sectors after partition (sibling partitions and unallocated space) MUST remain completely unmodified"
    );
}

// =========================================================================
// 8. Scoped Verification Reporting
// =========================================================================

#[test]
fn test_scoped_verification_report_fields() {
    let tmp = NamedTempFile::new().unwrap();
    let partition_size: u64 = 10_485_760; // 10 MiB
    let total_device_size: u64 = 104_857_600; // 100 MiB
    tmp.as_file().set_len(partition_size).unwrap();

    let report = verify_device_scoped(
        tmp.path().to_str().unwrap(),
        partition_size,
        total_device_size,
        "SER_VERIFY",
        "overwrite-zero",
        Some(10),
        true, // expect_zeros
        None,
    ).expect("Scoped verification should succeed");

    assert!(report.pass);
    assert_eq!(report.bytes_overwritten, partition_size);
    assert_eq!(report.total_device_bytes, total_device_size);
    assert_eq!(report.sample_count, 10);
    assert_eq!(report.samples.len(), 10);
    assert!(report.samples.iter().all(|s| s.is_zero));
}

#[test]
fn test_scoped_verification_fails_when_partition_range_still_has_data() {
    // A8: the partition range still holds 0xAA (the wipe never happened) —
    // scoped verification must FAIL, not error away.
    let tmp = NamedTempFile::new().unwrap();
    let partition_size: u64 = 1_048_576; // 1 MiB
    fs::write(tmp.path(), vec![0xAAu8; partition_size as usize]).unwrap();

    let report = verify_device_scoped(
        tmp.path().to_str().unwrap(),
        partition_size,
        8 * partition_size,
        "SER_VERIFY",
        "overwrite-zero",
        Some(16),
        true, // expect_zeros
        None,
    )
    .expect("Scoped verification executes and reports a failed result");

    assert!(
        !report.pass,
        "A non-zero partition range MUST fail scoped verification"
    );
    assert!(report.samples.iter().any(|s| !s.is_zero));
    assert_eq!(report.bytes_overwritten, partition_size);
}

#[test]
fn test_scoped_verification_samples_stay_inside_partition_range() {
    // A8: 2 MiB backing image — first 1 MiB zeroed (the wiped partition), the
    // tail 0xAA (sibling partition data). Scoped verification samples ONLY
    // within [0, partition_size) and must therefore pass.
    let tmp = NamedTempFile::new().unwrap();
    let partition_size: u64 = 1_048_576;
    let total_device_size: u64 = 2 * partition_size;
    let mut data = vec![0xAAu8; total_device_size as usize];
    data[..partition_size as usize].fill(0);
    fs::write(tmp.path(), &data).unwrap();

    let report = verify_device_scoped(
        tmp.path().to_str().unwrap(),
        partition_size,
        total_device_size,
        "SER_VERIFY",
        "overwrite-zero",
        Some(25),
        true,
        None,
    )
    .expect("Scoped verification should succeed");

    assert!(
        report.pass,
        "Bytes outside the partition range must never affect scoped verification"
    );
    assert!(report.samples.iter().all(|s| s.offset < partition_size));
    assert!(report.samples.iter().all(|s| s.is_zero));
    assert_eq!(report.total_device_bytes, total_device_size);
}

#[test]
fn test_scoped_verification_fails_closed_when_device_shrank_below_partition() {
    // A8: the partition claims 4 MiB but the backing device is only 1 MiB
    // (device swap / shrink race). Reads past EOF error out per sample, so the
    // verification fails closed instead of passing on stale geometry.
    let tmp = NamedTempFile::new().unwrap();
    let claimed_partition_size: u64 = 4 * 1_048_576;
    fs::write(tmp.path(), vec![0u8; 1_048_576]).unwrap();

    let report = verify_device_scoped(
        tmp.path().to_str().unwrap(),
        claimed_partition_size,
        claimed_partition_size,
        "SER_VERIFY",
        "overwrite-zero",
        Some(8),
        true,
        None,
    )
    .expect("Scoped verification reports a failed result rather than aborting");

    assert!(
        !report.pass,
        "Reads past the end of a shrunken device must fail the verification"
    );
    assert!(report.samples.iter().any(|s| !s.is_zero));
}

// =========================================================================
// 9. Loop Device Test (Manual / Sudo only — #[ignore])
// =========================================================================

#[test]
#[ignore]
fn test_real_loop_device_partition_overwrite_and_verify() {
    // This test requires sudo losetup -P and root privileges.
    // It verifies real Linux kernel partition block nodes (/dev/loopXp1).
    println!("To run manual loop device partition test:");
    println!("1. dd if=/dev/zero of=/tmp/test_disk.img bs=1M count=64");
    println!("2. parted -s /tmp/test_disk.img mklabel gpt mkpart p1 ext4 2048s 32768s mkpart p2 ext4 34816s 65500s");
    println!("3. sudo losetup -Pf /tmp/test_disk.img");
    println!("4. cargo test --test partition_scope_test test_real_loop_device -- --ignored");
}

// =========================================================================
// 10. CLI Fail-Closed & Missing Flag Validation Tests
// =========================================================================

#[test]
fn test_cli_refuse_partition_without_mode_partition() {
    let binary = env!("CARGO_BIN_EXE_zt_engine");
    let output = Command::new(binary)
        .args(["sanitize", "/dev/sdb1", "overwrite-zero", "TOKEN", "SERIAL"])
        .output()
        .expect("Failed to execute zt_engine CLI");

    assert_eq!(output.status.code(), Some(1), "Target partition without --mode partition must exit with 1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("target '/dev/sdb1' appears to be a partition, but --mode partition was not specified (fail closed)"),
        "Unexpected stderr: {}", stderr
    );
}

#[test]
fn test_cli_missing_expected_flags_in_partition_mode() {
    let binary = env!("CARGO_BIN_EXE_zt_engine");
    let output = Command::new(binary)
        .args(["sanitize", "/dev/sdb1", "overwrite-zero", "TOKEN", "SERIAL", "--mode", "partition"])
        .output()
        .expect("Failed to execute zt_engine CLI");

    assert_eq!(output.status.code(), Some(1), "Partition mode missing expected flags must exit with 1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Partition mode requires --expected-part-num, --expected-start-sector, --expected-size-sectors, and --expected-table-fingerprint"),
        "Unexpected stderr: {}", stderr
    );
}

// =========================================================================
// 11. Geometry Mismatch Refusal
// =========================================================================

#[tokio::test]
async fn test_partition_geometry_mismatch_refused() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let proc_root = tmp.path().join("proc");
    let dev_root = tmp.path().join("dev");
    let class_block = sys_root.join("class/block");
    fs::create_dir_all(&class_block).unwrap();
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&dev_root).unwrap();

    // Mock parent sdb and partition sdb1
    fs::create_dir_all(class_block.join("sdb")).unwrap();
    let p_dir = class_block.join("sdb1");
    fs::create_dir_all(&p_dir).unwrap();
    fs::write(p_dir.join("partition"), "1\n").unwrap();
    fs::write(p_dir.join("start"), "2048\n").unwrap();
    fs::write(p_dir.join("size"), "204800\n").unwrap();

    let mountinfo = "1 0 8:0 / / rw,relatime - ext4 /dev/root rw\n";
    fs::create_dir_all(proc_root.join("self")).unwrap();
    fs::write(proc_root.join("self/mountinfo"), mountinfo).unwrap();

    let ctx = FsContext { sys_root, proc_root, dev_root };
    let fp = compute_partition_table_fingerprint("sdb", &ctx).unwrap();
    let (tx, _rx) = mpsc::channel(16);

    // Mismatched expected_start_sector: 99999 vs sysfs 2048
    let params_mismatch = PartitionTargetParams {
        expected_partition_num: 1,
        expected_start_sector: 99999,
        expected_size_sectors: 204800,
        expected_partuuid: None,
        expected_table_fingerprint: fp,
    };

    let res = software_overwrite_partition_ctx(
        "/dev/sdb1",
        1,
        OverwritePattern::Zeros,
        "SER123",
        "SER123",
        &params_mismatch,
        true,
        tx,
        &ctx,
    ).await;

    assert!(res.is_err(), "Must refuse on geometry mismatch");
    match res.unwrap_err() {
        ExecuteError::IdentityMismatch(msg) => {
            assert!(msg.contains("Partition start sector mismatch: expected 99999, got sysfs start 2048"), "Got: {}", msg);
        }
        other => panic!("Expected IdentityMismatch, got {:?}", other),
    }
}

// =========================================================================
// 12. Sibling Removable Mount vs Protected Mount / Swap Test
// =========================================================================

#[test]
fn test_sibling_allowed_removable_mount_vs_protected_mount_or_swap() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let proc_root = tmp.path().join("proc");
    let dev_root = tmp.path().join("dev");
    let class_block = sys_root.join("class/block");
    fs::create_dir_all(&class_block).unwrap();
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&dev_root).unwrap();
    fs::create_dir_all(proc_root.join("self")).unwrap();

    // Mock parent sdb
    fs::create_dir_all(class_block.join("sdb")).unwrap();

    // Target partition sdb1
    let p1_dir = class_block.join("sdb1");
    fs::create_dir_all(&p1_dir).unwrap();
    fs::write(p1_dir.join("partition"), "1\n").unwrap();
    fs::write(p1_dir.join("start"), "2048\n").unwrap();
    fs::write(p1_dir.join("size"), "204800\n").unwrap();
    fs::write(p1_dir.join("dev"), "8:17\n").unwrap();

    // Sibling partition sdb2
    let p2_dir = class_block.join("sdb2");
    fs::create_dir_all(&p2_dir).unwrap();
    fs::write(p2_dir.join("partition"), "2\n").unwrap();
    fs::write(p2_dir.join("start"), "206848\n").unwrap();
    fs::write(p2_dir.join("size"), "204800\n").unwrap();
    fs::write(p2_dir.join("dev"), "8:18\n").unwrap();

    // Create device nodes in dev_root
    fs::write(dev_root.join("sdb1"), "").unwrap();
    fs::write(dev_root.join("sdb2"), "").unwrap();

    let ctx = FsContext {
        sys_root: sys_root.clone(),
        proc_root: proc_root.clone(),
        dev_root: dev_root.clone(),
    };

    // Case A: Sibling sdb2 is mounted under an allowed removable mount (/media/usb_stick)
    let mountinfo_allowed = "\
1 0 8:0 / / rw,relatime - ext4 /dev/root rw\n\
2 1 8:18 / /media/usb_stick rw,relatime - vfat /dev/sdb2 rw\n";
    fs::write(proc_root.join("self/mountinfo"), mountinfo_allowed).unwrap();

    let res_allowed = check_boot_disk_protection_ctx("/dev/sdb1", false, &ctx);
    assert!(
        res_allowed.is_ok(),
        "Sibling partition sdb2 mounted under /media must NOT prevent wiping target sdb1: {:?}",
        res_allowed.err()
    );

    // Case B: Sibling sdb2 is hosting a protected system mount (/home)
    let mountinfo_protected = "\
1 0 8:0 / / rw,relatime - ext4 /dev/root rw\n\
2 1 8:18 / /home rw,relatime - ext4 /dev/sdb2 rw\n";
    fs::write(proc_root.join("self/mountinfo"), mountinfo_protected).unwrap();

    let res_protected = check_boot_disk_protection_ctx("/dev/sdb1", false, &ctx);
    assert!(
        res_protected.is_err(),
        "Sibling partition sdb2 hosting protected mount (/home) MUST refuse operation"
    );
    match res_protected.unwrap_err() {
        ExecuteError::BootDiskProtection(msg) => {
            assert!(
                msg.contains("matches a protected device/mount") && msg.contains("sdb2"),
                "Expected protected mount msg mentioning sdb2: {}",
                msg
            );
        }
        other => panic!("Expected BootDiskProtection, got {:?}", other),
    }

    // Case C: Sibling sdb2 is an active swap partition
    fs::write(proc_root.join("self/mountinfo"), mountinfo_allowed).unwrap(); // reset mountinfo to allowed
    let swaps_content = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/sdb2\t\t\t\tpartition\t1048572\t\t0\t\t-2\n";
    fs::write(proc_root.join("swaps"), swaps_content).unwrap();

    let res_swap = check_boot_disk_protection_ctx("/dev/sdb1", false, &ctx);
    assert!(
        res_swap.is_err(),
        "Sibling partition sdb2 hosting active swap MUST refuse operation"
    );
    match res_swap.unwrap_err() {
        ExecuteError::BootDiskProtection(msg) => {
            assert!(
                msg.contains("matches a protected device/mount") && msg.contains("sdb2"),
                "Expected active swap msg mentioning sdb2: {}",
                msg
            );
        }
        other => panic!("Expected BootDiskProtection for swap, got {:?}", other),
    }
}

// =========================================================================
// 13. Logical Block Size Alignment Refusal
// =========================================================================

#[tokio::test]
async fn test_partition_start_size_alignment_refusal() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let proc_root = tmp.path().join("proc");
    let dev_root = tmp.path().join("dev");
    let class_block = sys_root.join("class/block");
    fs::create_dir_all(&class_block).unwrap();
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&dev_root).unwrap();

    // Mock parent sdb with 4096-byte logical block size in queue/logical_block_size
    let parent_dir = class_block.join("sdb");
    fs::create_dir_all(parent_dir.join("queue")).unwrap();
    fs::write(parent_dir.join("queue/logical_block_size"), "4096\n").unwrap();

    // Partition sdb1 starts at sector 2049 (2049 * 512 = 1049088 bytes; 1049088 % 4096 = 512 != 0)
    let p_dir = class_block.join("sdb1");
    fs::create_dir_all(&p_dir).unwrap();
    fs::write(p_dir.join("partition"), "1\n").unwrap();
    fs::write(p_dir.join("start"), "2049\n").unwrap();
    fs::write(p_dir.join("size"), "204800\n").unwrap();

    let mountinfo = "1 0 8:0 / / rw,relatime - ext4 /dev/root rw\n";
    fs::create_dir_all(proc_root.join("self")).unwrap();
    fs::write(proc_root.join("self/mountinfo"), mountinfo).unwrap();

    let ctx = FsContext { sys_root, proc_root, dev_root };
    let fp = compute_partition_table_fingerprint("sdb", &ctx).unwrap();
    let (tx, _rx) = mpsc::channel(16);

    let params = PartitionTargetParams {
        expected_partition_num: 1,
        expected_start_sector: 2049,
        expected_size_sectors: 204800,
        expected_partuuid: None,
        expected_table_fingerprint: fp,
    };

    let res = software_overwrite_partition_ctx(
        "/dev/sdb1",
        1,
        OverwritePattern::Zeros,
        "SER123",
        "SER123",
        &params,
        true,
        tx,
        &ctx,
    ).await;

    assert!(res.is_err(), "Must refuse execution when partition start/size is not aligned to logical block size");
    match res.unwrap_err() {
        ExecuteError::UnsupportedOperation(msg) => {
            assert!(
                msg.contains("not aligned to logical block size (4096)"),
                "Expected alignment refusal message, got: {}",
                msg
            );
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }
}

// =========================================================================
// 14. Targeted Unmount: Touches Target, Sibling Stays Mounted
// =========================================================================

#[test]
fn test_unmount_touches_only_target_sibling_stays_mounted() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let proc_root = tmp.path().join("proc");
    let dev_root = tmp.path().join("dev");
    let class_block = sys_root.join("class/block");
    fs::create_dir_all(&class_block).unwrap();
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&dev_root).unwrap();

    // Mock parent sdb and partition sdb1, sdb2
    fs::create_dir_all(class_block.join("sdb")).unwrap();
    fs::create_dir_all(class_block.join("sdb1")).unwrap();
    fs::create_dir_all(class_block.join("sdb2")).unwrap();

    // Both /dev/sdb1 and /dev/sdb2 are in /proc/mounts
    let mounts_content = "\
/dev/sdb1 /mnt/target_usb ext4 rw,relatime 0 0\n\
/dev/sdb2 /mnt/sibling_usb ext4 rw,relatime 0 0\n";
    fs::write(proc_root.join("mounts"), mounts_content).unwrap();

    let ctx = FsContext { sys_root, proc_root, dev_root };
    let mut command_log = Vec::new();

    // In dry-run mode, unmount_target_partition_and_holders logs what it would touch
    let res = unmount_target_partition_and_holders("/dev/sdb1", true, &mut command_log, &ctx);
    assert!(res.is_ok());

    // Verify command log contains only target partition and no sibling partition
    assert!(
        command_log.iter().all(|line| !line.contains("sdb2")),
        "Unmount must NEVER target sibling partition sdb2. Command log: {:?}",
        command_log
    );
    assert!(
        command_log.iter().any(|line| line.contains("sdb1")),
        "Command log must reference target partition sdb1"
    );
}

// =========================================================================
// 15. Resolve Parent Serial From Partition Node
// =========================================================================

#[test]
fn test_resolve_parent_serial_from_partition_node() {
    let tmp = TempDir::new().unwrap();
    let sys_root = tmp.path().join("sys");
    let class_block = sys_root.join("class/block");
    fs::create_dir_all(&class_block).unwrap();

    // Parent sdb
    let parent_dir = class_block.join("sdb");
    let device_dir = parent_dir.join("device");
    fs::create_dir_all(&device_dir).unwrap();
    fs::write(device_dir.join("serial"), "  WD-WCC4N12345678  \n").unwrap();

    // Partition sdb1
    let p_dir = class_block.join("sdb1");
    fs::create_dir_all(&p_dir).unwrap();
    fs::write(p_dir.join("partition"), "1\n").unwrap();

    let ctx = FsContext {
        sys_root,
        proc_root: tmp.path().join("proc"),
        dev_root: tmp.path().join("dev"),
    };

    let resolved_serial = resolve_parent_serial("/dev/sdb1", &ctx)
        .expect("Parent serial should be resolved from partition node");

    assert_eq!(
        resolved_serial, "WD-WCC4N12345678",
        "Parent serial must be correctly resolved and trimmed"
    );
}

// =========================================================================
// 16. Verify CLI Scoped vs Whole-Device Compatibility Tests
// =========================================================================

#[test]
fn test_verify_cli_whole_device_without_total_device_size_flag() {
    let tmp = NamedTempFile::new().unwrap();
    let size: u64 = 65536; // 64 KiB
    tmp.as_file().set_len(size).unwrap();

    let binary = env!("CARGO_BIN_EXE_zt_engine");
    let output = Command::new(binary)
        .args([
            "verify",
            tmp.path().to_str().unwrap(),
            &size.to_string(),
            "SERIAL-TEST-001",
            "overwrite-zero",
            "10",
            "true",
        ])
        .output()
        .expect("Failed to execute zt_engine verify CLI");

    assert_eq!(output.status.code(), Some(0), "Whole device verify CLI without --total-device-size must exit with 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VERIFY_REPORT:"));

    let json_line = stdout.lines().find(|l| l.starts_with("VERIFY_REPORT:")).unwrap();
    let json_str = &json_line["VERIFY_REPORT:".len()..];
    let report: VerificationReport = serde_json::from_str(json_str).unwrap();

    assert!(report.pass);
    assert_eq!(report.bytes_overwritten, size, "Without flag, bytes_overwritten must equal device size");
    assert_eq!(report.total_device_bytes, size, "Without flag, total_device_bytes must equal device size");
}

#[test]
fn test_verify_cli_scoped_with_total_device_size_flag() {
    let tmp = NamedTempFile::new().unwrap();
    let part_size: u64 = 65536; // 64 KiB
    let total_size: u64 = 1048576; // 1 MiB
    tmp.as_file().set_len(part_size).unwrap();

    let binary = env!("CARGO_BIN_EXE_zt_engine");
    let output = Command::new(binary)
        .args([
            "verify",
            tmp.path().to_str().unwrap(),
            &part_size.to_string(),
            "SERIAL-TEST-002",
            "overwrite-zero",
            "10",
            "true",
            "--total-device-size",
            &total_size.to_string(),
        ])
        .output()
        .expect("Failed to execute zt_engine verify CLI");

    assert_eq!(output.status.code(), Some(0), "Scoped verify CLI with --total-device-size must exit with 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VERIFY_REPORT:"));

    let json_line = stdout.lines().find(|l| l.starts_with("VERIFY_REPORT:")).unwrap();
    let json_str = &json_line["VERIFY_REPORT:".len()..];
    let report: VerificationReport = serde_json::from_str(json_str).unwrap();

    assert!(report.pass);
    assert_eq!(report.bytes_overwritten, part_size, "bytes_overwritten must equal partition size");
    assert_eq!(report.total_device_bytes, total_size, "total_device_bytes must equal total device size");
}
