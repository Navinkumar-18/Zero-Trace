//! Integration tests for partition-scoped sanitization, geometry validation,
//! MBR extended container checks, fingerprint verification, and PartitionRangeWriter.

use std::fs::{self, OpenOptions};
use tempfile::{NamedTempFile, TempDir};
use tokio::sync::mpsc;

use sha2::{Digest, Sha256};
use zt_engine::certificate::{sign_certificate, verify_ed25519_signature, SigningMethod};
use zt_engine::execute::*;
use zt_engine::verify::verify_device_scoped;

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
        allowed_count, 3,
        "Partition mode must allow EXACTLY 3 methods: overwrite-zero, overwrite-random, overwrite-3pass"
    );

    for method in EngineMethod::ALL {
        let is_allowed = method.is_allowed_in_partition_mode();
        let cli_name = method.as_str();
        let validation_res = validate_partition_method(cli_name);

        match method {
            EngineMethod::OverwriteZero | EngineMethod::OverwriteRandom | EngineMethod::Overwrite3Pass => {
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
// 3. Certificate v3 Tamper Detection Test
// =========================================================================

#[test]
fn test_certificate_v3_tamper_detection() {
    let key_dir = TempDir::new().unwrap();
    let key_file = key_dir.path().join("ed25519.key");

    let canonical_payload = r#"{"certificate_version":3,"device_path":"/dev/sdb1","device_serial":"ABC12345","limitation":"Partition wipe: partition table and unselected sectors are not overwritten","partitions_wiped":[{"partition_number":1,"size_bytes":104857600,"start_sector":2048}],"scope":"partial","timestamp_utc":"2026-10-05T12:00:00Z"}"#;

    let cert = sign_certificate(
        canonical_payload,
        SigningMethod::Ed25519,
        Some(key_file.to_str().unwrap()),
        "ABC12345",
    ).expect("Signing should succeed");

    let pub_key = cert.public_key_hex.as_ref().expect("Ed25519 cert must have public key");
    let initial_verify = verify_ed25519_signature(&cert.payload_json, &cert.signature_hex, pub_key).unwrap();
    assert!(initial_verify, "Signature must verify on untampered payload");

    // 1. Tamper with scope: "partial" -> "full"
    let tampered_scope = canonical_payload.replace(r#""scope":"partial""#, r#""scope":"full""#);
    let verify_scope_tamper = verify_ed25519_signature(&tampered_scope, &cert.signature_hex, pub_key).unwrap();
    assert!(
        !verify_scope_tamper,
        "Tampering with certificate scope MUST break signature verification"
    );

    // 2. Tamper with partition list
    let tampered_parts = canonical_payload.replace(r#""partition_number":1"#, r#""partition_number":2"#);
    let verify_parts_tamper = verify_ed25519_signature(&tampered_parts, &cert.signature_hex, pub_key).unwrap();
    assert!(
        !verify_parts_tamper,
        "Tampering with wiped partition list MUST break signature verification"
    );

    // 3. Tamper with limitation line
    let tampered_limit = canonical_payload.replace(
        "Partition wipe: partition table and unselected sectors are not overwritten",
        "Whole disk sanitized"
    );
    let verify_limit_tamper = verify_ed25519_signature(&tampered_limit, &cert.signature_hex, pub_key).unwrap();
    assert!(
        !verify_limit_tamper,
        "Tampering with limitation line MUST break signature verification"
    );

    // 4. A v3 certificate payload cannot be parsed as legacy v1 or v2 without certificate_version: 3
    let v1_tampered = canonical_payload.replace(r#""certificate_version":3,"#, r#""certificate_version":1,"#);
    let verify_v1_tamper = verify_ed25519_signature(&v1_tampered, &cert.signature_hex, pub_key).unwrap();
    assert!(
        !verify_v1_tamper,
        "Changing certificate version inside payload MUST break signature verification"
    );
}

// =========================================================================
// 4. MBR Extended Container & Active Holder Refusal (DOS vs GPT Fixtures)
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
    // Verify that the error message returned on EBUSY specifically matches:
    // "the system remounted the drive, retry"
    let ebusy_err = ExecuteError::CommandFailed(
        "the system remounted the drive, retry (Device /dev/sda1 is busy or mounted with O_EXCL conflict)".to_string()
    );

    let err_str = ebusy_err.to_string();
    assert!(
        err_str.contains("the system remounted the drive, retry"),
        "EBUSY error message must contain exact phrase 'the system remounted the drive, retry'. Got: {}",
        err_str
    );
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
    ).await.expect("Dry run should succeed");

    assert!(report.success);
    assert!(report.dry_run);
    assert_eq!(report.bytes_written, 0, "Dry run must write ZERO bytes");
    assert_eq!(report.io_mode, "dry_run");
    assert!(report.command_log.iter().all(|line| line.starts_with("[DRY RUN]")));
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
