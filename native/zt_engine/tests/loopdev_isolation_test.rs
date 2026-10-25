//! P3: loop-image isolation tests (manual, root-only).
//!
//! These tests automate the "pendrive" verification: build a 3-partition
//! disk image, fill every partition with a distinct pattern, then wipe ONE
//! partition (or the whole device) through the real engine and prove with
//! byte-exact comparisons that nothing outside the selected scope changed.
//!
//! They are `#[ignore]`d (so the normal suite lists them but never runs them)
//! and additionally require the `loopdev_tests` feature at run time: they
//! attach real loop devices and need root. Manual run:
//!
//! ```text
//! cd native/zt_engine
//! sudo env "PATH=$PATH" cargo test --features loopdev_tests \
//!     --test loopdev_isolation_test -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use zt_engine::execute::{
    compute_partition_table_fingerprint, software_overwrite, software_overwrite_partition,
    FsContext, OverwritePattern, PartitionTargetParams,
};

const SECTOR: u64 = 512;
const IMAGE_SECTORS: u64 = 51_200; // 25 MiB
const PART_START: [u64; 3] = [2_048, 18_432, 34_816];
const PART_SECTORS: u64 = 16_384; // 8 MiB per partition
const PATTERNS: [u8; 3] = [0x11, 0x22, 0x33];
const SERIAL: &str = "LOOP-ISOLATION-TEST";

/// Owns a loop device + backing image and always detaches/removes them.
struct LoopDisk {
    loop_path: String,
    image: PathBuf,
    _tmp: tempfile::TempDir,
}

impl LoopDisk {
    fn create() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let image = tmp.path().join("zt-loop.img");
        build_image(&image);

        let output = Command::new("losetup")
            .args(["--find", "--show", "--partscan"])
            .arg(&image)
            .output()
            .expect("losetup must be installed (util-linux)");
        assert!(
            output.status.success(),
            "losetup failed (root required): {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let loop_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(
            loop_path.starts_with("/dev/loop"),
            "unexpected losetup output: {:?}",
            loop_path
        );

        // Wait for udev/the kernel to publish the partition nodes.
        for n in 1..=3 {
            let part = format!("{}p{}", loop_path, n);
            for _ in 0..100 {
                if Path::new(&part).exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert!(
                Path::new(&part).exists(),
                "kernel did not create partition node {} — is CONFIG_BLK_DEV_LOOP_PARTSCAN available?",
                part
            );
        }

        LoopDisk { loop_path, image, _tmp: tmp }
    }

    fn part(&self, n: u32) -> String {
        format!("{}p{}", self.loop_path, n)
    }

    fn disk(&self) -> &str {
        &self.loop_path
    }
}

impl Drop for LoopDisk {
    fn drop(&mut self) {
        let _ = Command::new("losetup")
            .args(["--detach", &self.loop_path])
            .output();
        let _ = fs::remove_file(&self.image);
    }
}

/// Minimal MBR with three primary Linux partitions — the kernel partitionscan
/// (`losetup -P`) parses it, so the engine sees real sysfs partition facts.
fn build_image(image: &Path) {
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(image)
        .expect("create image");
    f.set_len(IMAGE_SECTORS * SECTOR).expect("size image");

    let mut mbr = vec![0u8; 512];
    for (i, (start, pattern)) in PART_START.iter().zip(PATTERNS.iter()).enumerate() {
        let entry = 446 + i * 16;
        mbr[entry] = 0x00; // not bootable
        mbr[entry + 1] = 0x00; // CHS start (LBA addressing is authoritative)
        mbr[entry + 2] = 0x02;
        mbr[entry + 3] = 0x00;
        mbr[entry + 4] = 0x83; // Linux filesystem
        mbr[entry + 5] = 0xFE; // CHS end
        mbr[entry + 6] = 0xFF;
        mbr[entry + 7] = 0xFF;
        mbr[entry + 8..entry + 12].copy_from_slice(&(*start as u32).to_le_bytes());
        mbr[entry + 12..entry + 16]
            .copy_from_slice(&(PART_SECTORS as u32).to_le_bytes());

        let fill = vec![*pattern; (PART_SECTORS * SECTOR) as usize];
        f.seek(SeekFrom::Start(start * SECTOR)).unwrap();
        f.write_all(&fill).unwrap();
    }
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(&mbr).unwrap();
    f.sync_all().unwrap();
}

fn read_bytes(path: &str) -> Vec<u8> {
    let mut f = File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path, e));
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    buf
}

fn sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Partition table + boot code + the gaps between partitions: everything
/// before partition 1 and outside the three partition ranges.
fn table_region(disk: &str) -> Vec<u8> {
    let mut f = File::open(disk).unwrap();
    let mut buf = vec![0u8; (PART_START[0] * SECTOR) as usize];
    f.read_exact(&mut buf).unwrap();
    buf
}

/// Assert that `sectors` starting at `start_sector` in `image_bytes` are zero.
fn assert_zero_range(image_bytes: &[u8], start_sector: u64, sectors: u64, what: &str) {
    let start = (start_sector * SECTOR) as usize;
    let end = start + (sectors * SECTOR) as usize;
    assert!(
        end <= image_bytes.len(),
        "{} range is outside the image",
        what
    );
    assert!(
        image_bytes[start..end].iter().all(|b| *b == 0),
        "{} was not fully overwritten",
        what
    );
}

/// These tests are `#[ignore]`d and must not run in a normal suite. Running
/// them with `--ignored` also requires the `loopdev_tests` feature.
#[allow(clippy::assertions_on_constants)]
fn require_loopdev_feature() {
    assert!(
        cfg!(feature = "loopdev_tests"),
        "enable the `loopdev_tests` feature to run the loop-image isolation tests \
         (sudo env \"PATH=$PATH\" cargo test --features loopdev_tests \
         --test loopdev_isolation_test -- --ignored --nocapture)"
    );
}

/// Wipe partition 3 through the engine; partitions 1 and 2 and the table
/// must stay byte-identical.
#[tokio::test]
#[ignore = "requires root + loop devices; run manually (see file header)"]
async fn partition_wipe_leaves_siblings_and_table_untouched() {
    require_loopdev_feature();
    let disk = LoopDisk::create();

    let p1_before = read_bytes(&disk.part(1));
    let p2_before = read_bytes(&disk.part(2));
    let table_before = table_region(disk.disk());
    assert_eq!(sha256(&p1_before).len(), 64);

    let part3 = disk.part(3);
    let fingerprint = compute_partition_table_fingerprint(disk.disk(), &FsContext::default())
        .expect("partition table fingerprint from sysfs");
    let params = PartitionTargetParams {
        expected_partition_num: 3,
        expected_start_sector: PART_START[2],
        expected_size_sectors: PART_SECTORS,
        expected_partuuid: None,
        expected_table_fingerprint: fingerprint,
    };

    let (tx, _rx) = mpsc::channel(64);
    let report = software_overwrite_partition(
        &part3,
        1,
        OverwritePattern::Zeros,
        SERIAL,
        SERIAL,
        &params,
        false, // real run
        tx,
    )
    .await
    .expect("engine partition wipe must succeed");
    assert!(report.success, "engine reported failure: {:?}", report);

    // Partition 3 fully overwritten.
    let p3_after = read_bytes(&part3);
    assert!(
        p3_after.iter().all(|b| *b == 0),
        "partition 3 was not fully zeroed"
    );
    assert_eq!(p3_after.len() as u64, PART_SECTORS * SECTOR);

    // Siblings and the table are byte-identical.
    let p1_after = read_bytes(&disk.part(1));
    let p2_after = read_bytes(&disk.part(2));
    assert_eq!(
        sha256(&p1_before),
        sha256(&p1_after),
        "partition 1 changed during a partition-3 wipe"
    );
    assert_eq!(
        sha256(&p2_before),
        sha256(&p2_after),
        "partition 2 changed during a partition-3 wipe"
    );
    assert_eq!(
        table_before,
        table_region(disk.disk()),
        "partition table changed during a partition-3 wipe"
    );
    assert!(p1_after.iter().all(|b| *b == PATTERNS[0]));
    assert!(p2_after.iter().all(|b| *b == PATTERNS[1]));

    println!(
        "P3 partition isolation: table={} p1={} p2={} p3=zeroed",
        sha256(&table_before),
        sha256(&p1_after),
        sha256(&p2_after)
    );
}

/// Whole-device wipe: partition table and all three partitions are zeroed.
#[tokio::test]
#[ignore = "requires root + loop devices; run manually (see file header)"]
async fn whole_device_wipe_overwrites_table_and_all_partitions() {
    require_loopdev_feature();
    let disk = LoopDisk::create();

    // Sanity: the fixtures are not zero before the wipe.
    assert!(!table_region(disk.disk()).iter().all(|b| *b == 0));
    assert!(read_bytes(&disk.part(1)).iter().all(|b| *b == PATTERNS[0]));

    let (tx, _rx) = mpsc::channel(64);
    let report = software_overwrite(
        disk.disk(),
        1,
        OverwritePattern::Zeros,
        SERIAL,
        SERIAL,
        false, // real run
        tx,
    )
    .await
    .expect("engine whole-device wipe must succeed");
    assert!(report.success, "engine reported failure: {:?}", report);
    assert_eq!(
        report.bytes_written,
        IMAGE_SECTORS * SECTOR,
        "whole-device wipe must cover the entire device"
    );

    // The wipe zeroes the MBR, so the kernel/udev may remove the
    // /dev/loopNpX partition nodes. Verify against the backing image file
    // instead of reopening partition devices.
    let whole = fs::read(&disk.image).expect("read backing image");
    assert_eq!(
        whole.len() as u64,
        IMAGE_SECTORS * SECTOR,
        "backing image size changed during the wipe"
    );

    // Partition table + boot region.
    assert_zero_range(
        &whole,
        0,
        PART_START[0],
        "partition table / pre-partition region",
    );

    // All former partition ranges.
    for (i, start) in PART_START.iter().enumerate() {
        assert_zero_range(
            &whole,
            *start,
            PART_SECTORS,
            &format!("former partition {}", i + 1),
        );
    }

    // The raw image itself is zero from start to end (no gap survived).
    assert!(
        whole.iter().all(|b| *b == 0),
        "whole-device wipe left non-zero bytes"
    );
    let zero_image = vec![0u8; whole.len()];
    assert_eq!(
        sha256(&whole),
        sha256(&zero_image),
        "backing image hash does not match an all-zero image"
    );

    println!(
        "P3 whole-device: {} bytes zeroed across table + 3 partitions (sha256={})",
        whole.len(),
        sha256(&whole)
    );
}
