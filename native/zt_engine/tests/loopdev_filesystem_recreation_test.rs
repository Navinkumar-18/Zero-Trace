//! Phase F: loop-image partition format test (manual, root-only).
//!
//! Wipe partition 3, verify it, recreate an ext4 filesystem, then prove the
//! table and partitions 1/2 are byte-identical and partition 3 mounts
//! read-only and is empty.
//!
//! Manual command (never run by the normal suite):
//!
//! ```text
//! cd native/zt_engine
//! sudo env "PATH=$PATH" cargo test --features loopdev_tests \
//!     --test loopdev_filesystem_recreation_test -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use zt_engine::execute::{
    mark_wiped_and_verified, recreate_filesystem, software_overwrite_partition, FsContext,
    OverwritePattern, PartitionTargetParams,
};
use zt_engine::guard;
use zt_engine::verify::verify_device_scoped;

const SECTOR: u64 = 512;
const IMAGE_SECTORS: u64 = 51_200; // 25 MiB
const PART_START: [u64; 3] = [2_048, 18_432, 34_816];
const PART_SECTORS: u64 = 16_384; // 8 MiB per partition
const PATTERNS: [u8; 3] = [0x11, 0x22, 0x33];
const SERIAL: &str = "LOOP-FORMAT-TEST";

const SUDO_COMMAND: &str = "cd native/zt_engine && sudo env \"PATH=$PATH\" cargo test \
    --features loopdev_tests --test loopdev_filesystem_recreation_test -- --ignored --nocapture";

struct LoopDisk {
    loop_path: String,
    image: PathBuf,
    _tmp: tempfile::TempDir,
}

impl LoopDisk {
    fn create() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let image = tmp.path().join("zt-loop-format.img");
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
        for n in 1..=3 {
            let part = format!("{}p{}", loop_path, n);
            for _ in 0..100 {
                if Path::new(&part).exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert!(Path::new(&part).exists(), "missing partition node {}", part);
        }
        LoopDisk {
            loop_path,
            image,
            _tmp: tmp,
        }
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
        mbr[entry + 1] = 0x00;
        mbr[entry + 2] = 0x02;
        mbr[entry + 3] = 0x00;
        mbr[entry + 4] = 0x83;
        mbr[entry + 5] = 0xfe;
        mbr[entry + 6] = 0xff;
        mbr[entry + 7] = 0xff;
        mbr[entry + 8..entry + 12].copy_from_slice(&(*start as u32).to_le_bytes());
        mbr[entry + 12..entry + 16].copy_from_slice(&(PART_SECTORS as u32).to_le_bytes());
        let fill = vec![*pattern; (PART_SECTORS * SECTOR) as usize];
        f.seek(SeekFrom::Start(start * SECTOR)).unwrap();
        f.write_all(&fill).unwrap();
    }
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
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

fn table_region(disk: &str) -> Vec<u8> {
    let mut f = File::open(disk).unwrap();
    let mut buf = vec![0u8; (PART_START[0] * SECTOR) as usize];
    f.read_exact(&mut buf).unwrap();
    buf
}

#[allow(clippy::assertions_on_constants)]
fn require_loopdev_feature() {
    assert!(
        cfg!(feature = "loopdev_tests"),
        "enable the `loopdev_tests` feature; manual command:\n{}",
        SUDO_COMMAND
    );
}

#[tokio::test]
#[ignore = "requires root + loop devices; run manually (see file header)"]
async fn partition_3_wipe_then_format_preserves_table_and_siblings() {
    require_loopdev_feature();
    println!(
        "Manual command (not executed by the suite): {}",
        SUDO_COMMAND
    );
    let disk = LoopDisk::create();

    let p1_before = read_bytes(&disk.part(1));
    let p2_before = read_bytes(&disk.part(2));
    let table_before = table_region(disk.disk());

    let part3 = disk.part(3);
    let fingerprint =
        zt_engine::execute::compute_partition_table_fingerprint(disk.disk(), &FsContext::default())
            .expect("fingerprint from sysfs");
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
        false,
        tx,
    )
    .await
    .expect("partition wipe");
    assert!(report.success);

    // Verify before the format step (this is what licenses the format).
    let verification = verify_device_scoped(
        &part3,
        PART_SECTORS * SECTOR,
        IMAGE_SECTORS * SECTOR,
        SERIAL,
        "Partition Overwrite",
        Some(50),
        true,
        None,
    )
    .expect("verification");
    assert!(verification.pass, "partition 3 did not verify");

    let backend = zt_engine::backend::linux::LinuxBackend::system();
    let target = guard::validate_partition_target(&backend, &part3, &params, false, SERIAL)
        .expect("re-validate partition before format");
    mark_wiped_and_verified(&backend, &target).expect("mark verified wipe");
    let format = recreate_filesystem(&target, "ext4", "ZT-TEST").expect("format partition 3");
    assert!(format.success);
    assert!(format.sanitization_verified_before_format);

    // Table and siblings byte-identical.
    assert_eq!(table_before, table_region(disk.disk()), "table changed");
    assert_eq!(
        sha256(&p1_before),
        sha256(&read_bytes(&disk.part(1))),
        "p1 changed"
    );
    assert_eq!(
        sha256(&p2_before),
        sha256(&read_bytes(&disk.part(2))),
        "p2 changed"
    );

    // Mount read-only and prove the new filesystem is empty.
    let mount_dir = tempfile::tempdir().expect("mount dir");
    let mount = Command::new("mount")
        .args(["-o", "ro", &part3, mount_dir.path().to_str().unwrap()])
        .output()
        .expect("mount");
    assert!(
        mount.status.success(),
        "read-only mount failed: {}",
        String::from_utf8_lossy(&mount.stderr)
    );
    let entries: Vec<_> = fs::read_dir(mount_dir.path())
        .expect("read mounted fs")
        .filter_map(Result::ok)
        .collect();
    assert!(
        entries.is_empty(),
        "fresh filesystem unexpectedly contains {:?}",
        entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
    let _ = Command::new("umount").arg(mount_dir.path()).output();

    println!(
        "Phase F format isolation: table={} p1={} p2={} p3={}",
        sha256(&table_before),
        sha256(&read_bytes(&disk.part(1))),
        sha256(&read_bytes(&disk.part(2))),
        sha256(&read_bytes(&disk.part(3)))
    );
}
