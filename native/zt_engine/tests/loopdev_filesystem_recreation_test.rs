//! Phase F: loop-image partition format test (manual, root-only).
//!
//! Wipe partition 3, verify it, recreate an ext4 filesystem, then prove the
//! table and partitions 1/2 are byte-identical and partition 3 mounts
//! read-only and is empty (apart from the filesystem's own system metadata).
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
const FORMAT_FS: &str = "ext4";

const SUDO_COMMAND: &str = "cd native/zt_engine && sudo env \"PATH=$PATH\" cargo test \
    --features loopdev_tests --test loopdev_filesystem_recreation_test -- --ignored --nocapture";

/// Entries a fresh filesystem is allowed to expose, per filesystem type.
///
/// Only the filesystem's own system metadata is tolerated: anything else means
/// the "fresh" filesystem was not empty and fails the test. vfat/exfat must be
/// completely empty.
fn allowed_fresh_entries(fs_type: &str) -> &'static [&'static str] {
    match fs_type {
        // ext4 always creates this root directory; its presence is expected.
        "ext4" => &["lost+found"],
        // mkntfs/ntfs-3g may expose the NTFS system files depending on mount
        // options. These are metadata, never user data.
        "ntfs" => &[
            "$AttrDef",
            "$BadClus",
            "$Bitmap",
            "$Boot",
            "$Extend",
            "$LogFile",
            "$MFT",
            "$MFTMirr",
            "$RECYCLE.BIN",
            "$Secure",
            "$UpCase",
            "$Volume",
            "System Volume Information",
        ],
        // vfat/exfat: strict empty check.
        _ => &[],
    }
}

/// Splits a fresh mount's directory names into `(ignored system entries,
/// unexpected entries)`. Only [allowed_fresh_entries] may be ignored.
fn classify_fresh_entries(fs_type: &str, names: &[String]) -> (Vec<String>, Vec<String>) {
    let allowed = allowed_fresh_entries(fs_type);
    let mut ignored = Vec::new();
    let mut unexpected = Vec::new();
    for name in names {
        if allowed.iter().any(|allowed_name| allowed_name == name) {
            ignored.push(name.clone());
        } else {
            unexpected.push(name.clone());
        }
    }
    (ignored, unexpected)
}

struct LoopDisk {
    loop_path: String,
    image: PathBuf,
    /// Mountpoint owned by this guard (if the test mounted a partition).
    mount_dir: Option<tempfile::TempDir>,
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

        // Construct the detach guard immediately, before any assertion can
        // panic and leak the loop device.
        let guard = Self {
            loop_path,
            image,
            mount_dir: None,
            _tmp: tmp,
        };
        assert!(
            guard.loop_path.starts_with("/dev/loop"),
            "unexpected losetup output: {:?}",
            guard.loop_path
        );

        // Never write through a loop device backed by anything but our image.
        guard.assert_backed_by_own_image();
        guard.wait_for_partitions(3);
        guard
    }

    fn assert_backed_by_own_image(&self) {
        let name = self.loop_path.rsplit('/').next().unwrap();
        let backing = fs::read_to_string(format!("/sys/block/{name}/loop/backing_file"))
            .expect("read loop backing_file from sysfs");
        let backing =
            fs::canonicalize(backing.trim()).expect("canonicalize sysfs loop backing_file");
        let expected = fs::canonicalize(&self.image).expect("canonicalize test loop image");
        assert_eq!(
            backing, expected,
            "allocated loop device {} is not backed by the test image",
            self.loop_path
        );
    }

    fn wait_for_partitions(&self, count: u32) {
        for n in 1..=count {
            let part = self.part(n);
            for _ in 0..100 {
                if Path::new(&part).exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert!(Path::new(&part).exists(), "missing partition node {}", part);
        }
    }

    fn part(&self, n: u32) -> String {
        format!("{}p{}", self.loop_path, n)
    }

    fn disk(&self) -> &str {
        &self.loop_path
    }

    /// Mounts [part] read-only and remembers the mountpoint so Drop can
    /// unmount it even when a later assertion panics.
    fn mount_read_only(&mut self, part: &str) -> PathBuf {
        assert!(self.mount_dir.is_none(), "loop disk is already mounted");
        let dir = tempfile::tempdir().expect("mount dir");
        let mount_path = dir.path().to_path_buf();
        let output = Command::new("mount")
            .args(["-o", "ro", part, mount_path.to_str().unwrap()])
            .output()
            .expect("mount");
        assert!(
            output.status.success(),
            "read-only mount failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.mount_dir = Some(dir);
        mount_path
    }

    fn unmount(&mut self) {
        if let Some(dir) = self.mount_dir.take() {
            let output = Command::new("umount").arg(dir.path()).output();
            let ok = output.map(|o| o.status.success()).unwrap_or(false);
            if !ok {
                // Lazy unmount still releases the loop device for detach.
                let _ = Command::new("umount").args(["-l"]).arg(dir.path()).output();
            }
        }
    }
}

impl Drop for LoopDisk {
    fn drop(&mut self) {
        // Unmount before detaching: losetup cannot detach a busy device.
        self.unmount();
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

fn mount_entry_names(mount_path: &Path) -> Vec<String> {
    fs::read_dir(mount_path)
        .expect("read mounted fs")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

#[allow(clippy::assertions_on_constants)]
fn require_loopdev_feature() {
    assert!(
        cfg!(feature = "loopdev_tests"),
        "enable the `loopdev_tests` feature; manual command:\n{}",
        SUDO_COMMAND
    );
}

/// Non-root unit test for the emptiness rules (runs in the normal suite).
#[test]
fn fresh_filesystem_emptiness_rules_match_each_filesystem() {
    let names = |values: &[&str]| -> Vec<String> { values.iter().map(|v| v.to_string()).collect() };

    // ext4: lost+found is the only tolerated entry.
    let (ignored, unexpected) = classify_fresh_entries("ext4", &names(&["lost+found"]));
    assert_eq!(ignored, names(&["lost+found"]));
    assert!(unexpected.is_empty());
    let (ignored, unexpected) =
        classify_fresh_entries("ext4", &names(&["lost+found", "README.txt"]));
    assert_eq!(ignored, names(&["lost+found"]));
    assert_eq!(
        unexpected,
        names(&["README.txt"]),
        "every other entry fails"
    );
    let (_, unexpected) = classify_fresh_entries("ext4", &names(&["lost+found.bak"]));
    assert_eq!(unexpected, names(&["lost+found.bak"]));

    // vfat/exfat: strict empty, even for ext4-style names.
    for fs_type in ["vfat", "exfat", "fat32"] {
        let (ignored, unexpected) = classify_fresh_entries(fs_type, &names(&["lost+found"]));
        assert!(ignored.is_empty(), "{fs_type} must ignore nothing");
        assert_eq!(unexpected, names(&["lost+found"]), "{fs_type} stays strict");
        let (ignored, unexpected) = classify_fresh_entries(fs_type, &[]);
        assert!(ignored.is_empty() && unexpected.is_empty());
    }

    // ntfs: only its own system metadata is tolerated (and reported).
    let (ignored, unexpected) =
        classify_fresh_entries("ntfs", &names(&["$Extend", "System Volume Information"]));
    assert_eq!(ignored, names(&["$Extend", "System Volume Information"]));
    assert!(unexpected.is_empty());
    let (ignored, unexpected) = classify_fresh_entries("ntfs", &names(&["$Extend", "notes.txt"]));
    assert_eq!(ignored, names(&["$Extend"]));
    assert_eq!(unexpected, names(&["notes.txt"]));

    // Unknown filesystems get the strict treatment too.
    let (_, unexpected) = classify_fresh_entries("btrfs", &names(&["lost+found"]));
    assert_eq!(unexpected, names(&["lost+found"]));
}

#[tokio::test]
#[ignore = "requires root + loop devices; run manually (see file header)"]
async fn partition_3_wipe_then_format_preserves_table_and_siblings() {
    require_loopdev_feature();
    println!(
        "Manual command (not executed by the suite): {}",
        SUDO_COMMAND
    );
    let mut disk = LoopDisk::create();

    let p1_before = read_bytes(&disk.part(1));
    let p2_before = read_bytes(&disk.part(2));
    let table_before = table_region(disk.disk());
    let p1_before_hash = sha256(&p1_before);
    let p2_before_hash = sha256(&p2_before);
    let table_before_hash = sha256(&table_before);
    println!(
        "Isolation BEFORE: table={} p1={} p2={}",
        table_before_hash, p1_before_hash, p2_before_hash
    );

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
    let format = recreate_filesystem(&target, FORMAT_FS, "ZT-TEST").expect("format partition 3");
    assert!(format.success);
    assert!(format.sanitization_verified_before_format);

    // Table and siblings byte-identical (before vs after).
    let p1_after = read_bytes(&disk.part(1));
    let p2_after = read_bytes(&disk.part(2));
    let table_after = table_region(disk.disk());
    let p1_after_hash = sha256(&p1_after);
    let p2_after_hash = sha256(&p2_after);
    let table_after_hash = sha256(&table_after);
    println!(
        "Isolation AFTER:  table={} p1={} p2={}",
        table_after_hash, p1_after_hash, p2_after_hash
    );
    assert_eq!(table_before, table_after, "table changed");
    assert_eq!(p1_before_hash, p1_after_hash, "p1 changed");
    assert_eq!(p2_before_hash, p2_after_hash, "p2 changed");

    // Mount read-only and prove the new filesystem contains no user data.
    let mount_path = disk.mount_read_only(&part3);
    let names = mount_entry_names(&mount_path);
    let (ignored, unexpected) = classify_fresh_entries(FORMAT_FS, &names);
    for name in &ignored {
        println!(
            "Fresh {} filesystem exposes known system entry '{}' (ignored)",
            FORMAT_FS, name
        );
    }
    assert!(
        unexpected.is_empty(),
        "fresh {FORMAT_FS} filesystem unexpectedly contains {unexpected:?} \
         (ignored system entries: {ignored:?})"
    );
    disk.unmount();

    println!(
        "Phase F format isolation: table={} p1={} p2={} p3={}",
        table_after_hash,
        p1_after_hash,
        p2_after_hash,
        sha256(&read_bytes(&disk.part(3)))
    );
}
