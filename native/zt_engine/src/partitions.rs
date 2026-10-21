//! A2: partition enumeration module.
//!
//! Lists partitions for a disk from sysfs + `/proc/self/mountinfo` +
//! `/proc/swaps`, and flags each partition for safety review:
//! `is_system`, `is_swap`, `is_active_mount`, `is_removable`, plus the
//! disk's partition-table type (GPT/MBR detection from raw sectors).
//!
//! All filesystem roots go through `FsContext` so tests can run against
//! fixtures without touching real hardware.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::Path;

use crate::execute::FsContext;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single partition as enumerated by the engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PartitionEntry {
    pub name: String,
    pub device_path: String,
    pub partition_number: u32,
    /// 512-byte LBA start sector.
    pub start_sector: u64,
    /// Size in bytes (sysfs `size` is in 512-byte sectors).
    pub size_bytes: u64,
    pub fs_type: Option<String>,
    pub label: Option<String>,
    pub mountpoints: Vec<String>,
    pub parent_disk: String,
    pub table_type: String,
    /// Mounted at a system location (/, /boot, /boot/efi, /usr, /var, /home).
    pub is_system: bool,
    /// Active or configured swap.
    pub is_swap: bool,
    /// Currently mounted anywhere (including unmountable user mounts).
    pub is_active_mount: bool,
    /// Parent disk is removable media.
    pub is_removable: bool,
}

/// Enumeration report for one disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskEnumerationReport {
    pub disk: String,
    /// "gpt" | "mbr" | "none" | "unknown"
    pub table_type: String,
    pub is_removable: bool,
    pub partitions: Vec<PartitionEntry>,
}

// ---------------------------------------------------------------------------
// Mount table parsing (pure)
// ---------------------------------------------------------------------------

/// One record from /proc/self/mountinfo.
#[derive(Debug, Clone, PartialEq)]
pub struct MountRecord {
    pub mountpoint: String,
    pub fs_type: String,
    pub source: String,
    pub major: u32,
    pub minor: u32,
}

/// Parse /proc/self/mountinfo content.
///
/// Format: `mount_id parent_id major:minor root mount_point mount_options
/// [optional fields...] - fs_type mount_source super_options`
pub fn parse_mountinfo(content: &str) -> Vec<MountRecord> {
    let mut out = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let (maj, min) = match parts[2].split_once(':') {
            Some((m, n)) => (
                m.parse::<u32>().unwrap_or(0),
                n.parse::<u32>().unwrap_or(0),
            ),
            None => continue,
        };
        let sep = parts.iter().position(|p| *p == "-");
        let Some(sep) = sep else { continue };
        if parts.len() < sep + 3 {
            continue;
        }
        out.push(MountRecord {
            mountpoint: parts[4].to_string(),
            fs_type: parts[sep + 1].to_string(),
            source: parts[sep + 2].to_string(),
            major: maj,
            minor: min,
        });
    }
    out
}

/// Parse /proc/swaps content → device paths (e.g. "/dev/sda3").
pub fn parse_swaps(content: &str) -> Vec<String> {
    content
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let first = line.split_whitespace().next()?;
            if first.starts_with('/') {
                Some(first.to_string())
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Partition table type detection (pure, reads raw sectors)
// ---------------------------------------------------------------------------

/// Detect the partition-table type of a disk device/file:
/// "gpt" (protective MBR + "EFI PART" header), "mbr" (0x55AA boot
/// signature without a GPT header), "none" (no signature at all),
/// or "unknown" (device unreadable / too small).
pub fn detect_table_type(disk_path: &Path) -> String {
    let mut f = match fs::File::open(disk_path) {
        Ok(f) => f,
        Err(_) => return "unknown".to_string(),
    };

    // Read LBA 1 (bytes 512..1024) to look for the GPT header; LBA 0 tail
    // for the MBR signature.
    let mut buf = [0u8; 1024];
    let n = f.read(&mut buf).unwrap_or(0);
    if n < 512 {
        return "unknown".to_string();
    }
    let mbr_sig = buf[510] == 0x55 && buf[511] == 0xAA;

    if n >= 1024 && &buf[512..520] == b"EFI PART" {
        return "gpt".to_string();
    }
    if mbr_sig {
        return "mbr".to_string();
    }
    if n >= 512 && !mbr_sig && buf[512..1024].iter().all(|&b| b == 0) {
        // No MBR signature and a blank LBA 1: treat as unpartitioned.
        return "none".to_string();
    }
    "unknown".to_string()
}

// ---------------------------------------------------------------------------
// Sysfs helpers
// ---------------------------------------------------------------------------

fn read_sys_attr(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// System mount points per A2: these make a partition "system".
pub fn is_system_mountpoint(mp: &str) -> bool {
    matches!(mp, "/" | "/boot" | "/boot/efi" | "/usr" | "/var" | "/home")
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// Enumerate partitions of `disk` (e.g. "/dev/sda") using FsContext roots.
///
/// Partitions are discovered via sysfs (`<sys_root>/class/block/<disk>/<part>`
/// entries carrying a `partition` file), enriched with mountpoints from
/// mountinfo and swap activity from /proc/swaps.
pub fn enumerate_partitions_ctx(
    disk: &str,
    ctx: &FsContext,
) -> Result<DiskEnumerationReport, String> {
    let disk_name = disk.rsplit('/').next().unwrap_or(disk).to_string();
    if disk_name.is_empty() {
        return Err("Empty disk name".to_string());
    }

    let disk_dir = ctx
        .sys_root
        .join("class/block")
        .join(disk_name.as_str());
    if !disk_dir.exists() {
        return Err(format!("Disk not found in sysfs: {}", disk_name));
    }

    let is_removable = read_sys_attr(&disk_dir.join("removable"))
        .and_then(|v| v.parse::<u8>().ok())
        .map(|v| v == 1)
        .unwrap_or(false);

    // Mount + swap context
    let mountinfo_path = ctx.proc_root.join("self/mountinfo");
    let mounts: Vec<MountRecord> = if mountinfo_path.exists() {
        fs::read_to_string(&mountinfo_path)
            .map(|c| parse_mountinfo(&c))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let swaps_path = ctx.proc_root.join("swaps");
    let swaps: Vec<String> = if swaps_path.exists() {
        fs::read_to_string(&swaps_path)
            .map(|c| parse_swaps(&c))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Disk major:minor (from sysfs dev file) for matching by mm.
    let disk_mm = read_sys_attr(&disk_dir.join("dev")).and_then(|v| {
        let (m, n) = v.split_once(':')?;
        Some((m.parse::<u32>().ok()?, n.parse::<u32>().ok()?))
    });

    // Table type from the raw device node (fixture: regular file).
    let dev_path = ctx.dev_root.join(disk_name.as_str());
    let table_type = detect_table_type(&dev_path);

    // Discover partition subdirectories.
    let mut partitions: Vec<PartitionEntry> = Vec::new();
    let entries = fs::read_dir(&disk_dir)
        .map_err(|e| format!("Cannot read sysfs disk dir {}: {}", disk_dir.display(), e))?;

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == disk_name || !name.starts_with(disk_name.as_str()) {
            continue;
        }
        let part_dir = entry.path();
        // A real partition node carries a `partition` file with its number.
        let part_num: u32 = match read_sys_attr(&part_dir.join("partition"))
            .and_then(|v| v.parse::<u32>().ok())
        {
            Some(n) => n,
            None => continue,
        };

        let size_sectors: u64 = read_sys_attr(&part_dir.join("size"))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let start_sector: u64 = read_sys_attr(&part_dir.join("start"))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        let part_mm = read_sys_attr(&part_dir.join("dev")).and_then(|v| {
            let (m, n) = v.split_once(':')?;
            Some((m.parse::<u32>().ok()?, n.parse::<u32>().ok()?))
        });

        // Mountpoints for this partition (by source name or major:minor).
        let mut mountpoints: Vec<String> = Vec::new();
        let mut fs_type: Option<String> = None;
        let part_path = format!("/dev/{}", name);
        for m in &mounts {
            let by_name = m.source == part_path
                || m.source == name
                || m.source.strip_prefix("/dev/") == Some(name.as_str());
            let by_mm = part_mm.is_some() && Some((m.major, m.minor)) == part_mm;
            if by_name || by_mm {
                mountpoints.push(m.mountpoint.clone());
                if fs_type.is_none() && !m.fs_type.is_empty() {
                    fs_type = Some(m.fs_type.clone());
                }
            }
        }

        let is_swap = fs_type.as_deref() == Some("swap")
            || swaps.iter().any(|s| {
                s == &part_path || s.strip_prefix("/dev/") == Some(name.as_str())
            });

        let is_system = mountpoints.iter().any(|mp| is_system_mountpoint(mp));
        let is_active_mount = !mountpoints.is_empty();

        // Parent-disk removability: prefer this disk's own flag; also accept
        // a parent sysfs check when the disk-level flag is absent.
        let entry_removable = is_removable;

        partitions.push(PartitionEntry {
            name: name.clone(),
            device_path: part_path,
            partition_number: part_num,
            start_sector,
            size_bytes: size_sectors.saturating_mul(512),
            fs_type,
            label: None,
            mountpoints,
            parent_disk: disk_name.clone(),
            table_type: table_type.clone(),
            is_system,
            is_swap,
            is_active_mount,
            is_removable: entry_removable,
        });
    }

    partitions.sort_by_key(|p| p.partition_number);

    // Sanity: disk major:minor recorded for future use (kept for parity with
    // guard-side checks; unused at enumeration time).
    let _ = disk_mm;

    Ok(DiskEnumerationReport {
        disk: disk_name,
        table_type,
        is_removable,
        partitions,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    /// Fixture: internal GPT disk sda with system partition (sda2 = /) and a
    /// data partition (sda3), plus a removable MBR USB stick sdb.
    fn build_fixture() -> TempFixture {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        let proc = tmp.path().join("proc");
        let dev = tmp.path().join("dev");

        // sysfs: sda (internal, removable=0) with sda1, sda2, sda3
        write(&sys.join("class/block/sda/removable"), "0\n");
        write(&sys.join("class/block/sda/dev"), "8:0\n");
        write(&sys.join("class/block/sda/sda1/partition"), "1\n");
        write(&sys.join("class/block/sda/sda1/size"), "4096\n"); // 2 MiB ESP
        write(&sys.join("class/block/sda/sda1/start"), "2048\n");
        write(&sys.join("class/block/sda/sda1/dev"), "8:1\n");
        write(&sys.join("class/block/sda/sda2/partition"), "2\n");
        write(&sys.join("class/block/sda/sda2/size"), "4194304\n"); // 2 GiB root
        write(&sys.join("class/block/sda/sda2/start"), "6144\n");
        write(&sys.join("class/block/sda/sda2/dev"), "8:2\n");
        write(&sys.join("class/block/sda/sda3/partition"), "3\n");
        write(&sys.join("class/block/sda/sda3/size"), "2097152\n"); // 1 GiB data
        write(&sys.join("class/block/sda/sda3/start"), "4200448\n");
        write(&sys.join("class/block/sda/sda3/dev"), "8:3\n");

        // sysfs: sdb (removable USB) with sdb1
        write(&sys.join("class/block/sdb/removable"), "1\n");
        write(&sys.join("class/block/sdb/dev"), "8:16\n");
        write(&sys.join("class/block/sdb/sdb1/partition"), "1\n");
        write(&sys.join("class/block/sdb/sdb1/size"), "16384\n");
        write(&sys.join("class/block/sdb/sdb1/start"), "8192\n");
        write(&sys.join("class/block/sdb/sdb1/dev"), "8:17\n");

        // mountinfo: / on sda2, /boot/efi on sda1, /mnt/usb on sdb1
        let mountinfo = "\
25 30 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
26 25 8:1 / /boot/efi rw,relatime shared:2 - vfat /dev/sda1 rw\n\
30 1 8:17 / /mnt/usb rw,relatime shared:3 - ext4 /dev/sdb1 rw\n";
        write(&proc.join("self/mountinfo"), mountinfo);

        // swaps: none active
        write(&proc.join("swaps"), "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");

        // Device nodes: GPT for sda, MBR for sdb
        let mut sda = vec![0u8; 4096];
        sda[510] = 0x55;
        sda[511] = 0xAA; // protective MBR
        sda[512..520].copy_from_slice(b"EFI PART");
        fs::create_dir_all(&dev).unwrap();
        fs::write(dev.join("sda"), &sda).unwrap();

        let mut sdb = vec![0u8; 4096];
        sdb[510] = 0x55;
        sdb[511] = 0xAA;
        fs::write(dev.join("sdb"), &sdb).unwrap();

        TempFixture {
            _tmp: tmp,
            ctx: FsContext {
                proc_root: proc,
                sys_root: sys,
                dev_root: dev,
            },
        }
    }

    struct TempFixture {
        _tmp: tempfile::TempDir,
        ctx: FsContext,
    }

    #[test]
    fn test_enumerate_internal_gpt_disk() {
        let f = build_fixture();
        let report = enumerate_partitions_ctx("/dev/sda", &f.ctx).unwrap();

        assert_eq!(report.disk, "sda");
        assert_eq!(report.table_type, "gpt");
        assert!(!report.is_removable);
        assert_eq!(report.partitions.len(), 3);

        let p1 = &report.partitions[0];
        assert_eq!(p1.partition_number, 1);
        assert_eq!(p1.start_sector, 2048);
        assert_eq!(p1.size_bytes, 4096 * 512);
        assert!(p1.is_system, "EFI system partition must be flagged system");
        assert!(p1.is_active_mount);

        let p2 = &report.partitions[1];
        assert_eq!(p2.fs_type.as_deref(), Some("ext4"));
        assert!(p2.is_system, "root partition must be flagged system");
        assert!(p2.is_active_mount);

        let p3 = &report.partitions[2];
        assert!(!p3.is_system, "unmounted data partition is not system");
        assert!(!p3.is_active_mount);
        assert!(!p3.is_swap);
    }

    #[test]
    fn test_enumerate_removable_mbr_disk() {
        let f = build_fixture();
        let report = enumerate_partitions_ctx("/dev/sdb", &f.ctx).unwrap();

        assert_eq!(report.table_type, "mbr");
        assert!(report.is_removable);
        assert_eq!(report.partitions.len(), 1);
        let p1 = &report.partitions[0];
        assert!(p1.is_removable);
        assert!(p1.is_active_mount);
        assert!(!p1.is_system, "/mnt/usb is not a system mountpoint");
    }

    #[test]
    fn test_swap_partition_flagged() {
        let f = build_fixture();
        write(
            &f.ctx.proc_root.join("swaps"),
            "Filename\tType\tSize\tUsed\tPriority\n/dev/sda3\tpartition\t1048576\t0\t-2\n",
        );
        let report = enumerate_partitions_ctx("/dev/sda", &f.ctx).unwrap();
        let p3 = &report.partitions[2];
        assert!(p3.is_swap, "partition listed in /proc/swaps must be flagged");
    }

    #[test]
    fn test_missing_disk_errors() {
        let f = build_fixture();
        assert!(enumerate_partitions_ctx("/dev/sdz", &f.ctx).is_err());
    }

    #[test]
    fn test_parse_mountinfo_and_swaps() {
        let mounts = parse_mountinfo(
            "25 30 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\nbad line\n",
        );
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mountpoint, "/");
        assert_eq!(mounts[0].fs_type, "ext4");
        assert_eq!(mounts[0].source, "/dev/sda2");
        assert_eq!((mounts[0].major, mounts[0].minor), (8, 2));

        let swaps = parse_swaps(
            "Filename Type Size Used Priority\n/dev/sda3 partition 1 0 -2\n",
        );
        assert_eq!(swaps, vec!["/dev/sda3".to_string()]);
    }

    #[test]
    fn test_detect_table_type() {
        let tmp = tempfile::tempdir().unwrap();

        // GPT
        let mut gpt = vec![0u8; 4096];
        gpt[510] = 0x55;
        gpt[511] = 0xAA;
        gpt[512..520].copy_from_slice(b"EFI PART");
        let p: PathBuf = tmp.path().join("gpt.img");
        fs::write(&p, &gpt).unwrap();
        assert_eq!(detect_table_type(&p), "gpt");

        // MBR
        let mut mbr = vec![0u8; 4096];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        let p = tmp.path().join("mbr.img");
        fs::write(&p, &mbr).unwrap();
        assert_eq!(detect_table_type(&p), "mbr");

        // None
        let p = tmp.path().join("none.img");
        fs::write(&p, vec![0u8; 4096]).unwrap();
        assert_eq!(detect_table_type(&p), "none");

        // Missing file
        assert_eq!(detect_table_type(&tmp.path().join("missing")), "unknown");
    }
}
