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
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::backend::BlockBackend;
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
    /// B1: canonical lowercase GPT partition type GUID (GPT tables only).
    #[serde(default)]
    pub type_guid: Option<String>,
    /// B1: friendly partition type name — "EFI System", "Microsoft Reserved",
    /// "Microsoft Basic Data", "Windows Recovery", "Linux Filesystem", ...
    #[serde(default)]
    pub type_name: Option<String>,
    /// B1: stable role token for policy/UI — "efi_system" | "msr" |
    /// "windows_data" | "windows_recovery" | "linux" | "linux_swap" |
    /// "linux_lvm" | "linux_raid" | "linux_crypt" | "luks" | "bios_boot" |
    /// "extended" | "unknown".
    #[serde(default)]
    pub role: Option<String>,
    /// B1: filesystem signature probed read-only from the volume header when
    /// the volume is not mounted — "ntfs" | "exfat" | "fat32" | "ext4" | ...
    #[serde(default)]
    pub fs_probe: Option<String>,
    /// B2: "BitLocker" | "LUKS" when the volume header carries an encryption
    /// signature. Wiping works regardless; the UI must tell the user.
    #[serde(default)]
    pub encryption: Option<String>,
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
    let mut f = match crate::backend::linux::open_read_buffered(disk_path) {
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
// B1: partition-type classification (GPT type GUIDs, MBR type bytes)
// B2: volume-header probing (BitLocker / LUKS signatures)
//
// Everything here works on byte buffers and read-only sector reads. Nothing
// ever opens a device for writing.
// ---------------------------------------------------------------------------

/// One classified GPT type GUID: (canonical lowercase GUID, display name, role).
/// Registry values verified against the UEFI specification / GUID Partition
/// Table type registry (Wikipedia).
const GPT_TYPE_REGISTRY: &[(&str, &str, &str)] = &[
    ("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "EFI System", "efi_system"),
    ("e3c9e316-0b5c-4db8-817d-f92df00215ae", "Microsoft Reserved", "msr"),
    ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", "Microsoft Basic Data", "windows_data"),
    ("de94bba4-06d1-4d40-a16a-bfd50179d6ac", "Windows Recovery", "windows_recovery"),
    ("0fc63daf-8483-4772-8e79-3d69d8477de4", "Linux Filesystem", "linux"),
    ("0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "Linux Swap", "linux_swap"),
    ("e6d6d379-f507-44c2-a23c-238f2a3df928", "Linux LVM", "linux_lvm"),
    ("a19d880f-05fc-4d3b-a006-743f0f84911e", "Linux RAID", "linux_raid"),
    ("7ffec5c9-2d00-49b7-8941-3ea10a5586b7", "Linux dm-crypt", "linux_crypt"),
    ("ca7d7ccb-63ed-4c53-861c-1742536059cc", "LUKS", "luks"),
    ("21686148-6449-6e6f-744e-656564454649", "BIOS Boot", "bios_boot"),
];

/// Look up a canonical (lowercase, dashed) GPT type GUID → (name, role).
pub fn classify_gpt_guid(guid: &str) -> Option<(&'static str, &'static str)> {
    GPT_TYPE_REGISTRY
        .iter()
        .find(|(g, _, _)| *g == guid)
        .map(|(_, name, role)| (*name, *role))
}

/// MBR partition-type byte → (display name, role) for known types.
/// Returns None for empty/unknown bytes so callers can fall back.
pub fn classify_mbr_type(type_byte: u8) -> Option<(&'static str, &'static str)> {
    match type_byte {
        0x07 => Some(("Windows NTFS/exFAT", "windows_data")),
        0x0b | 0x0c => Some(("Windows FAT32", "windows_data")),
        0x06 | 0x0e => Some(("Windows FAT16", "windows_data")),
        0xef => Some(("EFI System", "efi_system")),
        0x27 => Some(("Windows Recovery", "windows_recovery")),
        0x83 => Some(("Linux", "linux")),
        0x82 => Some(("Linux Swap", "linux_swap")),
        0x8e => Some(("Linux LVM", "linux_lvm")),
        0xfd => Some(("Linux dm-crypt", "linux_crypt")),
        0x05 | 0x0f => Some(("Extended partition", "extended")),
        0xee => Some(("Protective GPT", "protective")),
        _ => None,
    }
}

/// B1: combine an MBR partition-type byte with the probed filesystem
/// signature into `(display name, role)`. The fs signature wins when it
/// contradicts the generic type byte — a 0x07 entry actually holding ext4 is
/// a Linux volume, not a Windows one.
pub fn classify_mbr_partition(type_byte: u8, fs_probe: Option<&str>) -> (String, String) {
    let fs = fs_probe.unwrap_or("");
    if fs.starts_with("ext") || fs == "btrfs" || fs == "xfs" || fs == "f2fs" {
        return (format!("Linux ({})", fs), "linux".to_string());
    }
    if fs == "swap" {
        return ("Linux Swap".to_string(), "linux_swap".to_string());
    }
    if fs == "ntfs" || fs == "exfat" || fs == "fat32" || fs == "fat16" || fs == "fat12" {
        let (name, role) = classify_mbr_type(type_byte)
            .filter(|(_, r)| *r == "windows_data" || *r == "windows_recovery" || *r == "efi_system")
            .unwrap_or(("Windows volume", "windows_data"));
        return (name.to_string(), role.to_string());
    }
    match classify_mbr_type(type_byte) {
        Some((n, r)) => (n.to_string(), r.to_string()),
        None if fs.is_empty() => ("Unknown".to_string(), "unknown".to_string()),
        None => (format!("{} volume", fs), "unknown".to_string()),
    }
}

/// A parsed GPT partition header (LBA 1). Offsets per UEFI spec chapter 5.
#[derive(Debug, Clone, PartialEq)]
pub struct GptHeader {
    pub entries_lba: u64,
    pub num_entries: u32,
    pub entry_size: u32,
}

/// Parse a 512-byte GPT header sector. Sanity-capped: entry sizes < 128 or
/// absurd entry counts are rejected so a corrupt header cannot allocate
/// unbounded memory.
pub fn parse_gpt_header(sector: &[u8]) -> Option<GptHeader> {
    if sector.len() < 92 || &sector[0..8] != b"EFI PART" {
        return None;
    }
    let entries_lba = u64::from_le_bytes(sector[72..80].try_into().ok()?);
    let num_entries = u32::from_le_bytes(sector[80..84].try_into().ok()?);
    let entry_size = u32::from_le_bytes(sector[84..88].try_into().ok()?);
    if entries_lba == 0
        || num_entries == 0
        || num_entries > 1024
        || !(128..=4096).contains(&entry_size)
    {
        return None;
    }
    Some(GptHeader {
        entries_lba,
        num_entries,
        entry_size,
    })
}

/// Format a 16-byte GUID stored in Microsoft mixed-endian layout
/// (Data1 u32 LE, Data2 u16 LE, Data3 u16 LE, Data4 bytes) as the canonical
/// lowercase dashed string.
pub fn format_guid_mixed_endian(raw: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let d2 = u16::from_le_bytes([raw[4], raw[5]]);
    let d3 = u16::from_le_bytes([raw[6], raw[7]]);
    let mut out = format!("{:08x}-{:04x}-{:04x}-", d1, d2, d3);
    for b in &raw[8..10] {
        out.push_str(&format!("{:02x}", b));
    }
    out.push('-');
    for b in &raw[10..16] {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// One parsed GPT partition entry.
#[derive(Debug, Clone, PartialEq)]
pub struct GptPartitionEntry {
    pub type_guid: String,
    pub first_lba: u64,
    pub last_lba: u64,
    /// UTF-16LE partition name from the table (often empty on Windows disks).
    pub name: String,
}

/// Parse a single GPT partition-entry record. All-zero type GUID = unused
/// slot → None.
pub fn parse_gpt_entry(entry: &[u8]) -> Option<GptPartitionEntry> {
    if entry.len() < 128 {
        return None;
    }
    let mut guid_raw = [0u8; 16];
    guid_raw.copy_from_slice(&entry[0..16]);
    if guid_raw == [0u8; 16] {
        return None;
    }
    let first_lba = u64::from_le_bytes(entry[32..40].try_into().ok()?);
    let last_lba = u64::from_le_bytes(entry[40..48].try_into().ok()?);
    // Partition name: 72 bytes of UTF-16LE at offset 56.
    let name_units: Vec<u16> = entry[56..128]
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    let name = String::from_utf16(&name_units).unwrap_or_default();
    Some(GptPartitionEntry {
        type_guid: format_guid_mixed_endian(&guid_raw),
        first_lba,
        last_lba,
        name,
    })
}

/// Read the primary GPT partition-entry array from a disk image/device
/// (read-only). Returns entries in table order.
pub fn read_gpt_entries(disk_path: &Path) -> Option<Vec<GptPartitionEntry>> {
    let mut f = crate::backend::linux::open_read_buffered(disk_path).ok()?;
    let mut hdr = [0u8; 512];
    f.seek(SeekFrom::Start(512)).ok()?;
    f.read_exact(&mut hdr).ok()?;
    let h = parse_gpt_header(&hdr)?;
    // Allocation cap: 1024 entries × 4096 bytes = 4 MiB max.
    let total = (h.num_entries as usize).saturating_mul(h.entry_size as usize);
    f.seek(SeekFrom::Start(h.entries_lba.saturating_mul(512))).ok()?;
    let mut buf = vec![0u8; total];
    f.read_exact(&mut buf).ok()?;
    Some(
        buf.chunks(h.entry_size as usize)
            .filter_map(parse_gpt_entry)
            .collect(),
    )
}

/// A parsed MBR partition-entry record.
#[derive(Debug, Clone, PartialEq)]
pub struct MbrPartitionEntry {
    pub type_byte: u8,
    pub start_lba: u32,
    pub sectors: u32,
}

/// Parse the 4 primary entries of an MBR boot sector (read-only input).
pub fn parse_mbr_entries(sector: &[u8]) -> Vec<MbrPartitionEntry> {
    if sector.len() < 512 || sector[510] != 0x55 || sector[511] != 0xAA {
        return Vec::new();
    }
    (0..4)
        .filter_map(|i| {
            let off = 446 + i * 16;
            let e = &sector[off..off + 16];
            let type_byte = e[4];
            if type_byte == 0 {
                return None;
            }
            Some(MbrPartitionEntry {
                type_byte,
                start_lba: u32::from_le_bytes(e[8..12].try_into().ok()?),
                sectors: u32::from_le_bytes(e[12..16].try_into().ok()?),
            })
        })
        .collect()
}

/// Read the MBR (LBA 0) of a disk image/device (read-only).
pub fn read_mbr_entries(disk_path: &Path) -> Vec<MbrPartitionEntry> {
    let mut f = match crate::backend::linux::open_read_buffered(disk_path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let mut buf = [0u8; 512];
    match f.read_exact(&mut buf) {
        Ok(()) => parse_mbr_entries(&buf),
        Err(_) => Vec::new(),
    }
}

/// Filesystem/encryption signatures found in a volume header.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VolumeProbe {
    /// Lowercase fs signature: "ntfs" | "exfat" | "fat32" | "fat16" | "fat12"
    /// | "ext4" | "swap" | "bitlocker" | "crypto_LUKS".
    pub fs: Option<String>,
    /// B2: "BitLocker" | "LUKS" when an encryption signature matched.
    pub encryption: Option<String>,
}

/// Classify a volume header (first 4 KiB of a partition). Checks encryption
/// signatures first (B2: BitLocker `-FVE-FS-` at offset 3, LUKS magic), then
/// filesystem OEM strings. A false-positive only affects a display label —
/// the wipe decision never depends on this.
pub fn probe_volume_header(buf: &[u8]) -> VolumeProbe {
    let mut out = VolumeProbe::default();
    if buf.len() < 11 {
        return out;
    }
    // B2: BitLocker volume header — "-FVE-FS-" at offset 3.
    if &buf[3..11] == b"-FVE-FS-" {
        out.encryption = Some("BitLocker".to_string());
        out.fs = Some("bitlocker".to_string());
        return out;
    }
    // B2: LUKS1/LUKS2 magic "LUKS\xba\xbe" at offset 0.
    if buf.len() >= 6 && &buf[0..6] == b"LUKS\xba\xbe" {
        out.encryption = Some("LUKS".to_string());
        out.fs = Some("crypto_LUKS".to_string());
        return out;
    }
    let boot_sig = buf.len() >= 512 && buf[510] == 0x55 && buf[511] == 0xAA;
    if boot_sig {
        if &buf[3..11] == b"NTFS    " {
            out.fs = Some("ntfs".to_string());
        } else if &buf[3..11] == b"EXFAT   " {
            out.fs = Some("exfat".to_string());
        } else if buf.len() >= 90 && &buf[82..90] == b"FAT32   " {
            out.fs = Some("fat32".to_string());
        } else if buf.len() >= 62 && &buf[54..62] == b"FAT16   " {
            out.fs = Some("fat16".to_string());
        } else if buf.len() >= 62 && &buf[54..62] == b"FAT12   " {
            out.fs = Some("fat12".to_string());
        }
    }
    // ext2/3/4 superblock magic 0xEF53 at 1024 + 56.
    if out.fs.is_none() && buf.len() >= 1082 && buf[1080] == 0x53 && buf[1081] == 0xef {
        out.fs = Some("ext4".to_string());
    }
    // Swap area marker in the tail of the first 4 KiB page.
    if out.fs.is_none() && buf.len() >= 4096 && &buf[4086..4096] == b"SWAPSPACE2" {
        out.fs = Some("swap".to_string());
    }
    out
}

/// Read-only volume-header probe: reads the first 4 KiB of a partition by
/// seeking on its parent disk/image to `start_sector * 512`. Works without
/// per-partition device nodes (fixtures, minimal udev environments).
pub fn read_volume_probe_at(disk_path: &Path, start_sector: u64) -> VolumeProbe {
    let mut f = match crate::backend::linux::open_read_buffered(disk_path) {
        Ok(f) => f,
        Err(_) => return VolumeProbe::default(),
    };
    if f.seek(SeekFrom::Start(start_sector.saturating_mul(512))).is_err() {
        return VolumeProbe::default();
    }
    let mut buf = [0u8; 4096];
    match f.read(&mut buf) {
        Ok(n) if n >= 11 => probe_volume_header(&buf[..n]),
        _ => VolumeProbe::default(),
    }
}

// ---------------------------------------------------------------------------
// B1 (optional): read-only Windows-install probe
// ---------------------------------------------------------------------------

/// Result of probing a volume for a Windows installation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WindowsProbe {
    pub device: String,
    /// Whether the read-only mount succeeded (probe itself is meaningful).
    pub mounted_read_only: bool,
    /// A `Windows` directory exists at the volume root.
    pub has_windows_dir: bool,
    /// Corroborating `Windows\System32` directory exists.
    pub has_system32: bool,
    /// "Likely C: (Windows installed)" marker: a Windows directory is present.
    pub likely_windows_install: bool,
    pub used_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub error: Option<String>,
}

/// statvfs(3) wrapper → (total_bytes, used_bytes) for a mounted path.
fn statvfs_bytes(path: &Path) -> Option<(u64, u64)> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_str()?).ok()?;
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut st) != 0 {
            return None;
        }
        let frsize = if st.f_frsize != 0 {
            st.f_frsize as u64
        } else {
            st.f_bsize as u64
        };
        let total = (st.f_blocks as u64).saturating_mul(frsize);
        let used = (st.f_blocks as u64).saturating_sub(st.f_bfree as u64).saturating_mul(frsize);
        Some((total, used))
    }
}

/// Pure directory classification for the Windows probe: does the mount root
/// hold `Windows` and `Windows/System32`?
pub fn classify_windows_root(root: &Path) -> (bool, bool) {
    let has_windows = root.join("Windows").is_dir();
    let has_system32 = root.join("Windows").join("System32").is_dir();
    (has_windows, has_system32)
}

/// B1 optional: probe a volume for a Windows installation.
///
/// Mounts READ-ONLY (`ro,noexec,nosuid,nodev`) into a private temp dir, runs
/// the read-only classification, reads usage with statvfs, then ALWAYS
/// unmounts and removes the mountpoint. The volume is never opened for
/// writing at any point.
pub fn probe_windows_volume(device: &str) -> WindowsProbe {
    let mut probe = WindowsProbe {
        device: device.to_string(),
        mounted_read_only: false,
        has_windows_dir: false,
        has_system32: false,
        likely_windows_install: false,
        used_bytes: None,
        total_bytes: None,
        error: None,
    };

    let mnt = std::env::temp_dir().join(format!(
        "zt-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    if let Err(e) = fs::create_dir(&mnt) {
        probe.error = Some(format!("Cannot create mountpoint: {}", e));
        return probe;
    }
    let mnt_str = mnt.to_string_lossy().to_string();

    // P2: read-only probe tools go through the backend (argv list, no shell).
    let backend = crate::backend::linux::LinuxBackend::new(
        crate::execute::FsContext::default(),
    );
    let mount_out = backend.exec(
        "mount",
        &["-o", "ro,noexec,nosuid,nodev", "--", device, &mnt_str],
    );
    let mounted = match mount_out {
        Ok((_, _, 0)) => true,
        Ok((_, stderr, _)) => {
            probe.error = Some(format!("read-only mount failed: {}", stderr.trim()));
            false
        }
        Err(e) => {
            probe.error = Some(format!("mount command unavailable: {}", e));
            false
        }
    };

    if mounted {
        probe.mounted_read_only = true;
        let (has_windows, has_system32) = classify_windows_root(&mnt);
        probe.has_windows_dir = has_windows;
        probe.has_system32 = has_system32;
        probe.likely_windows_install = has_windows;
        if let Some((total, used)) = statvfs_bytes(&mnt) {
            probe.total_bytes = Some(total);
            probe.used_bytes = Some(used);
        }
        // Always unmount — the read-only mount must not outlive the probe.
        let _ = backend.exec("umount", &[&mnt_str]);
    }

    // Remove our (now unmounted) mountpoint. If removal fails the dir is
    // empty and harmless.
    let _ = fs::remove_dir(&mnt);
    probe
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

    // B1: raw partition-type tables, read read-only from the device/image.
    // Empty when the table is unreadable — classification then falls back to
    // the volume-header probe only.
    let gpt_entries: Vec<GptPartitionEntry> = if table_type == "gpt" {
        read_gpt_entries(&dev_path).unwrap_or_default()
    } else {
        Vec::new()
    };
    let mbr_entries: Vec<MbrPartitionEntry> = if table_type == "mbr" {
        read_mbr_entries(&dev_path)
    } else {
        Vec::new()
    };

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

        // B1/B2: read-only classification — GPT type GUID / MBR type byte
        // plus a boot-sector probe (fs signature, BitLocker/LUKS magic).
        // Probes read from the parent disk at the partition offset and fail
        // soft (all-None labels) when the disk is unreadable or too small.
        let vol = read_volume_probe_at(&dev_path, start_sector);
        if fs_type.is_none() {
            // Unmounted volume: the probed signature is the best fs evidence.
            fs_type = vol.fs.clone();
        }

        let gpt_hit = gpt_entries.iter().find(|e| e.first_lba == start_sector);
        let mbr_hit = mbr_entries
            .iter()
            .find(|e| u64::from(e.start_lba) == start_sector);

        let (type_guid, type_name, role) = if let Some(g) = gpt_hit {
            let classified = classify_gpt_guid(&g.type_guid);
            let name = classified
                .map(|(n, _)| n.to_string())
                .or_else(|| vol.fs.as_ref().map(|f| format!("{} volume", f)));
            let role = classified
                .map(|(_, r)| r.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            (Some(g.type_guid.clone()), name, Some(role))
        } else if let Some(m) = mbr_hit {
            let (n, r) = classify_mbr_partition(m.type_byte, vol.fs.as_deref());
            (None, Some(n), Some(r))
        } else {
            // No table entry matched: fall back to the fs signature alone.
            let name = vol.fs.as_ref().map(|f| format!("{} volume", f));
            let role = match vol.fs.as_deref() {
                Some("ntfs") | Some("exfat") | Some("fat32") | Some("fat16") | Some("fat12") => {
                    Some("windows_data".to_string())
                }
                Some("swap") => Some("linux_swap".to_string()),
                Some("bitlocker") => Some("windows_data".to_string()),
                Some("crypto_LUKS") => Some("luks".to_string()),
                Some(f) if f.starts_with("ext") => Some("linux".to_string()),
                _ => None,
            };
            (None, name, role)
        };
        // B2: header signature first, LUKS type GUID as corroboration.
        let encryption = vol.encryption.clone().or_else(|| {
            if role.as_deref() == Some("luks") {
                Some("LUKS".to_string())
            } else {
                None
            }
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
            type_guid,
            type_name,
            role,
            fs_probe: vol.fs,
            encryption,
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

    // ------------------------------------------------------------------
    // B1/B2: partition-type classification & volume-header probing
    // ------------------------------------------------------------------

    /// Parse a canonical dashed GUID into mixed-endian on-disk bytes
    /// (inverse of `format_guid_mixed_endian`).
    fn guid_bytes(canonical: &str) -> [u8; 16] {
        let parts: Vec<&str> = canonical.split('-').collect();
        assert_eq!(parts.len(), 5, "bad GUID: {}", canonical);
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&u32::from_str_radix(parts[0], 16).unwrap().to_le_bytes());
        out[4..6].copy_from_slice(&u16::from_str_radix(parts[1], 16).unwrap().to_le_bytes());
        out[6..8].copy_from_slice(&u16::from_str_radix(parts[2], 16).unwrap().to_le_bytes());
        let hex = format!("{}{}", parts[3], parts[4]);
        for i in 0..8 {
            out[8 + i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn put_utf16(dst: &mut [u8], s: &str) {
        for (i, unit) in s.encode_utf16().enumerate() {
            dst[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    /// 8 MiB GPT disk image with Windows-typical partitions:
    /// EFI System, MSR, Basic Data (NTFS), Windows Recovery, LUKS.
    fn build_windows_gpt_image() -> Vec<u8> {
        let mut img = vec![0u8; 8 * 1024 * 1024];
        // Protective MBR signature
        img[510] = 0x55;
        img[511] = 0xAA;
        // GPT header at LBA 1
        img[512..520].copy_from_slice(b"EFI PART");
        img[524..528].copy_from_slice(&92u32.to_le_bytes()); // header size
        img[584..592].copy_from_slice(&2u64.to_le_bytes()); // entries LBA
        img[592..596].copy_from_slice(&128u32.to_le_bytes()); // entry count
        img[596..600].copy_from_slice(&128u32.to_le_bytes()); // entry size
        // Partition entries at LBA 2
        let entries: [(&str, u64, u64, &str); 5] = [
            ("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", 2048, 6143, "EFI system partition"),
            ("e3c9e316-0b5c-4db8-817d-f92df00215ae", 6144, 8191, ""),
            ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", 8192, 10239, "Data"),
            ("de94bba4-06d1-4d40-a16a-bfd50179d6ac", 10240, 12287, "Recovery"),
            ("ca7d7ccb-63ed-4c53-861c-1742536059cc", 12288, 14335, ""),
        ];
        for (i, (guid, first, last, name)) in entries.iter().enumerate() {
            let off = 1024 + i * 128;
            img[off..off + 16].copy_from_slice(&guid_bytes(guid));
            img[off + 32..off + 40].copy_from_slice(&first.to_le_bytes());
            img[off + 40..off + 48].copy_from_slice(&last.to_le_bytes());
            put_utf16(&mut img[off + 56..off + 128], name);
        }
        // NTFS boot sector at the basic-data partition (LBA 8192)
        let ntfs = 8192 * 512;
        img[ntfs] = 0xEB;
        img[ntfs + 3..ntfs + 11].copy_from_slice(b"NTFS    ");
        img[ntfs + 510] = 0x55;
        img[ntfs + 511] = 0xAA;
        // LUKS magic at the LUKS partition (LBA 12288)
        let luks = 12288 * 512;
        img[luks..luks + 6].copy_from_slice(b"LUKS\xba\xbe");
        img
    }

    fn build_windows_gpt_fixture() -> TempFixture {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        let proc = tmp.path().join("proc");
        let dev = tmp.path().join("dev");
        fs::create_dir_all(&dev).unwrap();
        fs::write(dev.join("sda"), build_windows_gpt_image()).unwrap();
        write(&sys.join("class/block/sda/removable"), "0\n");
        write(&sys.join("class/block/sda/dev"), "8:0\n");
        let parts: [(u32, u64, u64); 5] = [
            (1, 2048, 4096),   // EFI System
            (2, 6144, 2048),   // MSR
            (3, 8192, 2048),   // Basic Data (NTFS)
            (4, 10240, 2048),  // Windows Recovery
            (5, 12288, 2048),  // LUKS
        ];
        for (n, start, size) in parts {
            let base = sys.join(format!("class/block/sda/sda{}", n));
            write(&base.join("partition"), &format!("{}\n", n));
            write(&base.join("size"), &format!("{}\n", size));
            write(&base.join("start"), &format!("{}\n", start));
            write(&base.join("dev"), &format!("8:{}\n", n));
        }
        TempFixture {
            _tmp: tmp,
            ctx: FsContext {
                proc_root: proc,
                sys_root: sys,
                dev_root: dev,
            },
        }
    }

    #[test]
    fn test_gpt_header_and_entry_parsing() {
        let img = build_windows_gpt_image();
        let hdr = parse_gpt_header(&img[512..1024]).unwrap();
        assert_eq!(hdr.entries_lba, 2);
        assert_eq!(hdr.num_entries, 128);
        assert_eq!(hdr.entry_size, 128);

        // Truncated / non-GPT / corrupt headers fail closed.
        assert!(parse_gpt_header(&img[512..600]).is_none(), "< 92 bytes");
        assert!(parse_gpt_header(&[0u8; 512]).is_none(), "no EFI PART signature");
        let mut bad = img[512..1024].to_vec();
        bad[80..84].copy_from_slice(&0u32.to_le_bytes()); // num_entries = 0
        assert!(parse_gpt_header(&bad).is_none(), "zero entry count");

        let e = parse_gpt_entry(&img[1024..1024 + 128]).unwrap();
        assert_eq!(e.type_guid, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
        assert_eq!(e.first_lba, 2048);
        assert_eq!(e.last_lba, 6143);
        assert_eq!(e.name, "EFI system partition", "UTF-16LE name decode");

        // All-zero type GUID = unused slot; short buffers fail closed.
        assert!(parse_gpt_entry(&[0u8; 128]).is_none());
        assert!(parse_gpt_entry(&img[1024..1100]).is_none());
    }

    #[test]
    fn test_format_guid_mixed_endian_roundtrip() {
        for g in [
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            "e3c9e316-0b5c-4db8-817d-f92df00215ae",
            "de94bba4-06d1-4d40-a16a-bfd50179d6ac",
            "ca7d7ccb-63ed-4c53-861c-1742536059cc",
        ] {
            assert_eq!(format_guid_mixed_endian(&guid_bytes(g)), g);
        }
    }

    #[test]
    fn test_classify_gpt_guid_registry() {
        assert_eq!(
            classify_gpt_guid("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
            Some(("EFI System", "efi_system"))
        );
        assert_eq!(
            classify_gpt_guid("e3c9e316-0b5c-4db8-817d-f92df00215ae"),
            Some(("Microsoft Reserved", "msr"))
        );
        assert_eq!(
            classify_gpt_guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"),
            Some(("Microsoft Basic Data", "windows_data"))
        );
        assert_eq!(
            classify_gpt_guid("de94bba4-06d1-4d40-a16a-bfd50179d6ac"),
            Some(("Windows Recovery", "windows_recovery"))
        );
        assert_eq!(
            classify_gpt_guid("ca7d7ccb-63ed-4c53-861c-1742536059cc"),
            Some(("LUKS", "luks"))
        );
        assert_eq!(classify_gpt_guid("00000000-0000-0000-0000-000000000000"), None);
    }

    #[test]
    fn test_probe_volume_header_signatures() {
        // NTFS
        let mut ntfs = vec![0u8; 4096];
        ntfs[510] = 0x55;
        ntfs[511] = 0xAA;
        ntfs[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(
            probe_volume_header(&ntfs),
            VolumeProbe { fs: Some("ntfs".into()), encryption: None }
        );

        // exFAT
        let mut exfat = vec![0u8; 4096];
        exfat[510] = 0x55;
        exfat[511] = 0xAA;
        exfat[3..11].copy_from_slice(b"EXFAT   ");
        assert_eq!(probe_volume_header(&exfat).fs, Some("exfat".into()));

        // FAT32 (OEM name at offset 82)
        let mut fat32 = vec![0u8; 4096];
        fat32[510] = 0x55;
        fat32[511] = 0xAA;
        fat32[82..90].copy_from_slice(b"FAT32   ");
        assert_eq!(probe_volume_header(&fat32).fs, Some("fat32".into()));

        // B2: BitLocker "-FVE-FS-" at offset 3 (wins over an NTFS-looking boot)
        let mut bl = vec![0u8; 4096];
        bl[510] = 0x55;
        bl[511] = 0xAA;
        bl[3..11].copy_from_slice(b"-FVE-FS-");
        assert_eq!(
            probe_volume_header(&bl),
            VolumeProbe { fs: Some("bitlocker".into()), encryption: Some("BitLocker".into()) }
        );

        // B2: LUKS1/LUKS2 magic
        let mut luks = vec![0u8; 4096];
        luks[0..6].copy_from_slice(b"LUKS\xba\xbe");
        assert_eq!(
            probe_volume_header(&luks),
            VolumeProbe { fs: Some("crypto_LUKS".into()), encryption: Some("LUKS".into()) }
        );

        // ext superblock magic
        let mut ext = vec![0u8; 4096];
        ext[1080] = 0x53;
        ext[1081] = 0xef;
        assert_eq!(probe_volume_header(&ext).fs, Some("ext4".into()));

        // Swap marker
        let mut swap = vec![0u8; 4096];
        swap[4086..4096].copy_from_slice(b"SWAPSPACE2");
        assert_eq!(probe_volume_header(&swap).fs, Some("swap".into()));

        // Zeros / truncated input → nothing
        assert_eq!(probe_volume_header(&[0u8; 4096]), VolumeProbe::default());
        assert_eq!(probe_volume_header(&[0u8; 5]), VolumeProbe::default());
    }

    #[test]
    fn test_classify_mbr_partition_combines_type_and_fs() {
        // Type byte and fs signature agree → Windows labels.
        assert_eq!(
            classify_mbr_partition(0x07, Some("ntfs")),
            ("Windows NTFS/exFAT".to_string(), "windows_data".to_string())
        );
        assert_eq!(
            classify_mbr_partition(0x0b, Some("fat32")),
            ("Windows FAT32".to_string(), "windows_data".to_string())
        );
        assert_eq!(
            classify_mbr_partition(0x27, Some("ntfs")),
            ("Windows Recovery".to_string(), "windows_recovery".to_string())
        );
        // fs signature contradicts the generic Windows byte → Linux wins.
        assert_eq!(
            classify_mbr_partition(0x07, Some("ext4")),
            ("Linux (ext4)".to_string(), "linux".to_string())
        );
        // Type byte alone (unreadable volume header).
        assert_eq!(
            classify_mbr_partition(0x83, None),
            ("Linux".to_string(), "linux".to_string())
        );
        assert_eq!(
            classify_mbr_partition(0x00, None),
            ("Unknown".to_string(), "unknown".to_string())
        );
    }

    #[test]
    fn test_enumerate_windows_gpt_disk() {
        let f = build_windows_gpt_fixture();
        let report = enumerate_partitions_ctx("/dev/sda", &f.ctx).unwrap();
        assert_eq!(report.table_type, "gpt");
        assert_eq!(report.partitions.len(), 5);

        let esp = &report.partitions[0];
        assert_eq!(
            esp.type_guid.as_deref(),
            Some("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
        );
        assert_eq!(esp.type_name.as_deref(), Some("EFI System"));
        assert_eq!(esp.role.as_deref(), Some("efi_system"));
        assert_eq!(esp.fs_probe, None, "zeros must not fake a filesystem");
        assert_eq!(esp.encryption, None);

        let msr = &report.partitions[1];
        assert_eq!(msr.type_name.as_deref(), Some("Microsoft Reserved"));
        assert_eq!(msr.role.as_deref(), Some("msr"));

        let basic = &report.partitions[2];
        assert_eq!(basic.type_guid.as_deref(), Some("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"));
        assert_eq!(basic.type_name.as_deref(), Some("Microsoft Basic Data"));
        assert_eq!(basic.role.as_deref(), Some("windows_data"));
        assert_eq!(basic.fs_probe.as_deref(), Some("ntfs"));
        assert_eq!(
            basic.fs_type.as_deref(),
            Some("ntfs"),
            "unmounted volume takes its fs from the header probe"
        );
        assert_eq!(basic.encryption, None);

        let recovery = &report.partitions[3];
        assert_eq!(recovery.type_name.as_deref(), Some("Windows Recovery"));
        assert_eq!(recovery.role.as_deref(), Some("windows_recovery"));
        assert_eq!(recovery.fs_probe, None);

        let luks = &report.partitions[4];
        assert_eq!(luks.type_name.as_deref(), Some("LUKS"));
        assert_eq!(luks.role.as_deref(), Some("luks"));
        assert_eq!(luks.fs_probe.as_deref(), Some("crypto_LUKS"));
        assert_eq!(luks.encryption.as_deref(), Some("LUKS"), "B2: label the volume");
    }

    #[test]
    fn test_enumerate_mbr_bitlocker_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        let proc = tmp.path().join("proc");
        let dev = tmp.path().join("dev");
        fs::create_dir_all(&dev).unwrap();

        // MBR image: one 0x07 primary partition at LBA 2048 with a BitLocker
        // volume header.
        let mut img = vec![0u8; 4 * 1024 * 1024];
        img[510] = 0x55;
        img[511] = 0xAA;
        let e = 446; // first entry
        img[e + 4] = 0x07; // type: NTFS/exFAT
        img[e + 8..e + 12].copy_from_slice(&2048u32.to_le_bytes());
        img[e + 12..e + 16].copy_from_slice(&2048u32.to_le_bytes());
        let p = 2048 * 512;
        img[p] = 0xEB;
        img[p + 1] = 0x90;
        img[p + 2] = 0x90;
        img[p + 3..p + 11].copy_from_slice(b"-FVE-FS-");
        img[p + 510] = 0x55;
        img[p + 511] = 0xAA;
        fs::write(dev.join("sdb"), &img).unwrap();

        write(&sys.join("class/block/sdb/removable"), "1\n");
        write(&sys.join("class/block/sdb/dev"), "8:16\n");
        write(&sys.join("class/block/sdb/sdb1/partition"), "1\n");
        write(&sys.join("class/block/sdb/sdb1/size"), "2048\n");
        write(&sys.join("class/block/sdb/sdb1/start"), "2048\n");
        write(&sys.join("class/block/sdb/sdb1/dev"), "8:17\n");

        let ctx = FsContext { proc_root: proc, sys_root: sys, dev_root: dev };
        let report = enumerate_partitions_ctx("/dev/sdb", &ctx).unwrap();
        assert_eq!(report.table_type, "mbr");
        assert_eq!(report.partitions.len(), 1);
        let p1 = &report.partitions[0];
        assert_eq!(p1.type_guid, None, "MBR has no type GUIDs");
        assert_eq!(p1.type_name.as_deref(), Some("Windows NTFS/exFAT"));
        assert_eq!(p1.role.as_deref(), Some("windows_data"));
        assert_eq!(p1.fs_probe.as_deref(), Some("bitlocker"));
        assert_eq!(
            p1.encryption.as_deref(),
            Some("BitLocker"),
            "B2: BitLocker signature must be surfaced"
        );
    }

    #[test]
    fn test_classify_windows_root_fixture() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(classify_windows_root(tmp.path()), (false, false));
        fs::create_dir(tmp.path().join("Windows")).unwrap();
        assert_eq!(classify_windows_root(tmp.path()), (true, false));
        fs::create_dir(tmp.path().join("Windows").join("System32")).unwrap();
        assert_eq!(classify_windows_root(tmp.path()), (true, true));

        // statvfs on a local tempdir is pure filesystem work — no hardware.
        let (total, used) = statvfs_bytes(tmp.path()).expect("statvfs on tempdir");
        assert!(total > 0);
        assert!(used <= total);
    }
}
