//! Pure, platform-neutral byte parsers for Windows storage facts.
//!
//! Windows IoControl and API results return binary structures (C-style structs).
//! To enable thorough unit testing on Linux without Windows APIs or hardware,
//! this module handles parsing of raw byte buffers (`&[u8]`).
//!
//! Handled structures:
//! - `STORAGE_DEVICE_DESCRIPTOR` (IOCTL_STORAGE_QUERY_PROPERTY, StorageDeviceProperty)
//! - `DEVICE_SEEK_PENALTY_DESCRIPTOR` (IOCTL_STORAGE_QUERY_PROPERTY, StorageDeviceSeekPenaltyProperty)
//! - `DISK_GEOMETRY_EX` (IOCTL_DISK_GET_DRIVE_GEOMETRY_EX)
//! - `DRIVE_LAYOUT_INFORMATION_EX` (IOCTL_DISK_GET_DRIVE_LAYOUT_EX, GPT and MBR)
//! - `VOLUME_DISK_EXTENTS` (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS)
//! - BitLocker volume header detection (`-FVE-FS-` signature)
//! - Layout fingerprint calculation (matching the Linux canonical format)
//!
//! Field offsets below are cited against the Microsoft Win32 structure
//! documentation. Where an offset is not documented by Microsoft it is marked
//! `TODO-VERIFY` instead of being guessed.

use sha2::{Digest, Sha256};
use std::fmt;

use crate::backend::{BitLockerLockState, VolumeDriveType};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// 1. Storage Device Descriptor (model, serial, bus type, removable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedStorageDescriptor {
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub product_revision: Option<String>,
    pub serial_number: Option<String>,
    pub bus_type: i32,
    pub is_removable: bool,
}

impl ParsedStorageDescriptor {
    /// Combines vendor_id and product_id to form a friendly model name,
    /// matching the behavior of lsblk/udev on Linux.
    pub fn model(&self) -> Option<String> {
        let v = self.vendor_id.as_deref().unwrap_or("").trim();
        let p = self.product_id.as_deref().unwrap_or("").trim();
        if v.is_empty() && p.is_empty() {
            None
        } else if v.is_empty() {
            Some(p.to_string())
        } else if p.is_empty() {
            Some(v.to_string())
        } else {
            Some(format!("{} {}", v, p))
        }
    }

    /// Maps Windows STORAGE_BUS_TYPE integer to transport string (e.g. "usb", "nvme", "sata").
    ///
    /// Values follow the Microsoft `STORAGE_BUS_TYPE` enumeration:
    /// https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-storage_bus_type
    pub fn transport_str(&self) -> Option<String> {
        match self.bus_type {
            1 => Some("scsi".into()),
            2 | 3 => Some("ata".into()),
            4 => Some("firewire".into()),
            5 => Some("ssa".into()),
            6 => Some("fibre".into()),
            7 => Some("usb".into()),
            8 => Some("raid".into()),
            9 => Some("iscsi".into()),
            10 => Some("sas".into()),
            11 => Some("sata".into()),
            12 => Some("sd".into()),
            13 => Some("mmc".into()),
            14 | 15 => Some("virtual".into()),
            16 => Some("spaces".into()),
            17 => Some("nvme".into()),
            18 => Some("scm".into()),
            19 => Some("ufs".into()),
            _ => None,
        }
    }
}

fn read_null_terminated_ascii(buf: &[u8], offset: usize) -> Option<String> {
    if offset == 0 || offset >= buf.len() {
        return None;
    }
    let slice = &buf[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let s = String::from_utf8_lossy(&slice[..end]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

pub fn parse_storage_device_descriptor(buf: &[u8]) -> Result<ParsedStorageDescriptor, ParseError> {
    // STORAGE_DEVICE_DESCRIPTOR layout, Microsoft Win32 API docs:
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_descriptor
    // Version               DWORD  @ 0
    // Size                  DWORD  @ 4
    // DeviceType            BYTE   @ 8
    // DeviceTypeModifier    BYTE   @ 9
    // RemovableMedia        BOOLEAN@ 10
    // CommandQueueing       BOOLEAN@ 11
    // VendorIdOffset        DWORD  @ 12
    // ProductIdOffset       DWORD  @ 16
    // ProductRevisionOffset DWORD  @ 20
    // SerialNumberOffset    DWORD  @ 24
    // BusType               enum   @ 28
    // RawPropertiesLength   DWORD  @ 32
    // RawDeviceProperties[] BYTE   @ 36
    // The fixed part (through RawPropertiesLength) is 36 bytes; offsets below
    // are byte offsets relative to the start of the returned buffer.
    if buf.len() < 36 {
        return Err(ParseError(format!(
            "Buffer too short for STORAGE_DEVICE_DESCRIPTOR: {} bytes (need at least 36)",
            buf.len()
        )));
    }

    // RemovableMedia is a BOOLEAN at offset 10 (docs linked above).
    let is_removable = buf[10] != 0;
    // String offsets are DWORDs at offsets 12, 16, 20 and 24 (docs above);
    // each is relative to the start of this structure.
    let vendor_id_offset = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
    let product_id_offset = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    let product_rev_offset = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
    let serial_num_offset = u32::from_le_bytes(buf[24..28].try_into().unwrap()) as usize;
    // STORAGE_BUS_TYPE is an enum stored as a 32-bit integer at offset 28:
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-storage_bus_type
    let bus_type = i32::from_le_bytes(buf[28..32].try_into().unwrap());

    Ok(ParsedStorageDescriptor {
        vendor_id: read_null_terminated_ascii(buf, vendor_id_offset),
        product_id: read_null_terminated_ascii(buf, product_id_offset),
        product_revision: read_null_terminated_ascii(buf, product_rev_offset),
        serial_number: read_null_terminated_ascii(buf, serial_num_offset),
        bus_type,
        is_removable,
    })
}

// ---------------------------------------------------------------------------
// 2. Device Seek Penalty (rotational vs SSD)
// ---------------------------------------------------------------------------

pub fn parse_seek_penalty_descriptor(buf: &[u8]) -> Result<bool, ParseError> {
    // DEVICE_SEEK_PENALTY_DESCRIPTOR layout, Microsoft Win32 API docs:
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-device_seek_penalty_descriptor
    // Version            DWORD   @ 0
    // Size               DWORD   @ 4
    // IncursSeekPenalty  BOOLEAN @ 8
    if buf.len() < 9 {
        return Err(ParseError(format!(
            "Buffer too short for DEVICE_SEEK_PENALTY_DESCRIPTOR: {} bytes (need at least 9)",
            buf.len()
        )));
    }
    // IncursSeekPenalty at offset 8 (docs above): non-zero = rotational HDD,
    // zero = flash/SSD. Unknown/unsupported queries are handled by the caller.
    Ok(buf[8] != 0)
}

// ---------------------------------------------------------------------------
// 3. Disk Geometry (size and sector sizes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGeometry {
    pub size_bytes: u64,
    pub bytes_per_sector: u32,
}

pub fn parse_disk_geometry_ex(buf: &[u8]) -> Result<ParsedGeometry, ParseError> {
    // DISK_GEOMETRY_EX layout, Microsoft Win32 API docs:
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-disk_geometry_ex
    // DISK_GEOMETRY Geometry (24 bytes):
    //   Cylinders         LARGE_INTEGER @ 0
    //   MediaType         enum          @ 8
    //   TracksPerCylinder DWORD         @ 12
    //   SectorsPerTrack   DWORD         @ 16
    //   BytesPerSector    DWORD         @ 20
    // DiskSize            LARGE_INTEGER @ 24
    // Data[]              BYTE          @ 32
    // DISK_GEOMETRY member offsets:
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-disk_geometry
    if buf.len() < 32 {
        return Err(ParseError(format!(
            "Buffer too short for DISK_GEOMETRY_EX: {} bytes (need at least 32)",
            buf.len()
        )));
    }

    // BytesPerSector is the last DWORD of DISK_GEOMETRY at offset 20.
    let bytes_per_sector = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    // DiskSize follows the 24-byte DISK_GEOMETRY at offset 24.
    let disk_size = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    // A negative DiskSize is not a valid geometry fact; report it as zero so
    // the backend's fail-closed probe check rejects it instead of inventing a
    // size. (Windows itself returns a LARGE_INTEGER here.)
    let size_bytes = if disk_size < 0 { 0 } else { disk_size as u64 };

    Ok(ParsedGeometry {
        size_bytes,
        // TODO-VERIFY: Microsoft does not state that BytesPerSector can be 0
        // for a valid disk; the historical 512 fallback is retained for
        // malformed/fixture buffers only and is rejected later by discovery
        // when the probe reports a zero-sized disk.
        bytes_per_sector: if bytes_per_sector == 0 {
            512
        } else {
            bytes_per_sector
        },
    })
}

// ---------------------------------------------------------------------------
// 4. Drive Layout Information (GPT and MBR partitions)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionStyle {
    Mbr,
    Gpt,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPartition {
    pub partition_number: u32,
    pub starting_offset: u64,
    pub partition_length: u64,
    pub start_sector: u64,
    pub size_sectors: u64,
    pub partition_type_guid: Option<String>,
    pub partition_type_mbr: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDriveLayout {
    pub style: PartitionStyle,
    pub partitions: Vec<ParsedPartition>,
}

pub fn format_guid_le(buf: &[u8]) -> String {
    if buf.len() < 16 {
        return String::new();
    }
    // GUID layout, Microsoft docs: Data1 is a little-endian DWORD, Data2 and
    // Data3 are little-endian WORDs, and Data4 is 8 bytes in wire order.
    // https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
    let d1 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let d2 = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    let d3 = u16::from_le_bytes(buf[6..8].try_into().unwrap());
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1, d2, d3, buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
    )
}

pub fn parse_drive_layout_ex(buf: &[u8]) -> Result<ParsedDriveLayout, ParseError> {
    // DRIVE_LAYOUT_INFORMATION_EX layout, Microsoft Win32 API docs:
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-drive_layout_information_ex
    // PartitionStyle DWORD @ 0  (0 = MBR, 1 = GPT, 2 = RAW)
    // PartitionCount DWORD @ 4
    // Anonymous union        @ 8  (x64 size 40: DRIVE_LAYOUT_INFORMATION_GPT)
    // PartitionEntry[1]      @ 48 (8-byte aligned on x64)
    // DRIVE_LAYOUT_INFORMATION_GPT (union member):
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-drive_layout_information_gpt
    //   DiskId              GUID          @ union+0
    //   StartingUsableOffset LARGE_INTEGER @ union+16
    //   UsableLength         LARGE_INTEGER @ union+24
    //   MaxPartitionCount    DWORD         @ union+32
    //   (4 bytes tail padding -> 40-byte union on x64)
    // `PartitionEntry` therefore starts at offset 48, not 56. This was
    // verified against windows-sys 0.61.2 with `offset_of!` and the mingw-w64
    // winioctl.h declarations; the previous 56-byte assumption skipped the
    // first 8 bytes of every entry.
    //
    // PARTITION_INFORMATION_EX (144 bytes on x64), Microsoft docs:
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-partition_information_ex
    //   PartitionStyle   enum  @ 0
    //   PartitionOrdinal WORD  @ 4 (modern SDK; otherwise padding)
    //   StartingOffset   i64   @ 8
    //   PartitionLength  i64   @ 16
    //   PartitionNumber  DWORD @ 24
    //   RewritePartition BOOLEAN @ 28
    //   IsServicePartition BOOLEAN @ 29
    //   Anonymous union  @ 32 (112-byte GPT member)
    //   GPT: PartitionType GUID @ 32..48; MBR: PartitionType BYTE @ 32
    const HEADER_SIZE: usize = 48;
    const ENTRY_SIZE: usize = 144;

    if buf.len() < HEADER_SIZE {
        return Err(ParseError(format!(
            "Buffer too short for DRIVE_LAYOUT_INFORMATION_EX: {} bytes (need at least 48)",
            buf.len()
        )));
    }

    // PartitionStyle at offset 0 and PartitionCount at offset 4 (docs above).
    let raw_style = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let partition_count = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;

    // PARTITION_STYLE values: 0 = MBR, 1 = GPT, 2 = RAW.
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-partition_style
    let style = match raw_style {
        0 => PartitionStyle::Mbr,
        1 => PartitionStyle::Gpt,
        _ => PartitionStyle::Raw,
    };

    let mut partitions = Vec::new();
    let mut offset = HEADER_SIZE;

    for _ in 0..partition_count {
        let entry_end = offset.checked_add(ENTRY_SIZE).ok_or_else(|| {
            ParseError("DRIVE_LAYOUT_INFORMATION_EX entry offset overflow".to_string())
        })?;
        if entry_end > buf.len() {
            return Err(ParseError(format!(
                "Truncated DRIVE_LAYOUT_INFORMATION_EX: declared {} entries, need {} bytes but buffer is {} bytes",
                partition_count,
                entry_end,
                buf.len()
            )));
        }

        let entry = &buf[offset..entry_end];
        // PARTITION_INFORMATION_EX field offsets (docs above).
        let starting_offset_raw = i64::from_le_bytes(entry[8..16].try_into().unwrap());
        let partition_length_raw = i64::from_le_bytes(entry[16..24].try_into().unwrap());
        let partition_number = u32::from_le_bytes(entry[24..28].try_into().unwrap());
        // Union starts at offset 32: GPT PartitionType GUID @ 32..48, MBR
        // PartitionType BYTE @ 32 (docs above).

        // In both MBR and GPT, partition_number 0 indicates an unused table
        // entry (Microsoft DRIVE_LAYOUT_INFORMATION_EX docs: unused MBR
        // entries use PARTITION_ENTRY_UNUSED = 0).
        if partition_number > 0 && starting_offset_raw >= 0 && partition_length_raw > 0 {
            let starting_offset = starting_offset_raw as u64;
            let partition_length = partition_length_raw as u64;
            let start_sector = starting_offset / 512;
            let size_sectors = partition_length / 512;

            let (type_guid, mbr_type) = match style {
                PartitionStyle::Gpt => {
                    let guid_bytes = &entry[32..48];
                    // Skip unused/zero GUID partition entries.
                    if guid_bytes.iter().all(|&b| b == 0) {
                        offset = entry_end;
                        continue;
                    }
                    (Some(format_guid_le(guid_bytes)), None)
                }
                PartitionStyle::Mbr => {
                    let ptype = entry[32];
                    // Skip PARTITION_ENTRY_UNUSED (0) MBR entries.
                    if ptype == 0 {
                        offset = entry_end;
                        continue;
                    }
                    (None, Some(ptype))
                }
                PartitionStyle::Raw => (None, None),
            };

            partitions.push(ParsedPartition {
                partition_number,
                starting_offset,
                partition_length,
                start_sector,
                size_sectors,
                partition_type_guid: type_guid,
                partition_type_mbr: mbr_type,
            });
        }

        offset = entry_end;
    }

    Ok(ParsedDriveLayout { style, partitions })
}

// ---------------------------------------------------------------------------
// 5. Volume Disk Extents
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedExtent {
    pub disk_number: u32,
    pub starting_offset: u64,
    pub extent_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVolumeExtents {
    pub extents: Vec<ParsedExtent>,
    pub is_multi_extent: bool,
}

pub fn parse_volume_disk_extents(buf: &[u8]) -> Result<ParsedVolumeExtents, ParseError> {
    // VOLUME_DISK_EXTENTS layout, Microsoft Win32 API docs:
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-volume_disk_extents
    // NumberOfDiskExtents DWORD @ 0
    // (4 bytes padding on x64)
    // Extents[1]          @ 8
    // DISK_EXTENT (24 bytes on x64), Microsoft docs:
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-disk_extent
    //   DiskNumber     DWORD         @ 0
    //   (4 bytes padding on x64)
    //   StartingOffset LARGE_INTEGER @ 8
    //   ExtentLength   LARGE_INTEGER @ 16
    const HEADER_SIZE: usize = 8;
    const EXTENT_SIZE: usize = 24;

    if buf.len() < HEADER_SIZE {
        return Err(ParseError(format!(
            "Buffer too short for VOLUME_DISK_EXTENTS: {} bytes (need at least 8)",
            buf.len()
        )));
    }

    let count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    let is_multi_extent = count > 1;

    let mut extents = Vec::new();
    let mut offset = HEADER_SIZE;

    for _ in 0..count {
        let extent_end = offset
            .checked_add(EXTENT_SIZE)
            .ok_or_else(|| ParseError("VOLUME_DISK_EXTENTS extent offset overflow".to_string()))?;
        if extent_end > buf.len() {
            return Err(ParseError(format!(
                "Truncated VOLUME_DISK_EXTENTS: declared {} extents, need {} bytes but buffer is {} bytes",
                count,
                extent_end,
                buf.len()
            )));
        }

        let extent_bytes = &buf[offset..extent_end];
        let disk_number = u32::from_le_bytes(extent_bytes[0..4].try_into().unwrap());
        let starting_offset_raw = i64::from_le_bytes(extent_bytes[8..16].try_into().unwrap());
        let extent_length_raw = i64::from_le_bytes(extent_bytes[16..24].try_into().unwrap());

        extents.push(ParsedExtent {
            disk_number,
            // Negative LARGE_INTEGER values are not valid disk extents; clamp
            // them to zero so discovery can reject the malformed fact instead
            // of presenting a huge unsigned offset.
            starting_offset: if starting_offset_raw < 0 {
                0
            } else {
                starting_offset_raw as u64
            },
            extent_length: if extent_length_raw < 0 {
                0
            } else {
                extent_length_raw as u64
            },
        });

        offset = extent_end;
    }

    Ok(ParsedVolumeExtents {
        extents,
        is_multi_extent,
    })
}

// ---------------------------------------------------------------------------
// 6. BitLocker Detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitLockerStatus {
    Encrypted,
    NotEncrypted,
    Unknown(String),
}

/// Detects BitLocker signature in volume boot record or header slice.
/// BitLocker volumes have the ASCII signature `-FVE-FS-` starting at offset 3.
///
/// TODO-VERIFY: Microsoft does not publish a public byte-layout struct for the
/// BitLocker volume header. The 3..11 signature offset follows the documented
/// BitLocker on-disk signature used by forensic tooling; the fallback scan of
/// the first 512 bytes is intentionally conservative and must be validated on
/// real BitLocker volumes before any write phase relies on it.
pub fn detect_bitlocker(boot_sector_or_header: &[u8]) -> BitLockerStatus {
    if boot_sector_or_header.len() < 11 {
        return BitLockerStatus::Unknown(format!(
            "Buffer too short to check BitLocker signature: {} bytes (minimum 11)",
            boot_sector_or_header.len()
        ));
    }

    // Standard location in VBR is bytes 3..11
    if &boot_sector_or_header[3..11] == b"-FVE-FS-" {
        return BitLockerStatus::Encrypted;
    }

    // Also check if `-FVE-FS-` is anywhere within the first 512 bytes (in case of offset variation)
    let search_window = &boot_sector_or_header[..boot_sector_or_header.len().min(512)];
    if search_window.windows(8).any(|window| window == b"-FVE-FS-") {
        return BitLockerStatus::Encrypted;
    }

    BitLockerStatus::NotEncrypted
}

// ---------------------------------------------------------------------------
// 7. Volume facts (Step 1.2: read-only enumeration helpers)
// ---------------------------------------------------------------------------

/// BitLocker GPT partition type GUID, uppercase like [`format_guid_le`].
pub const BITLOCKER_GPT_TYPE_GUID: &str = "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC";

/// `GetVolumeInformationW` failures that mean "a BitLocker container exists but
/// the OS cannot present its filesystem": `ERROR_ACCESS_DENIED` (5),
/// `ERROR_NOT_READY` (21) and `ERROR_UNRECOGNIZED_VOLUME` (1005). Any other
/// error stays `Unknown`, never "unlocked".
pub const BITLOCKER_LOCKED_FS_ERRORS: [u32; 3] = [5, 21, 1005];

/// What the parent disk's drive layout says about the partition holding a
/// volume. GPT is authoritative; MBR type `0x07` is shared with plain NTFS and
/// exFAT, so it is only a hint that needs the volume header to disambiguate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionContainer {
    GptBitLocker,
    GptOther,
    Mbr(u8),
    Unknown,
}

/// The BitLocker conclusion for one volume. `encrypted: None` means the
/// detection was inconclusive and the shared guard must refuse the volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitLockerAssessment {
    pub encrypted: Option<bool>,
    pub state: BitLockerLockState,
}

/// Parses the `REG_MULTI_SZ`-style buffer returned by
/// `GetVolumePathNamesForVolumeNameW` (strings separated by NUL, list
/// terminated by an empty string). Trailing bytes without a terminator are
/// ignored, matching the API contract rather than guessing.
pub fn parse_volume_path_names(buf: &[u16]) -> Vec<String> {
    let mut names = Vec::new();
    let mut start = 0usize;

    for (idx, &unit) in buf.iter().enumerate() {
        if unit != 0 {
            continue;
        }
        if idx == start {
            // Empty string: the double-NUL list terminator.
            break;
        }
        names.push(String::from_utf16_lossy(&buf[start..idx]));
        start = idx + 1;
    }

    names
}

/// Drive letters (uppercase, no colon) from mount points such as `E:\`.
/// Mount-folder paths and UNC paths contribute no drive letter.
pub fn drive_letters_from_mount_points(points: &[String]) -> Vec<char> {
    let mut letters = Vec::new();
    for point in points {
        let bytes = point.trim().as_bytes();
        let is_drive_root = bytes.len() >= 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes.len() == 2 || (bytes.len() == 3 && bytes[2] == b'\\'));
        if is_drive_root {
            let letter = (bytes[0] as char).to_ascii_uppercase();
            if !letters.contains(&letter) {
                letters.push(letter);
            }
        }
    }
    letters
}

/// `GetDriveTypeW` numeric result → fact. Unknown values are preserved.
pub fn classify_drive_type(raw: u32) -> VolumeDriveType {
    match raw {
        0 => VolumeDriveType::Unknown,
        1 => VolumeDriveType::NoRootDir,
        2 => VolumeDriveType::Removable,
        3 => VolumeDriveType::Fixed,
        4 => VolumeDriveType::Remote,
        5 => VolumeDriveType::CdRom,
        6 => VolumeDriveType::RamDisk,
        other => VolumeDriveType::Other(other),
    }
}

/// A volume spanning more than one disk extent must be refused by the guard.
pub fn is_multi_extent(extent_count: u32) -> bool {
    extent_count > 1
}

/// Finds the partition ordinal whose starting offset equals the volume's
/// single disk extent. `None` = the (successfully read) layout has no basic
/// partition at that offset (dynamic/storage-space volumes).
pub fn find_partition_for_extent(layout: &ParsedDriveLayout, starting_offset: u64) -> Option<u32> {
    layout
        .partitions
        .iter()
        .find(|p| p.starting_offset == starting_offset)
        .map(|p| p.partition_number)
}

/// Classifies the partition holding a volume from the parent disk's layout.
pub fn partition_container(
    style: PartitionStyle,
    partition_type_guid: Option<&str>,
    partition_type_mbr: Option<u8>,
) -> PartitionContainer {
    match style {
        PartitionStyle::Gpt => match partition_type_guid {
            Some(guid) if guid.eq_ignore_ascii_case(BITLOCKER_GPT_TYPE_GUID) => {
                PartitionContainer::GptBitLocker
            }
            Some(_) => PartitionContainer::GptOther,
            None => PartitionContainer::Unknown,
        },
        PartitionStyle::Mbr => match partition_type_mbr {
            Some(kind) => PartitionContainer::Mbr(kind),
            None => PartitionContainer::Unknown,
        },
        PartitionStyle::Raw => PartitionContainer::Unknown,
    }
}

/// MBR partition type of a dynamic-disk container (`PARTITION_LDM`).
pub const MBR_DYNAMIC_DISK_TYPE: u8 = 0x42;
/// GPT LDM metadata partition (dynamic disk).
pub const GPT_LDM_METADATA_GUID: &str = "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3";
/// GPT LDM data partition (dynamic disk).
pub const GPT_LDM_DATA_GUID: &str = "AF9B60A0-1431-4F62-BC68-3311714A69AD";
/// GPT Storage Spaces pool-member partition type.
pub const GPT_STORAGE_SPACES_GUID: &str = "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D";

/// True when this partition entry belongs to a dynamic disk, a Storage
/// Spaces pool, or another non-basic container the volume guard must refuse.
pub fn partition_is_dynamic(partition: &ParsedPartition) -> bool {
    match (&partition.partition_type_guid, partition.partition_type_mbr) {
        (Some(guid), _) => {
            guid.eq_ignore_ascii_case(GPT_LDM_METADATA_GUID)
                || guid.eq_ignore_ascii_case(GPT_LDM_DATA_GUID)
                || guid.eq_ignore_ascii_case(GPT_STORAGE_SPACES_GUID)
        }
        (None, Some(kind)) => kind == MBR_DYNAMIC_DISK_TYPE,
        (None, None) => false,
    }
}

/// True when any partition entry marks the disk as dynamic / Storage Spaces.
/// A volume-scoped wipe requires a basic disk layout, so the guard refuses.
pub fn layout_is_dynamic(layout: &ParsedDriveLayout) -> bool {
    layout.partitions.iter().any(partition_is_dynamic)
}

/// Conclusive BitLocker classification from three independent read-only
/// signals:
///
/// 1. the GPT partition type GUID (authoritative: BitLocker keeps its own
///    type GUID even while unlocked);
/// 2. the first sector read through a read-only volume handle (`-FVE-FS-`);
/// 3. `GetVolumeInformationW` — a locked container fails with one of
///    [`BITLOCKER_LOCKED_FS_ERRORS`], an unlocked container reports its
///    filesystem normally.
///
/// The function never guesses: a container that cannot be ruled out stays
/// `Unknown`, which the guard treats as locked.
pub fn classify_bitlocker(
    container: PartitionContainer,
    signature: Result<BitLockerStatus, u32>,
    filesystem: Result<Option<&str>, u32>,
) -> BitLockerAssessment {
    let header = match &signature {
        Ok(BitLockerStatus::Encrypted) => Some(true),
        Ok(BitLockerStatus::NotEncrypted) => Some(false),
        Ok(BitLockerStatus::Unknown(_)) | Err(_) => None,
    };

    let encrypted = match container {
        PartitionContainer::GptBitLocker => Some(true),
        PartitionContainer::GptOther => Some(false),
        // 0x07 is shared with NTFS/exFAT; only the header can disambiguate.
        PartitionContainer::Mbr(0x07) => header,
        PartitionContainer::Mbr(_) => Some(header.unwrap_or(false)),
        PartitionContainer::Unknown => header,
    };

    match encrypted {
        Some(false) => BitLockerAssessment {
            encrypted: Some(false),
            state: BitLockerLockState::NotEncrypted,
        },
        Some(true) => {
            let state = match filesystem {
                Ok(Some(name)) if !name.trim().is_empty() => BitLockerLockState::Unlocked,
                Ok(_) => BitLockerLockState::Unknown(
                    "BitLocker container exposes no filesystem name".to_string(),
                ),
                Err(code) if BITLOCKER_LOCKED_FS_ERRORS.contains(&code) => {
                    BitLockerLockState::Locked
                }
                Err(code) => BitLockerLockState::Unknown(format!(
                    "BitLocker filesystem query failed (Win32 error {})",
                    code
                )),
            };
            BitLockerAssessment {
                encrypted: Some(true),
                state,
            }
        }
        None => {
            let reason = match signature {
                Err(code) => format!(
                    "volume header unreadable (Win32 error {}) and the partition type is inconclusive",
                    code
                ),
                Ok(BitLockerStatus::Unknown(detail)) => detail,
                Ok(_) => "partition type is inconclusive (MBR type 0x07)".to_string(),
            };
            BitLockerAssessment {
                encrypted: None,
                state: BitLockerLockState::Unknown(reason),
            }
        }
    }
}

/// Case-insensitive volume GUID comparison, tolerating a trailing backslash.
pub fn volume_guid_eq(a: &str, b: &str) -> bool {
    fn normalize(value: &str) -> String {
        value.trim().trim_end_matches('\\').to_ascii_lowercase()
    }
    let left = normalize(a);
    !left.is_empty() && left == normalize(b)
}

/// True when `volume_guid` matches any of `candidates`.
pub fn volume_guid_matches_any(volume_guid: &str, candidates: &[String]) -> bool {
    candidates.iter().any(|c| volume_guid_eq(volume_guid, c))
}

// ---------------------------------------------------------------------------
// 8. Layout Fingerprint (matching Linux canonical format)
// ---------------------------------------------------------------------------

/// Computes SHA-256 partition table fingerprint matching the Linux format:
/// Sorted `"num:start:size\n"` in 512-byte sectors.
pub fn compute_windows_partition_fingerprint(partitions: &[ParsedPartition]) -> String {
    let mut sorted = partitions.to_vec();
    sorted.sort_by_key(|p| p.partition_number);

    let mut canonical = String::new();
    for p in &sorted {
        canonical.push_str(&format!(
            "{}:{}:{}\n",
            p.partition_number, p.start_sector, p.size_sectors
        ));
    }

    let hash = Sha256::digest(canonical.as_bytes());
    format!("{:x}", hash)
}

// ---------------------------------------------------------------------------
// 8. Boot/system facts (D-a piece 2)
//
// The Windows backend reads these values from documented places:
//   * page files:   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\
//                   Memory Management\PagingFiles (REG_MULTI_SZ)
//   * hibernation:  HKLM\SYSTEM\CurrentControlSet\Control\Power\
//                   HibernateEnabled (REG_DWORD); hiberfil.sys lives in the
//                   root of the system volume.
//   * crash dump:   HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\
//                   CrashDumpEnabled (REG_DWORD), DumpFile and MinidumpDir
//                   (REG_SZ/REG_EXPAND_SZ).
// The pure parsers/decision helpers below stay platform-neutral so their
// fixtures run on Linux; the Win32 calls live in `backend/windows.rs`.
// TODO-VERIFY: Microsoft documents the registry value names and types, but
// the "boot volume" vs "system volume" distinction and the crash-dump default
// when `CrashDumpEnabled` is absent must be verified on a real Windows host.
// ---------------------------------------------------------------------------

fn decode_utf16_registry(buf: &[u8]) -> Result<Vec<u16>, ParseError> {
    if !buf.len().is_multiple_of(2) {
        return Err(ParseError(format!(
            "Registry UTF-16 payload has an odd byte length: {}",
            buf.len()
        )));
    }
    Ok(buf
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

/// Decodes a `REG_SZ` payload (UTF-16LE, NUL-terminated). The returned string
/// stops at the first NUL; a missing terminator is tolerated.
pub fn parse_reg_sz(buf: &[u8]) -> Result<String, ParseError> {
    let units = decode_utf16_registry(buf)?;
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    Ok(String::from_utf16_lossy(&units[..end]))
}

/// Decodes a `REG_MULTI_SZ` payload into its non-empty UTF-16 strings.
pub fn parse_reg_multi_sz(buf: &[u8]) -> Result<Vec<String>, ParseError> {
    let units = decode_utf16_registry(buf)?;
    let mut out = Vec::new();
    let mut current: Vec<u16> = Vec::new();
    for unit in units {
        if unit == 0 {
            if !current.is_empty() {
                out.push(String::from_utf16_lossy(&current));
                current.clear();
            }
        } else {
            current.push(unit);
        }
    }
    if !current.is_empty() {
        out.push(String::from_utf16_lossy(&current));
    }
    Ok(out)
}

/// Decodes a `REG_DWORD` payload.
pub fn parse_reg_dword(buf: &[u8]) -> Result<u32, ParseError> {
    if buf.len() < 4 {
        return Err(ParseError(format!(
            "Registry DWORD payload is too short: {} bytes (need 4)",
            buf.len()
        )));
    }
    Ok(u32::from_le_bytes(buf[0..4].try_into().unwrap()))
}

/// Volume root of a Windows path: `C:` for drive-letter paths, or the
/// `\\?\Volume{...}\` prefix for volume-GUID paths. `None` = not a local
/// volume path we can resolve (UNC/relative/unknown), which callers must
/// treat as unreadable rather than as "no disk".
pub fn windows_volume_root(path: &str) -> Option<String> {
    let path = path.trim();
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Some(format!("{}:", path[..1].to_ascii_uppercase()));
    }

    let lowercase = path.to_ascii_lowercase();
    if lowercase.starts_with(r"\\?\volume{") {
        let close = path.find('}')?;
        return Some(format!("{}\\", &path[..=close]));
    }

    // `\??\C:\...` is an NT object-manager path; normalize it.
    if let Some(rest) = path.strip_prefix(r"\??\") {
        return windows_volume_root(rest);
    }

    None
}

/// Normalizes a user-supplied volume selector to the mount-point form that
/// `GetVolumeNameForVolumeMountPointW` expects.
///
/// * `E`, `e:` and `E:\` become `E:\`;
/// * a path below a drive root (`E:\sub\dir`) is kept as a mount-point path
///   (it may be a mount-folder volume; the read-only resolution decides);
/// * a `\\?\Volume{GUID}` path and UNC/other forms get a trailing backslash.
///
/// Pure string work: no resolution and no Win32 call. An empty selector
/// returns an empty string (the caller refuses it).
pub fn windows_mount_root(selector: &str) -> String {
    let selector = selector.trim();
    if selector.is_empty() {
        return String::new();
    }
    let bytes = selector.as_bytes();
    if bytes.len() == 1 && bytes[0].is_ascii_alphabetic() {
        return format!("{}:\\", selector.to_ascii_uppercase());
    }
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let rest = &selector[2..];
        if rest.is_empty() || rest == "\\" {
            return format!("{}:\\", selector[..1].to_ascii_uppercase());
        }
    }
    let mut out = selector.to_string();
    if !out.ends_with('\\') {
        out.push('\\');
    }
    out
}

/// Expands `%SystemRoot%` / `%WINDIR%` / `%SystemDrive%` in a registry path.
/// Other variables are left untouched (the caller then fails to resolve the
/// volume and reports an unreadable fact rather than guessing).
pub fn expand_system_vars(path: &str, system_root: &str, system_drive: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            let replacement =
                if name.eq_ignore_ascii_case("systemroot") || name.eq_ignore_ascii_case("windir") {
                    Some(system_root)
                } else if name.eq_ignore_ascii_case("systemdrive") {
                    Some(system_drive)
                } else {
                    None
                };
            if let Some(value) = replacement {
                out.push_str(value);
                rest = &after[end + 1..];
                continue;
            }
        }
        out.push('%');
        rest = after;
    }
    out.push_str(rest);
    out
}

fn first_path_token(spec: &str) -> &str {
    let spec = spec.trim();
    if let Some(inner) = spec.strip_prefix('"') {
        if let Some(end) = inner.find('"') {
            return &inner[..end];
        }
        return inner;
    }
    spec.split_whitespace().next().unwrap_or("")
}

fn sort_dedup_roots(mut roots: Vec<String>) -> Vec<String> {
    roots.sort();
    roots.dedup();
    roots
}

/// Maps the `PagingFiles` registry entries to volume roots.
///
/// Each entry is a path plus optional initial/maximum sizes
/// (`C:\pagefile.sys 0 0`). `?:\pagefile.sys` means "system managed on the
/// system drive", so it maps to `system_drive`. An entry whose root cannot be
/// resolved is a parse error (fail closed).
pub fn pagefile_volume_roots(
    entries: &[String],
    system_drive: &str,
) -> Result<Vec<String>, ParseError> {
    let mut roots = Vec::new();
    for entry in entries {
        let path = first_path_token(entry);
        if path.is_empty() {
            continue;
        }
        let root = if path.starts_with("?:\\") || path.starts_with("?:/") {
            windows_volume_root(system_drive).ok_or_else(|| {
                ParseError(format!(
                    "Cannot resolve the system drive for page file entry '{}'",
                    entry
                ))
            })?
        } else {
            windows_volume_root(path).ok_or_else(|| {
                ParseError(format!(
                    "Cannot resolve the volume for page file '{}'",
                    entry
                ))
            })?
        };
        roots.push(root);
    }
    Ok(sort_dedup_roots(roots))
}

/// Volume roots that hold the hibernation file. `hiberfil.sys` lives in the
/// root of the system volume, so an enabled hibernation file maps to the
/// system drive; disabled hibernation contributes no disk.
pub fn hibernation_volume_roots(enabled: u32, system_drive: &str) -> Vec<String> {
    if enabled == 0 {
        return Vec::new();
    }
    windows_volume_root(system_drive)
        .map(|root| vec![root])
        .unwrap_or_default()
}

/// Volume roots that hold the configured crash-dump and minidump targets.
///
/// `CrashDumpEnabled == 0` contributes no disk. Otherwise both configured
/// paths are mapped; when neither is configured, Windows' documented default
/// `%SystemRoot%\MEMORY.DMP` is used (TODO-VERIFY on real Windows). A
/// configured path whose volume cannot be resolved is a parse error.
pub fn crash_dump_volume_roots(
    enabled: u32,
    dump_file: Option<&str>,
    minidump_dir: Option<&str>,
    system_root: &str,
    system_drive: &str,
) -> Result<Vec<String>, ParseError> {
    if enabled == 0 {
        return Ok(Vec::new());
    }

    let mut roots = Vec::new();
    let mut saw_configured = false;
    for configured in [dump_file, minidump_dir].into_iter().flatten() {
        if configured.trim().is_empty() {
            continue;
        }
        saw_configured = true;
        let expanded = expand_system_vars(configured, system_root, system_drive);
        let root = windows_volume_root(&expanded).ok_or_else(|| {
            ParseError(format!(
                "Cannot resolve the volume for crash-dump target '{}'",
                configured
            ))
        })?;
        roots.push(root);
    }

    if !saw_configured {
        let root = windows_volume_root(system_root).ok_or_else(|| {
            ParseError(format!(
                "Cannot resolve the system volume '{}' for the default crash dump",
                system_root
            ))
        })?;
        roots.push(root);
    }

    Ok(sort_dedup_roots(roots))
}

// ===========================================================================
// Tests (Runnable on Linux and all platforms)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_device_descriptor_parsing() {
        let mut buf = vec![0u8; 128];
        // Version 36, Size 128
        buf[0..4].copy_from_slice(&36u32.to_le_bytes());
        buf[4..8].copy_from_slice(&128u32.to_le_bytes());
        // Removable = 1
        buf[10] = 1;
        // Offsets
        buf[12..16].copy_from_slice(&36u32.to_le_bytes()); // VendorId
        buf[16..20].copy_from_slice(&48u32.to_le_bytes()); // ProductId
        buf[20..24].copy_from_slice(&64u32.to_le_bytes()); // Revision
        buf[24..28].copy_from_slice(&80u32.to_le_bytes()); // Serial
        buf[28..32].copy_from_slice(&7i32.to_le_bytes()); // BusType = 7 (USB)

        // Strings
        buf[36..46].copy_from_slice(b"SanDisk\0\0\0");
        buf[48..62].copy_from_slice(b"Ultra USB 3.0\0");
        buf[64..68].copy_from_slice(b"1.00");
        buf[80..96].copy_from_slice(b"0123456789ABCDEF");

        let desc = parse_storage_device_descriptor(&buf).unwrap();
        assert!(desc.is_removable);
        assert_eq!(desc.vendor_id.as_deref(), Some("SanDisk"));
        assert_eq!(desc.product_id.as_deref(), Some("Ultra USB 3.0"));
        assert_eq!(desc.model().as_deref(), Some("SanDisk Ultra USB 3.0"));
        assert_eq!(desc.serial_number.as_deref(), Some("0123456789ABCDEF"));
        assert_eq!(desc.transport_str().as_deref(), Some("usb"));
    }

    #[test]
    fn test_storage_device_descriptor_short_buffer_is_rejected() {
        for len in [0usize, 1, 35] {
            let err = parse_storage_device_descriptor(&vec![0u8; len]).unwrap_err();
            assert!(
                err.0.contains("need at least 36"),
                "len {} error was: {}",
                len,
                err
            );
        }
    }

    #[test]
    fn test_seek_penalty_descriptor() {
        // HDD (seek penalty = 1)
        let mut hdd = vec![0u8; 12];
        hdd[8] = 1;
        assert!(parse_seek_penalty_descriptor(&hdd).unwrap());

        // SSD (seek penalty = 0)
        let mut ssd = vec![0u8; 12];
        ssd[8] = 0;
        assert!(!parse_seek_penalty_descriptor(&ssd).unwrap());

        // Truncated buffer
        assert!(parse_seek_penalty_descriptor(&[0u8; 5]).is_err());
    }

    #[test]
    fn test_disk_geometry_ex() {
        let mut buf = vec![0u8; 40];
        // BytesPerSector at offset 20 = 4096
        buf[20..24].copy_from_slice(&4096u32.to_le_bytes());
        // DiskSize at offset 24 = 1_000_204_886_016 (1 TB)
        let size: i64 = 1_000_204_886_016;
        buf[24..32].copy_from_slice(&size.to_le_bytes());

        let geom = parse_disk_geometry_ex(&buf).unwrap();
        assert_eq!(geom.bytes_per_sector, 4096);
        assert_eq!(geom.size_bytes, 1_000_204_886_016);
    }

    #[test]
    fn test_disk_geometry_ex_short_and_negative_size_fixtures() {
        // Short buffer: the fixed DISK_GEOMETRY_EX prefix is 32 bytes.
        assert!(parse_disk_geometry_ex(&[0u8; 31]).is_err());

        // Negative DiskSize is not a valid fact; the parser normalizes it to 0
        // so the backend's fail-closed probe check rejects it.
        let mut negative = vec![0u8; 32];
        negative[20..24].copy_from_slice(&512u32.to_le_bytes());
        negative[24..32].copy_from_slice(&(-1i64).to_le_bytes());
        let geom = parse_disk_geometry_ex(&negative).unwrap();
        assert_eq!(geom.bytes_per_sector, 512);
        assert_eq!(geom.size_bytes, 0);
    }

    #[test]
    fn test_drive_layout_gpt_fixture() {
        // Build a GPT layout buffer with 2 partitions. The fixed header is
        // 48 bytes on x64 (see the offset citation on parse_drive_layout_ex).
        let mut buf = vec![0u8; 48 + 144 * 2];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // PartitionStyle = 1 (GPT)
        buf[4..8].copy_from_slice(&2u32.to_le_bytes()); // PartitionCount = 2

        // Partition 1
        let p1 = &mut buf[48..48 + 144];
        let p1_start: i64 = 2048 * 512;
        let p1_len: i64 = 20969472 * 512;
        p1[8..16].copy_from_slice(&p1_start.to_le_bytes());
        p1[16..24].copy_from_slice(&p1_len.to_le_bytes());
        p1[24..28].copy_from_slice(&1u32.to_le_bytes()); // PartitionNumber = 1
                                                         // Basic data GUID EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
        p1[32..36].copy_from_slice(&0xEBD0A0A2u32.to_le_bytes());
        p1[36..38].copy_from_slice(&0xB9E5u16.to_le_bytes());
        p1[38..40].copy_from_slice(&0x4433u16.to_le_bytes());
        p1[40..48].copy_from_slice(&[0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7]);

        // Partition 2
        let p2 = &mut buf[48 + 144..48 + 288];
        let p2_start: i64 = 20971520 * 512;
        let p2_len: i64 = 20971520 * 512;
        p2[8..16].copy_from_slice(&p2_start.to_le_bytes());
        p2[16..24].copy_from_slice(&p2_len.to_le_bytes());
        p2[24..28].copy_from_slice(&2u32.to_le_bytes()); // PartitionNumber = 2
        p2[32..36].copy_from_slice(&0xC12A7328u32.to_le_bytes()); // ESP GUID
        p2[36..38].copy_from_slice(&0xF81Fu16.to_le_bytes());
        p2[38..40].copy_from_slice(&0x11D2u16.to_le_bytes());
        p2[40..48].copy_from_slice(&[0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B]);

        let layout = parse_drive_layout_ex(&buf).unwrap();
        assert_eq!(layout.style, PartitionStyle::Gpt);
        assert_eq!(layout.partitions.len(), 2);
        assert_eq!(layout.partitions[0].partition_number, 1);
        assert_eq!(layout.partitions[0].start_sector, 2048);
        assert_eq!(layout.partitions[0].size_sectors, 20969472);
        assert_eq!(
            layout.partitions[0].partition_type_guid.as_deref(),
            Some("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")
        );
        assert_eq!(layout.partitions[1].partition_number, 2);
        assert_eq!(layout.partitions[1].start_sector, 20971520);
        assert_eq!(
            layout.partitions[1].partition_type_guid.as_deref(),
            Some("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
        );
    }

    #[test]
    fn test_drive_layout_mbr_fixture_with_used_and_unused_entries() {
        // MBR uses the same 48-byte header + 144-byte entries. Windows reports
        // PartitionCount as a multiple of four, including unused entries.
        let mut buf = vec![0u8; 48 + 144 * 4];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes()); // PartitionStyle = 0 (MBR)
        buf[4..8].copy_from_slice(&4u32.to_le_bytes()); // PartitionCount = 4

        // Entry 1: used FAT32/NTFS-style partition (type 0x07).
        let e1 = &mut buf[48..48 + 144];
        e1[8..16].copy_from_slice(&(2048i64 * 512).to_le_bytes());
        e1[16..24].copy_from_slice(&(20969472i64 * 512).to_le_bytes());
        e1[24..28].copy_from_slice(&1u32.to_le_bytes());
        e1[32] = 0x07; // PARTITION_IFS

        // Entry 2: unused slot (PartitionNumber 0, type 0).
        let e2 = &mut buf[48 + 144..48 + 288];
        e2[8..16].copy_from_slice(&(20971520i64 * 512).to_le_bytes());
        e2[16..24].copy_from_slice(&(1024i64 * 512).to_le_bytes());
        e2[24..28].copy_from_slice(&0u32.to_le_bytes());
        e2[32] = 0x00;

        // Entry 3: used FAT32 partition (type 0x0B).
        let e3 = &mut buf[48 + 288..48 + 432];
        e3[8..16].copy_from_slice(&(20971520i64 * 512).to_le_bytes());
        e3[16..24].copy_from_slice(&(20971520i64 * 512).to_le_bytes());
        e3[24..28].copy_from_slice(&3u32.to_le_bytes());
        e3[32] = 0x0B; // PARTITION_FAT32

        // Entry 4: numbered slot whose type is PARTITION_ENTRY_UNUSED (0).
        let e4 = &mut buf[48 + 432..48 + 576];
        e4[8..16].copy_from_slice(&(41943040i64 * 512).to_le_bytes());
        e4[16..24].copy_from_slice(&(1024i64 * 512).to_le_bytes());
        e4[24..28].copy_from_slice(&4u32.to_le_bytes());
        e4[32] = 0x00;

        let layout = parse_drive_layout_ex(&buf).unwrap();
        assert_eq!(layout.style, PartitionStyle::Mbr);
        assert_eq!(layout.partitions.len(), 2);
        assert_eq!(layout.partitions[0].partition_number, 1);
        assert_eq!(layout.partitions[0].start_sector, 2048);
        assert_eq!(layout.partitions[0].size_sectors, 20969472);
        assert_eq!(layout.partitions[0].partition_type_mbr, Some(0x07));
        assert_eq!(layout.partitions[0].partition_type_guid, None);
        assert_eq!(layout.partitions[1].partition_number, 3);
        assert_eq!(layout.partitions[1].start_sector, 20971520);
        assert_eq!(layout.partitions[1].size_sectors, 20971520);
        assert_eq!(layout.partitions[1].partition_type_mbr, Some(0x0B));
    }

    #[test]
    fn test_drive_layout_gpt_unused_zero_guid_entry_is_skipped() {
        let mut buf = vec![0u8; 48 + 144 * 2];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // GPT
        buf[4..8].copy_from_slice(&2u32.to_le_bytes()); // 2 entries

        let p1 = &mut buf[48..48 + 144];
        p1[8..16].copy_from_slice(&(2048i64 * 512).to_le_bytes());
        p1[16..24].copy_from_slice(&(4096i64 * 512).to_le_bytes());
        p1[24..28].copy_from_slice(&1u32.to_le_bytes());
        p1[32..36].copy_from_slice(&0xC12A7328u32.to_le_bytes());

        // Second slot has a partition number but a zero type GUID: unused.
        let p2 = &mut buf[48 + 144..48 + 288];
        p2[8..16].copy_from_slice(&(6144i64 * 512).to_le_bytes());
        p2[16..24].copy_from_slice(&(4096i64 * 512).to_le_bytes());
        p2[24..28].copy_from_slice(&2u32.to_le_bytes());

        let layout = parse_drive_layout_ex(&buf).unwrap();
        assert_eq!(layout.style, PartitionStyle::Gpt);
        assert_eq!(layout.partitions.len(), 1);
        assert_eq!(layout.partitions[0].partition_number, 1);
    }

    #[test]
    fn test_drive_layout_short_header_is_rejected() {
        let err = parse_drive_layout_ex(&[0u8; 47]).unwrap_err();
        assert!(
            err.0.contains("need at least 48"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_drive_layout_truncated_entries_are_rejected() {
        // Header declares two entries but the buffer only contains one.
        let mut buf = vec![0u8; 48 + 144];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes()); // MBR
        buf[4..8].copy_from_slice(&2u32.to_le_bytes());
        let err = parse_drive_layout_ex(&buf).unwrap_err();
        assert!(
            err.0.contains("Truncated DRIVE_LAYOUT_INFORMATION_EX"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_drive_layout_malformed_header_unknown_style_is_raw() {
        // Unknown style values are reported as Raw (PARTITION_STYLE_RAW
        // semantics) and a zero count yields no partitions instead of panicking.
        let mut buf = vec![0u8; 48];
        buf[0..4].copy_from_slice(&99u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0u32.to_le_bytes());
        let layout = parse_drive_layout_ex(&buf).unwrap();
        assert_eq!(layout.style, PartitionStyle::Raw);
        assert!(layout.partitions.is_empty());
    }

    #[test]
    fn test_volume_disk_extents() {
        let mut buf = vec![0u8; 8 + 24 * 2];
        buf[0..4].copy_from_slice(&2u32.to_le_bytes()); // 2 extents (multi-extent)

        // Extent 1: Disk 1, offset 1048576, len 500000000
        let e1 = &mut buf[8..32];
        e1[0..4].copy_from_slice(&1u32.to_le_bytes());
        e1[8..16].copy_from_slice(&1048576i64.to_le_bytes());
        e1[16..24].copy_from_slice(&500000000i64.to_le_bytes());

        // Extent 2: Disk 2, offset 2097152, len 500000000
        let e2 = &mut buf[32..56];
        e2[0..4].copy_from_slice(&2u32.to_le_bytes());
        e2[8..16].copy_from_slice(&2097152i64.to_le_bytes());
        e2[16..24].copy_from_slice(&500000000i64.to_le_bytes());

        let res = parse_volume_disk_extents(&buf).unwrap();
        assert!(res.is_multi_extent);
        assert_eq!(res.extents.len(), 2);
        assert_eq!(res.extents[0].disk_number, 1);
        assert_eq!(res.extents[0].starting_offset, 1048576);
    }

    #[test]
    fn test_volume_disk_extents_single_extent_fixture() {
        let mut buf = vec![0u8; 8 + 24];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        let e1 = &mut buf[8..32];
        e1[0..4].copy_from_slice(&0u32.to_le_bytes());
        e1[8..16].copy_from_slice(&(2048i64 * 512).to_le_bytes());
        e1[16..24].copy_from_slice(&(4096i64 * 512).to_le_bytes());

        let res = parse_volume_disk_extents(&buf).unwrap();
        assert!(!res.is_multi_extent);
        assert_eq!(res.extents.len(), 1);
        assert_eq!(res.extents[0].disk_number, 0);
        assert_eq!(res.extents[0].starting_offset, 2048 * 512);
        assert_eq!(res.extents[0].extent_length, 4096 * 512);
    }

    #[test]
    fn test_volume_disk_extents_zero_count_is_not_multi_extent() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        let res = parse_volume_disk_extents(&buf).unwrap();
        assert!(!res.is_multi_extent);
        assert!(res.extents.is_empty());
    }

    #[test]
    fn test_volume_disk_extents_short_and_truncated_buffers_are_rejected() {
        assert!(parse_volume_disk_extents(&[0u8; 7]).is_err());

        // Header declares two extents but only one is present.
        let mut truncated = vec![0u8; 8 + 24];
        truncated[0..4].copy_from_slice(&2u32.to_le_bytes());
        let err = parse_volume_disk_extents(&truncated).unwrap_err();
        assert!(
            err.0.contains("Truncated VOLUME_DISK_EXTENTS"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_bitlocker_detection() {
        let mut encrypted_vbr = vec![0u8; 512];
        encrypted_vbr[3..11].copy_from_slice(b"-FVE-FS-");
        assert_eq!(detect_bitlocker(&encrypted_vbr), BitLockerStatus::Encrypted);

        let mut normal_ntfs_vbr = vec![0u8; 512];
        normal_ntfs_vbr[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(
            detect_bitlocker(&normal_ntfs_vbr),
            BitLockerStatus::NotEncrypted
        );

        let short_buf = vec![0u8; 5];
        assert!(matches!(
            detect_bitlocker(&short_buf),
            BitLockerStatus::Unknown(_)
        ));
    }

    #[test]
    fn test_partition_fingerprint_matches_shared_test_vector() {
        // Using the exact shared test vector:
        // Partition 1: start sector 2048, size sectors 20969472
        // Partition 2: start sector 20971520, size sectors 20971520
        // Partition 3: start sector 41943040, size sectors 19496960
        // Expected hash: 8c4efb1b4866d0b332ebef624e1ba8cff76427c143b08a4f1199e6ee81279580
        let partitions = vec![
            ParsedPartition {
                partition_number: 3,
                starting_offset: 41943040 * 512,
                partition_length: 19496960 * 512,
                start_sector: 41943040,
                size_sectors: 19496960,
                partition_type_guid: None,
                partition_type_mbr: None,
            },
            ParsedPartition {
                partition_number: 1,
                starting_offset: 2048 * 512,
                partition_length: 20969472 * 512,
                start_sector: 2048,
                size_sectors: 20969472,
                partition_type_guid: None,
                partition_type_mbr: None,
            },
            ParsedPartition {
                partition_number: 2,
                starting_offset: 20971520 * 512,
                partition_length: 20971520 * 512,
                start_sector: 20971520,
                size_sectors: 20971520,
                partition_type_guid: None,
                partition_type_mbr: None,
            },
        ];

        let fp = compute_windows_partition_fingerprint(&partitions);
        assert_eq!(
            fp,
            "8c4efb1b4866d0b332ebef624e1ba8cff76427c143b08a4f1199e6ee81279580"
        );
    }

    // -----------------------------------------------------------------------
    // D-a piece 2: boot/system fact parsers and decision helpers.
    // -----------------------------------------------------------------------

    fn utf16_bytes(values: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for value in values {
            for unit in value.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        if values.is_empty() {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        out
    }

    #[test]
    fn test_parse_reg_multi_sz_pagefile_fixture() {
        let payload = utf16_bytes(&[r"C:\pagefile.sys 0 0", r"D:\pagefile.sys 0 0"]);
        let values = parse_reg_multi_sz(&payload).unwrap();
        assert_eq!(values, vec!["C:\\pagefile.sys 0 0", "D:\\pagefile.sys 0 0"]);
    }

    #[test]
    fn test_parse_reg_multi_sz_odd_length_and_empty_are_typed() {
        assert!(parse_reg_multi_sz(&[0u8; 3]).is_err());
        let empty = parse_reg_multi_sz(&utf16_bytes(&[])).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_parse_reg_sz_and_dword_fixtures() {
        let sz = utf16_bytes(&[r"C:\Windows"]);
        assert_eq!(parse_reg_sz(&sz).unwrap(), r"C:\Windows");
        let dword = 7u32.to_le_bytes();
        assert_eq!(parse_reg_dword(&dword).unwrap(), 7);
        assert!(parse_reg_dword(&[1, 2, 3]).is_err());
    }

    #[test]
    fn test_windows_volume_root_paths() {
        assert_eq!(
            windows_volume_root(r"c:\Windows\System32").as_deref(),
            Some("C:")
        );
        assert_eq!(
            windows_volume_root(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Windows")
                .as_deref(),
            Some(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\")
        );
        assert_eq!(windows_volume_root(r"\??\D:\data").as_deref(), Some("D:"));
        assert_eq!(windows_volume_root(r"\\server\share\file"), None);
        assert_eq!(windows_volume_root("relative\\path"), None);
    }

    #[test]
    fn test_expand_system_vars_only_expands_known_variables() {
        assert_eq!(
            expand_system_vars(r"%SystemRoot%\MEMORY.DMP", r"C:\Windows", "C:"),
            r"C:\Windows\MEMORY.DMP"
        );
        assert_eq!(
            expand_system_vars(r"%systemdrive%\hiberfil.sys", r"C:\Windows", "C:"),
            r"C:\hiberfil.sys"
        );
        assert_eq!(
            expand_system_vars(r"%UNKNOWN%\%SystemDrive%\x", r"C:\Windows", "C:"),
            r"%UNKNOWN%\C:\x"
        );
    }

    #[test]
    fn test_windows_mount_root_normalizes_volume_selectors() {
        assert_eq!(windows_mount_root("E"), r"E:\");
        assert_eq!(windows_mount_root("e"), r"E:\");
        assert_eq!(windows_mount_root("E:"), r"E:\");
        assert_eq!(windows_mount_root(r"E:\"), r"E:\");
        assert_eq!(windows_mount_root("  e:  "), r"E:\");
        assert_eq!(windows_mount_root(r"E:\sub\dir"), r"E:\sub\dir\");
        assert_eq!(
            windows_mount_root(r"\\?\Volume{11111111-1111-1111-1111-111111111111}"),
            r"\\?\Volume{11111111-1111-1111-1111-111111111111}\"
        );
        assert_eq!(
            windows_mount_root(r"\\?\Volume{11111111-1111-1111-1111-111111111111}\"),
            r"\\?\Volume{11111111-1111-1111-1111-111111111111}\"
        );
        assert_eq!(windows_mount_root(r"\\server\share"), r"\\server\share\");
        assert_eq!(windows_mount_root(""), "");
        assert_eq!(windows_mount_root("   "), "");
    }

    #[test]
    fn test_pagefile_volume_roots_handles_system_managed_entries() {
        let entries = vec![
            r"C:\pagefile.sys 0 0".to_string(),
            r"?:\pagefile.sys".to_string(),
            r#""D:\pagefile.sys" 1024 2048"#.to_string(),
        ];
        let roots = pagefile_volume_roots(&entries, "C:").unwrap();
        assert_eq!(roots, vec!["C:".to_string(), "D:".to_string()]);
    }

    #[test]
    fn test_pagefile_volume_roots_unknown_path_is_typed() {
        let entries = vec![r"\\server\share\pagefile.sys 0 0".to_string()];
        assert!(pagefile_volume_roots(&entries, "C:").is_err());
    }

    #[test]
    fn test_hibernation_volume_roots() {
        assert_eq!(hibernation_volume_roots(1, "c:"), vec!["C:".to_string()]);
        assert!(hibernation_volume_roots(0, "C:").is_empty());
    }

    #[test]
    fn test_crash_dump_volume_roots_fixtures() {
        // Enabled with a configured DumpFile on another volume.
        let roots =
            crash_dump_volume_roots(2, Some(r"D:\dumps\MEMORY.DMP"), None, r"C:\Windows", "C:")
                .unwrap();
        assert_eq!(roots, vec!["D:".to_string()]);

        // Enabled with %SystemRoot% expansion.
        let roots = crash_dump_volume_roots(
            7,
            Some(r"%SystemRoot%\MEMORY.DMP"),
            None,
            r"C:\Windows",
            "C:",
        )
        .unwrap();
        assert_eq!(roots, vec!["C:".to_string()]);

        // Enabled but unconfigured: Windows' default lives on the system volume.
        let roots = crash_dump_volume_roots(7, None, None, r"C:\Windows", "C:").unwrap();
        assert_eq!(roots, vec!["C:".to_string()]);

        // Disabled contributes no disk.
        assert!(
            crash_dump_volume_roots(0, Some(r"D:\dump.dmp"), None, r"C:\Windows", "C:")
                .unwrap()
                .is_empty()
        );

        // Configured but unresolvable is a typed error, never silently empty.
        assert!(crash_dump_volume_roots(
            2,
            Some(r"\\server\share\dump.dmp"),
            None,
            r"C:\Windows",
            "C:"
        )
        .is_err());
    }

    // -----------------------------------------------------------------
    // Step 1.2: read-only volume facts
    // -----------------------------------------------------------------

    #[test]
    fn test_parse_volume_path_names_multi_sz() {
        // "C:\\\0D:\\\0\0" (UTF-16), trailing metadata bytes ignored.
        let units: Vec<u16> = "C:\\"
            .encode_utf16()
            .chain(std::iter::once(0))
            .chain("D:\\".encode_utf16())
            .chain(std::iter::once(0))
            .chain(std::iter::once(0))
            .chain([0x77, 0x88])
            .collect();
        assert_eq!(
            parse_volume_path_names(&units),
            vec!["C:\\".to_string(), "D:\\".to_string()]
        );

        // Empty list (only the double-NUL terminator).
        assert!(parse_volume_path_names(&[0, 0, 0]).is_empty());
        assert!(parse_volume_path_names(&[]).is_empty());

        // Unterminated tail is ignored rather than guessed.
        let unterminated: Vec<u16> = "E:\\".encode_utf16().collect();
        assert!(parse_volume_path_names(&unterminated).is_empty());
    }

    #[test]
    fn test_drive_letters_from_mount_points() {
        let points = vec![
            r"E:\".to_string(),
            r"F:\".to_string(),
            r"E:\".to_string(),              // duplicate
            r"\\?\Volume{abc}\".to_string(), // volume path contributes none
            r"C:\Mount\Data\".to_string(),   // mount-folder path contributes none
            r"\\server\share".to_string(),   // UNC contributes none
            "g:".to_string(),                // lower-case, no trailing slash
        ];
        assert_eq!(
            drive_letters_from_mount_points(&points),
            vec!['E', 'F', 'G']
        );
        assert!(drive_letters_from_mount_points(&[]).is_empty());
    }

    #[test]
    fn test_classify_drive_type() {
        assert_eq!(classify_drive_type(2), VolumeDriveType::Removable);
        assert_eq!(classify_drive_type(3), VolumeDriveType::Fixed);
        assert_eq!(classify_drive_type(4), VolumeDriveType::Remote);
        assert_eq!(classify_drive_type(5), VolumeDriveType::CdRom);
        assert_eq!(classify_drive_type(6), VolumeDriveType::RamDisk);
        assert_eq!(classify_drive_type(1), VolumeDriveType::NoRootDir);
        assert_eq!(classify_drive_type(0), VolumeDriveType::Unknown);
        // Unknown values are preserved, never mapped to a default.
        assert_eq!(classify_drive_type(42), VolumeDriveType::Other(42));
        assert!(classify_drive_type(2).is_removable());
        assert!(classify_drive_type(3).is_fixed());
    }

    #[test]
    fn test_is_multi_extent() {
        assert!(!is_multi_extent(0));
        assert!(!is_multi_extent(1));
        assert!(is_multi_extent(2));
        assert!(is_multi_extent(17));
    }

    /// GPT layout fixture with three partitions, matching the offsets used by
    /// `parse_drive_layout_ex` (48-byte header, 144-byte entries).
    fn layout_fixture() -> Vec<u8> {
        let mut buf = vec![0u8; 48 + 144 * 3];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // PartitionStyle = GPT
        buf[4..8].copy_from_slice(&3u32.to_le_bytes()); // PartitionCount = 3

        for (idx, (number, start_bytes)) in [
            (1u32, 1_048_576u64),
            (2u32, 20_971_520u64),
            (3u32, 41_943_040u64),
        ]
        .iter()
        .enumerate()
        {
            let entry = &mut buf[48 + idx * 144..48 + (idx + 1) * 144];
            entry[8..16].copy_from_slice(&(*start_bytes as i64).to_le_bytes());
            entry[16..24].copy_from_slice(&(1_048_576i64).to_le_bytes());
            entry[24..28].copy_from_slice(&number.to_le_bytes());
            // Basic data GUID EBD0A0A2-B9E5-4433-87C0-68B6B72699C7 (a zero
            // GUID marks an unused table entry and is skipped by the parser).
            entry[32..36].copy_from_slice(&0xEBD0A0A2u32.to_le_bytes());
            entry[36..38].copy_from_slice(&0xB9E5u16.to_le_bytes());
            entry[38..40].copy_from_slice(&0x4433u16.to_le_bytes());
            entry[40..48].copy_from_slice(&[0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7]);
        }
        buf
    }

    #[test]
    fn test_find_partition_for_extent() {
        let layout = parse_drive_layout_ex(&layout_fixture()).unwrap();
        assert_eq!(find_partition_for_extent(&layout, 1_048_576), Some(1));
        assert_eq!(find_partition_for_extent(&layout, 20_971_520), Some(2));
        assert_eq!(find_partition_for_extent(&layout, 41_943_040), Some(3));
        // A readable layout with no partition at the extent offset is a fact.
        assert_eq!(find_partition_for_extent(&layout, 123_456), None);
    }

    #[test]
    fn test_partition_container() {
        assert_eq!(
            partition_container(
                PartitionStyle::Gpt,
                Some("de94bba4-06d1-4d40-a16a-bfd50179d6ac"),
                None
            ),
            PartitionContainer::GptBitLocker
        );
        assert_eq!(
            partition_container(
                PartitionStyle::Gpt,
                Some("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"),
                None
            ),
            PartitionContainer::GptOther
        );
        assert_eq!(
            partition_container(PartitionStyle::Gpt, None, None),
            PartitionContainer::Unknown
        );
        assert_eq!(
            partition_container(PartitionStyle::Mbr, None, Some(0x07)),
            PartitionContainer::Mbr(0x07)
        );
        assert_eq!(
            partition_container(PartitionStyle::Mbr, None, None),
            PartitionContainer::Unknown
        );
        assert_eq!(
            partition_container(PartitionStyle::Raw, None, None),
            PartitionContainer::Unknown
        );
    }

    fn partition_fixture(guid: Option<&str>, mbr: Option<u8>) -> ParsedPartition {
        ParsedPartition {
            partition_number: 1,
            starting_offset: 1_048_576,
            partition_length: 32_000_000_000,
            start_sector: 2048,
            size_sectors: 62_500_000,
            partition_type_guid: guid.map(str::to_string),
            partition_type_mbr: mbr,
        }
    }

    fn layout_with(partition: ParsedPartition) -> ParsedDriveLayout {
        ParsedDriveLayout {
            style: if partition.partition_type_guid.is_some() {
                PartitionStyle::Gpt
            } else {
                PartitionStyle::Mbr
            },
            partitions: vec![partition],
        }
    }

    #[test]
    fn test_layout_is_dynamic_detects_ldm_and_storage_spaces() {
        // Basic GPT data partition: not dynamic.
        let basic = layout_with(partition_fixture(
            Some("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"),
            None,
        ));
        assert!(!layout_is_dynamic(&basic));

        // GPT LDM metadata / data and Storage Spaces types.
        for guid in [
            GPT_LDM_METADATA_GUID,
            GPT_LDM_DATA_GUID,
            GPT_STORAGE_SPACES_GUID,
        ] {
            let layout = layout_with(partition_fixture(Some(guid), None));
            assert!(
                layout_is_dynamic(&layout),
                "GPT type {} must be dynamic",
                guid
            );
            assert!(partition_is_dynamic(&layout.partitions[0]));
        }

        // Case-insensitive GUID match.
        let lower_guid = GPT_LDM_DATA_GUID.to_ascii_lowercase();
        let lower = layout_with(partition_fixture(Some(&lower_guid), None));
        assert!(layout_is_dynamic(&lower));

        // MBR dynamic-disk container type 0x42.
        let mbr_dynamic = layout_with(partition_fixture(None, Some(0x42)));
        assert!(layout_is_dynamic(&mbr_dynamic));

        // Basic MBR NTFS is not dynamic.
        let mbr_basic = layout_with(partition_fixture(None, Some(0x07)));
        assert!(!layout_is_dynamic(&mbr_basic));

        // Empty and Raw layouts are not flagged as dynamic (the guard refuses
        // them separately as non-basic).
        assert!(!layout_is_dynamic(&ParsedDriveLayout {
            style: PartitionStyle::Raw,
            partitions: Vec::new(),
        }));
    }

    #[test]
    fn test_bitlocker_gpt_container_is_locked_when_filesystem_is_not_ready() {
        for code in BITLOCKER_LOCKED_FS_ERRORS {
            let assessment =
                classify_bitlocker(PartitionContainer::GptBitLocker, Err(code), Err(code));
            assert_eq!(assessment.encrypted, Some(true));
            assert_eq!(assessment.state, BitLockerLockState::Locked);
            assert!(assessment.state.treated_as_locked());
        }
    }

    #[test]
    fn test_bitlocker_gpt_container_is_unlocked_when_filesystem_is_readable() {
        let assessment = classify_bitlocker(
            PartitionContainer::GptBitLocker,
            Ok(BitLockerStatus::Encrypted),
            Ok(Some("NTFS")),
        );
        assert_eq!(assessment.encrypted, Some(true));
        assert_eq!(assessment.state, BitLockerLockState::Unlocked);
        assert!(!assessment.state.treated_as_locked());
        assert_eq!(assessment.state.is_encrypted(), Some(true));
    }

    #[test]
    fn test_bitlocker_unexpected_filesystem_error_is_unknown_not_unlocked() {
        let assessment = classify_bitlocker(
            PartitionContainer::GptBitLocker,
            Ok(BitLockerStatus::Encrypted),
            Err(87), // ERROR_INVALID_PARAMETER — not a lock signal
        );
        assert_eq!(assessment.encrypted, Some(true));
        assert!(matches!(assessment.state, BitLockerLockState::Unknown(_)));
        assert!(assessment.state.treated_as_locked());
    }

    #[test]
    fn test_bitlocker_empty_filesystem_name_is_unknown() {
        for filesystem in [Ok(None), Ok(Some("")), Ok(Some("   "))] {
            let assessment = classify_bitlocker(
                PartitionContainer::GptBitLocker,
                Ok(BitLockerStatus::Encrypted),
                filesystem,
            );
            assert!(
                matches!(assessment.state, BitLockerLockState::Unknown(_)),
                "state was {:?}",
                assessment.state
            );
        }
    }

    #[test]
    fn test_bitlocker_not_encrypted_is_conclusive_from_gpt_type() {
        // GPT basic-data type is authoritative even when the header read fails.
        let assessment = classify_bitlocker(PartitionContainer::GptOther, Err(5), Ok(Some("NTFS")));
        assert_eq!(assessment.encrypted, Some(false));
        assert_eq!(assessment.state, BitLockerLockState::NotEncrypted);
        assert!(!assessment.state.treated_as_locked());
        assert_eq!(assessment.state.is_encrypted(), Some(false));
    }

    #[test]
    fn test_bitlocker_mbr_0x07_requires_a_readable_header() {
        // Unreadable header: cannot rule BitLocker To Go out -> Unknown.
        let unknown = classify_bitlocker(PartitionContainer::Mbr(0x07), Err(21), Ok(Some("NTFS")));
        assert!(matches!(unknown.state, BitLockerLockState::Unknown(_)));
        assert!(unknown.state.treated_as_locked());

        // Readable header without the FVE signature -> conclusively not encrypted.
        let plain = classify_bitlocker(
            PartitionContainer::Mbr(0x07),
            Ok(BitLockerStatus::NotEncrypted),
            Ok(Some("NTFS")),
        );
        assert_eq!(plain.encrypted, Some(false));
        assert_eq!(plain.state, BitLockerLockState::NotEncrypted);

        // Readable FVE header -> encrypted; filesystem decides locked/unlocked.
        let locked = classify_bitlocker(
            PartitionContainer::Mbr(0x07),
            Ok(BitLockerStatus::Encrypted),
            Err(21),
        );
        assert_eq!(locked.state, BitLockerLockState::Locked);

        // Another MBR type cannot be a BitLocker container.
        let fat = classify_bitlocker(PartitionContainer::Mbr(0x0c), Err(5), Ok(Some("FAT32")));
        assert_eq!(fat.encrypted, Some(false));
    }

    #[test]
    fn test_bitlocker_signature_overrides_mbr_non_07_type() {
        // Defensive: a readable FVE header wins over an unexpected MBR type.
        let assessment = classify_bitlocker(
            PartitionContainer::Mbr(0x83),
            Ok(BitLockerStatus::Encrypted),
            Err(21),
        );
        assert_eq!(assessment.state, BitLockerLockState::Locked);
    }

    #[test]
    fn test_bitlocker_unknown_container_and_header_stays_unknown() {
        let assessment = classify_bitlocker(
            PartitionContainer::Unknown,
            Ok(BitLockerStatus::Unknown("short read".to_string())),
            Ok(Some("NTFS")),
        );
        assert_eq!(assessment.encrypted, None);
        assert!(matches!(assessment.state, BitLockerLockState::Unknown(_)));
        assert!(assessment.state.treated_as_locked());

        let no_header = classify_bitlocker(PartitionContainer::Unknown, Err(5), Err(5));
        match no_header.state {
            BitLockerLockState::Unknown(reason) => {
                assert!(reason.contains("Win32 error 5"), "reason: {}", reason)
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn test_volume_guid_eq_normalizes_case_and_trailing_slash() {
        assert!(volume_guid_eq(
            r"\\?\Volume{01234567-89AB-CDEF-0123-456789ABCDEF}\",
            r"\\?\volume{01234567-89ab-cdef-0123-456789abcdef}"
        ));
        assert!(!volume_guid_eq(
            r"\\?\Volume{01234567-89AB-CDEF-0123-456789ABCDEF}\",
            r"\\?\Volume{FFFFFFFF-89AB-CDEF-0123-456789ABCDEF}\"
        ));
        // An empty candidate never matches (fail closed, not "matches nothing to protect").
        assert!(!volume_guid_eq(r"\\?\Volume{abc}\", ""));
    }

    #[test]
    fn test_volume_guid_matches_any() {
        let system = vec![r"\\?\Volume{AAA}\".to_string()];
        assert!(volume_guid_matches_any(r"\\?\volume{aaa}", &system));
        assert!(!volume_guid_matches_any(r"\\?\Volume{BBB}\", &system));
        assert!(!volume_guid_matches_any(r"\\?\Volume{AAA}\", &[]));
    }
}
