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

use std::fmt;
use sha2::{Digest, Sha256};

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
    // STORAGE_DEVICE_DESCRIPTOR minimum fixed header size is 36 bytes.
    if buf.len() < 36 {
        return Err(ParseError(format!(
            "Buffer too short for STORAGE_DEVICE_DESCRIPTOR: {} bytes (need at least 36)",
            buf.len()
        )));
    }

    let is_removable = buf[10] != 0;
    let vendor_id_offset = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
    let product_id_offset = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    let product_rev_offset = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
    let serial_num_offset = u32::from_le_bytes(buf[24..28].try_into().unwrap()) as usize;
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
    // DEVICE_SEEK_PENALTY_DESCRIPTOR: Version (4), Size (4), IncursSeekPenalty (1)
    if buf.len() < 9 {
        return Err(ParseError(format!(
            "Buffer too short for DEVICE_SEEK_PENALTY_DESCRIPTOR: {} bytes (need at least 9)",
            buf.len()
        )));
    }
    // IncursSeekPenalty != 0 indicates rotational HDD. False indicates SSD.
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
    // DISK_GEOMETRY_EX:
    // Geometry: Cylinders (8), MediaType (4), TracksPerCylinder (4), SectorsPerTrack (4), BytesPerSector (4) = 24
    // DiskSize: i64 (8) = 32
    if buf.len() < 32 {
        return Err(ParseError(format!(
            "Buffer too short for DISK_GEOMETRY_EX: {} bytes (need at least 32)",
            buf.len()
        )));
    }

    let bytes_per_sector = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    let disk_size = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    let size_bytes = if disk_size < 0 { 0 } else { disk_size as u64 };

    Ok(ParsedGeometry {
        size_bytes,
        bytes_per_sector: if bytes_per_sector == 0 { 512 } else { bytes_per_sector },
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
    let d1 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let d2 = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    let d3 = u16::from_le_bytes(buf[6..8].try_into().unwrap());
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1, d2, d3, buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
    )
}

pub fn parse_drive_layout_ex(buf: &[u8]) -> Result<ParsedDriveLayout, ParseError> {
    // DRIVE_LAYOUT_INFORMATION_EX on 64-bit Windows:
    // PartitionStyle (u32, 4)
    // PartitionCount (u32, 4)
    // Anonymous union (48 bytes, aligned to 8)
    // PartitionEntry[1] starts at offset 56.
    // Each PARTITION_INFORMATION_EX entry is 144 bytes.
    const HEADER_SIZE: usize = 56;
    const ENTRY_SIZE: usize = 144;

    if buf.len() < HEADER_SIZE {
        return Err(ParseError(format!(
            "Buffer too short for DRIVE_LAYOUT_INFORMATION_EX: {} bytes (need at least 56)",
            buf.len()
        )));
    }

    let raw_style = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let partition_count = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;

    let style = match raw_style {
        0 => PartitionStyle::Mbr,
        1 => PartitionStyle::Gpt,
        _ => PartitionStyle::Raw,
    };

    let mut partitions = Vec::new();
    let mut offset = HEADER_SIZE;

    for _ in 0..partition_count {
        if offset + ENTRY_SIZE > buf.len() {
            break;
        }

        let entry = &buf[offset..offset + ENTRY_SIZE];
        let starting_offset_raw = i64::from_le_bytes(entry[8..16].try_into().unwrap());
        let partition_length_raw = i64::from_le_bytes(entry[16..24].try_into().unwrap());
        let partition_number = u32::from_le_bytes(entry[24..28].try_into().unwrap());

        // In both MBR and GPT, partition_number 0 indicates an unused table entry
        if partition_number > 0 && starting_offset_raw >= 0 && partition_length_raw > 0 {
            let starting_offset = starting_offset_raw as u64;
            let partition_length = partition_length_raw as u64;
            let start_sector = starting_offset / 512;
            let size_sectors = partition_length / 512;

            let (type_guid, mbr_type) = match style {
                PartitionStyle::Gpt => {
                    let guid_bytes = &entry[32..48];
                    // Skip empty/zero GUID partition entries
                    if guid_bytes.iter().all(|&b| b == 0) {
                        offset += ENTRY_SIZE;
                        continue;
                    }
                    (Some(format_guid_le(guid_bytes)), None)
                }
                PartitionStyle::Mbr => {
                    let ptype = entry[32];
                    // Skip empty partition type (0)
                    if ptype == 0 {
                        offset += ENTRY_SIZE;
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

        offset += ENTRY_SIZE;
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
    // VOLUME_DISK_EXTENTS on 64-bit Windows:
    // NumberOfDiskExtents (u32, 4 bytes)
    // 4 bytes padding
    // Extents start at offset 8.
    // Each DISK_EXTENT is 24 bytes:
    // DiskNumber (u32, 4)
    // 4 bytes padding
    // StartingOffset (i64, 8)
    // ExtentLength (i64, 8)
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
        if offset + EXTENT_SIZE > buf.len() {
            break;
        }

        let extent_bytes = &buf[offset..offset + EXTENT_SIZE];
        let disk_number = u32::from_le_bytes(extent_bytes[0..4].try_into().unwrap());
        let starting_offset_raw = i64::from_le_bytes(extent_bytes[8..16].try_into().unwrap());
        let extent_length_raw = i64::from_le_bytes(extent_bytes[16..24].try_into().unwrap());

        extents.push(ParsedExtent {
            disk_number,
            starting_offset: if starting_offset_raw < 0 { 0 } else { starting_offset_raw as u64 },
            extent_length: if extent_length_raw < 0 { 0 } else { extent_length_raw as u64 },
        });

        offset += EXTENT_SIZE;
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
// 7. Layout Fingerprint (matching Linux canonical format)
// ---------------------------------------------------------------------------

/// Computes SHA-256 partition table fingerprint matching the Linux format:
/// Sorted `"num:start:size\n"` in 512-byte sectors.
pub fn compute_windows_partition_fingerprint(partitions: &[ParsedPartition]) -> String {
    let mut sorted = partitions.to_vec();
    sorted.sort_by_key(|p| p.partition_number);

    let mut canonical = String::new();
    for p in &sorted {
        canonical.push_str(&format!("{}:{}:{}\n", p.partition_number, p.start_sector, p.size_sectors));
    }

    let hash = Sha256::digest(canonical.as_bytes());
    format!("{:x}", hash)
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
        buf[28..32].copy_from_slice(&7i32.to_le_bytes());  // BusType = 7 (USB)

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
    fn test_drive_layout_gpt_and_mbr() {
        // Build mock GPT layout buffer with 2 partitions
        let mut buf = vec![0u8; 56 + 144 * 2];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // PartitionStyle = 1 (GPT)
        buf[4..8].copy_from_slice(&2u32.to_le_bytes()); // PartitionCount = 2

        // Partition 1
        let p1 = &mut buf[56..56 + 144];
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
        let p2 = &mut buf[56 + 144..56 + 288];
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
    fn test_bitlocker_detection() {
        let mut encrypted_vbr = vec![0u8; 512];
        encrypted_vbr[3..11].copy_from_slice(b"-FVE-FS-");
        assert_eq!(detect_bitlocker(&encrypted_vbr), BitLockerStatus::Encrypted);

        let mut normal_ntfs_vbr = vec![0u8; 512];
        normal_ntfs_vbr[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(detect_bitlocker(&normal_ntfs_vbr), BitLockerStatus::NotEncrypted);

        let short_buf = vec![0u8; 5];
        assert!(matches!(detect_bitlocker(&short_buf), BitLockerStatus::Unknown(_)));
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
}
