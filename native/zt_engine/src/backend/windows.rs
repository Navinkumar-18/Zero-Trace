//! Windows BlockBackend implementation (Phase D-a, piece 1 — read-only facts).
//!
//! Hard rules (Phase D-a):
//! - Every disk and volume handle is opened with `dwDesiredAccess = 0` or `FILE_READ_ATTRIBUTES` only.
//!   Zero write access is ever requested.
//! - Every destructive / write operation returns `BackendError::Unsupported`.
//! - Pure byte parsing is delegated to `crate::backend::windows_parse`.
//! - PhysicalDrive0..63 scan: not-found = absent; access-denied or any other error = typed error, never skipped.

#[cfg(not(target_os = "windows"))]
pub use crate::backend::unsupported::UnsupportedBackend as WindowsBackend;

#[cfg(not(target_os = "windows"))]
pub fn windows_backend() -> WindowsBackend {
    crate::backend::unsupported::UnsupportedBackend::new("windows", "windows")
}

#[cfg(target_os = "windows")]
pub use windows_impl::{windows_backend, WindowsBackend};

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::HashMap;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES,
        ERROR_PATH_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationW,
        GetVolumePathNamesForVolumeNameW, FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        PropertyStandardQuery, StorageDeviceProperty, StorageDeviceSeekPenaltyProperty,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROPERTY_QUERY,
    };

    use crate::backend::windows_parse::{
        parse_disk_geometry_ex, parse_drive_layout_ex, parse_seek_penalty_descriptor,
        parse_storage_device_descriptor, parse_volume_disk_extents,
    };
    use crate::backend::{
        BackendCapabilities, BackendError, BlockBackend, DeviceGeometry, DeviceInfo,
        ExclusiveHandle, MountState, PartitionFacts, Relation, StatFact,
    };
    use crate::guard::ValidatedTarget;
    use crate::types::{BootEnvironment, ExecuteError};

    /// Scoped RAII handle wrapper ensuring `CloseHandle` is always called.
    struct ScopedHandle(HANDLE);

    impl ScopedHandle {
        fn new(h: HANDLE) -> Option<Self> {
            if h == INVALID_HANDLE_VALUE || h.is_null() {
                None
            } else {
                Some(Self(h))
            }
        }

        fn get(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for ScopedHandle {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    /// Converts a Rust string slice to a null-terminated UTF-16 vector.
    fn to_wide_null(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Read-only open helper: `dwDesiredAccess = 0` (FILE_ANY_ACCESS) or `FILE_READ_ATTRIBUTES`.
    /// Never uses `GENERIC_WRITE` or `GENERIC_READ`.
    fn open_read_only_handle(path: &str, access_attributes_only: bool) -> Result<ScopedHandle, BackendError> {
        let wide = to_wide_null(path);
        // dwDesiredAccess: 0 allows query IOCTLs; FILE_READ_ATTRIBUTES allows querying volume metadata.
        let access = if access_attributes_only {
            FILE_READ_ATTRIBUTES
        } else {
            0
        };

        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0 as FILE_FLAGS_AND_ATTRIBUTES,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
                return Err(BackendError::Unavailable(format!("Device not found: {}", path)));
            } else if err == ERROR_ACCESS_DENIED {
                return Err(BackendError::Io(format!(
                    "Access denied opening {} (Win32 error {})",
                    path, err
                )));
            } else {
                return Err(BackendError::Io(format!(
                    "Failed to open {} (Win32 error {})",
                    path, err
                )));
            }
        }

        ScopedHandle::new(handle)
            .ok_or_else(|| BackendError::Io(format!("Invalid handle for {}", path)))
    }

    #[derive(Debug, Default)]
    pub struct WindowsBackend;

    pub fn windows_backend() -> WindowsBackend {
        WindowsBackend
    }

    impl BlockBackend for WindowsBackend {
        fn name(&self) -> &'static str {
            "windows"
        }

        fn platform(&self) -> &'static str {
            "windows"
        }

        fn capabilities(&self) -> BackendCapabilities {
            // Read-only discovery facts; all write/wipe capabilities disabled.
            BackendCapabilities::unsupported()
        }

        // -- Discovery ---------------------------------------------------------

        fn enumerate_devices(&self) -> Result<Vec<DeviceInfo>, BackendError> {
            let mut devices = Vec::new();

            // Scan PhysicalDrive0..63
            for i in 0..64 {
                let path = format!(r"\\.\PhysicalDrive{}", i);
                let wide = to_wide_null(&path);

                // Open with access = 0 (FILE_ANY_ACCESS)
                let handle = unsafe {
                    CreateFileW(
                        wide.as_ptr(),
                        0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0 as FILE_FLAGS_AND_ATTRIBUTES,
                        std::ptr::null_mut(),
                    )
                };

                if handle == INVALID_HANDLE_VALUE {
                    let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                    // Absent drive: skip
                    if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
                        continue;
                    }
                    // Access denied or any other error: typed error, NEVER silently skip!
                    return Err(BackendError::Io(format!(
                        "Error probing physical drive {} (Win32 error {})",
                        path, err
                    )));
                }

                let handle = ScopedHandle(handle);

                // 1. Query size and sector geometry via IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
                let mut geom_buf = [0u8; 128];
                let mut bytes_returned = 0u32;
                let ok = unsafe {
                    DeviceIoControl(
                        handle.get(),
                        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                        std::ptr::null(),
                        0,
                        geom_buf.as_mut_ptr() as *mut _,
                        geom_buf.len() as u32,
                        &mut bytes_returned,
                        std::ptr::null_mut(),
                    )
                };

                let geom = if ok != 0 {
                    parse_disk_geometry_ex(&geom_buf[..bytes_returned as usize]).ok()
                } else {
                    None
                };

                let size_bytes = geom.as_ref().map(|g| g.size_bytes).unwrap_or(0);

                // 2. Query StorageDeviceProperty (model, serial, bus type, removable)
                let mut query = STORAGE_PROPERTY_QUERY {
                    PropertyId: StorageDeviceProperty,
                    QueryType: PropertyStandardQuery,
                    AdditionalParameters: [0],
                };
                let mut desc_buf = [0u8; 1024];
                let ok_desc = unsafe {
                    DeviceIoControl(
                        handle.get(),
                        IOCTL_STORAGE_QUERY_PROPERTY,
                        &mut query as *mut _ as *const _,
                        std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                        desc_buf.as_mut_ptr() as *mut _,
                        desc_buf.len() as u32,
                        &mut bytes_returned,
                        std::ptr::null_mut(),
                    )
                };

                let desc = if ok_desc != 0 {
                    parse_storage_device_descriptor(&desc_buf[..bytes_returned as usize]).ok()
                } else {
                    None
                };

                // 3. Query StorageDeviceSeekPenaltyProperty (SSD vs HDD)
                let mut seek_query = STORAGE_PROPERTY_QUERY {
                    PropertyId: StorageDeviceSeekPenaltyProperty,
                    QueryType: PropertyStandardQuery,
                    AdditionalParameters: [0],
                };
                let mut seek_buf = [0u8; 32];
                let ok_seek = unsafe {
                    DeviceIoControl(
                        handle.get(),
                        IOCTL_STORAGE_QUERY_PROPERTY,
                        &mut seek_query as *mut _ as *const _,
                        std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                        seek_buf.as_mut_ptr() as *mut _,
                        seek_buf.len() as u32,
                        &mut bytes_returned,
                        std::ptr::null_mut(),
                    )
                };

                let is_rotational = if ok_seek != 0 {
                    parse_seek_penalty_descriptor(&seek_buf[..bytes_returned as usize]).unwrap_or(true)
                } else {
                    // Default to rotational when query unsupported
                    true
                };

                let model = desc.as_ref().and_then(|d| d.model());
                let serial = desc.as_ref().and_then(|d| d.serial_number.clone());
                let is_removable = desc.as_ref().map(|d| d.is_removable).unwrap_or(false);
                let transport = desc.as_ref().and_then(|d| d.transport_str());

                devices.push(DeviceInfo {
                    name: path,
                    model,
                    serial,
                    size_bytes,
                    is_removable,
                    is_rotational,
                    transport,
                });
            }

            Ok(devices)
        }

        fn enumerate_partitions(&self, device: &str) -> Result<Vec<PartitionFacts>, BackendError> {
            // Extract disk number from `\\.\PhysicalDriveN` or `PhysicalDriveN`
            let disk_num: u32 = device
                .trim_start_matches(r"\\.\")
                .strip_prefix("PhysicalDrive")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    BackendError::Unavailable(format!("Not a PhysicalDrive path: {}", device))
                })?;

            let handle = open_read_only_handle(device, false)?;

            // Query drive layout (up to 128 partitions in 16KB buffer)
            let mut layout_buf = vec![0u8; 16384];
            let mut bytes_returned = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    handle.get(),
                    IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                    std::ptr::null(),
                    0,
                    layout_buf.as_mut_ptr() as *mut _,
                    layout_buf.len() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };

            if ok == 0 {
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                return Err(BackendError::Io(format!(
                    "Failed to get drive layout for {} (Win32 error {})",
                    device, err
                )));
            }

            let layout = parse_drive_layout_ex(&layout_buf[..bytes_returned as usize])
                .map_err(|e| BackendError::Io(e.0))?;

            // Map volumes to partitions by (disk_number, starting_offset)
            let volume_map = collect_volume_mappings()?;

            let mut partitions = Vec::new();
            for p in layout.partitions {
                let key = (disk_num, p.starting_offset);
                let vol_info = volume_map.get(&key);

                let (label, fs_type) = if let Some(vol) = vol_info {
                    (vol.label.clone(), vol.fs_type.clone())
                } else {
                    (None, None)
                };

                let name = if let Some(vol) = vol_info {
                    if let Some(drive_letter) = &vol.drive_letter {
                        drive_letter.clone()
                    } else {
                        format!(r"{}\p{}", device, p.partition_number)
                    }
                } else {
                    format!(r"{}\p{}", device, p.partition_number)
                };

                partitions.push(PartitionFacts {
                    name,
                    partition_number: p.partition_number,
                    start_sector: p.start_sector,
                    size_sectors: p.size_sectors,
                    fs_type,
                    label,
                });
            }

            Ok(partitions)
        }

        // -- Facts consumed by the shared guard chain --------------------------

        fn read_mount_state(&self) -> Result<MountState, BackendError> {
            Err(BackendError::Unsupported("mount state on Windows"))
        }

        fn mountinfo_self(&self) -> Result<Option<String>, BackendError> {
            Err(BackendError::Unsupported("mountinfo on Windows"))
        }

        fn mounts_file(&self) -> String {
            String::new()
        }

        fn boot_environment(&self) -> Result<BootEnvironment, ExecuteError> {
            Err(ExecuteError::UnsupportedOperation(
                "boot environment detection on Windows".into(),
            ))
        }

        fn canonicalize_path(&self, path: &str, _dry_run: bool) -> Result<String, ExecuteError> {
            Ok(path.to_string())
        }

        fn sysfs_class_attr(
            &self,
            _block_name: &str,
            _attr_rel: &str,
        ) -> Result<Option<String>, BackendError> {
            Err(BackendError::Unsupported("sysfs attributes on Windows"))
        }

        fn sysfs_block_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn sysfs_block_exists(&self, _name: &str) -> bool {
            false
        }

        fn sysfs_is_partition(&self, _name: &str) -> bool {
            false
        }

        fn sysfs_parent_link(&self, _name: &str) -> Option<String> {
            None
        }

        fn sysfs_related_names(
            &self,
            _name: &str,
            _relation: Relation,
        ) -> Result<Vec<String>, BackendError> {
            Ok(Vec::new())
        }

        fn btrfs_member_devices(&self) -> Result<Vec<String>, BackendError> {
            Ok(Vec::new())
        }

        fn sysfs_root_display(&self) -> String {
            String::new()
        }

        fn device_file_path(&self, device: &str, _canonical: &str) -> PathBuf {
            PathBuf::from(device)
        }

        fn stat_backing_device(&self, _path: &str) -> Option<(u32, u32)> {
            None
        }

        fn read_raw(&self, _path: &str, _offset: u64, _len: u64) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("raw reads on Windows in this pass"))
        }

        fn stat_path(&self, _path: &str) -> Result<StatFact, BackendError> {
            Err(BackendError::Unsupported("stat on Windows"))
        }

        fn probe_exclusive_open(
            &self,
            _canonical_path: &str,
            device: &str,
        ) -> Result<StatFact, ExecuteError> {
            Err(ExecuteError::UnsupportedOperation(format!(
                "exclusive open of {} on Windows",
                device
            )))
        }

        fn exec(&self, _program: &str, _args: &[&str]) -> Result<(String, String, i32), BackendError> {
            Err(BackendError::Unsupported("external command exec on Windows"))
        }

        fn device_geometry(&self, target: &str) -> Result<DeviceGeometry, BackendError> {
            let handle = open_read_only_handle(target, false)?;
            let mut geom_buf = [0u8; 128];
            let mut bytes_returned = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    handle.get(),
                    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                    std::ptr::null(),
                    0,
                    geom_buf.as_mut_ptr() as *mut _,
                    geom_buf.len() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };

            if ok == 0 {
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                return Err(BackendError::Io(format!(
                    "Failed to get device geometry for {} (Win32 error {})",
                    target, err
                )));
            }

            let geom = parse_disk_geometry_ex(&geom_buf[..bytes_returned as usize])
                .map_err(|e| BackendError::Io(e.0))?;

            Ok(DeviceGeometry {
                size_bytes: geom.size_bytes,
                logical_block_size: geom.bytes_per_sector,
            })
        }

        // -- Actions (Refused) -------------------------------------------------

        fn unmount(&self, _target: &ValidatedTarget) -> Result<(), BackendError> {
            Err(BackendError::Unsupported("unmount on Windows"))
        }

        fn open_exclusive(&self, _target: &ValidatedTarget) -> Result<ExclusiveHandle, BackendError> {
            Err(BackendError::Unsupported("exclusive write access on Windows"))
        }

        fn discard_range(
            &self,
            _handle: &ExclusiveHandle,
            _offset: u64,
            _len: u64,
        ) -> Result<(), BackendError> {
            Err(BackendError::Unsupported("discard on Windows"))
        }

        fn reread_partition_table(&self, _target: &ValidatedTarget) -> Result<(), BackendError> {
            Err(BackendError::Unsupported("partition-table re-read on Windows"))
        }
    }

    #[derive(Debug, Clone)]
    struct MappedVolume {
        drive_letter: Option<String>,
        label: Option<String>,
        fs_type: Option<String>,
    }

    /// Enumerates all volumes and maps (disk_number, starting_offset) -> MappedVolume
    fn collect_volume_mappings() -> Result<HashMap<(u32, u64), MappedVolume>, BackendError> {
        let mut map = HashMap::new();
        let mut volume_name = [0u16; 512];

        let find_handle = unsafe {
            FindFirstVolumeW(volume_name.as_mut_ptr(), volume_name.len() as u32)
        };

        if find_handle == INVALID_HANDLE_VALUE {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == ERROR_NO_MORE_FILES {
                return Ok(map);
            }
            return Err(BackendError::Io(format!(
                "FindFirstVolumeW failed (Win32 error {})",
                err
            )));
        }

        loop {
            let vol_guid_path = String::from_utf16_lossy(
                &volume_name[..volume_name.iter().position(|&c| c == 0).unwrap_or(0)],
            );

            // Strip trailing backslash to open device handle (e.g. `\\?\Volume{...}`)
            let vol_dev_path = vol_guid_path.trim_end_matches('\\');

            // Open volume device with dwDesiredAccess = 0
            if let Ok(vol_handle) = open_read_only_handle(vol_dev_path, false) {
                let mut extents_buf = [0u8; 1024];
                let mut bytes_returned = 0u32;
                let ok = unsafe {
                    DeviceIoControl(
                        vol_handle.get(),
                        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                        std::ptr::null(),
                        0,
                        extents_buf.as_mut_ptr() as *mut _,
                        extents_buf.len() as u32,
                        &mut bytes_returned,
                        std::ptr::null_mut(),
                    )
                };

                if ok != 0 {
                    if let Ok(parsed) = parse_volume_disk_extents(&extents_buf[..bytes_returned as usize]) {
                        // Multi-extent volumes => ambiguous/unsupported; single extent matches 1:1
                        if !parsed.is_multi_extent && parsed.extents.len() == 1 {
                            let ext = &parsed.extents[0];
                            let key = (ext.disk_number, ext.starting_offset);

                            // Get drive letter(s)
                            let drive_letter = get_volume_path_name(&vol_guid_path);

                            // Get volume label and filesystem
                            let (label, fs_type) = get_volume_info(&vol_guid_path);

                            map.insert(
                                key,
                                MappedVolume {
                                    drive_letter,
                                    label,
                                    fs_type,
                                },
                            );
                        }
                    }
                }
            }

            let next_ok = unsafe {
                FindNextVolumeW(
                    find_handle,
                    volume_name.as_mut_ptr(),
                    volume_name.len() as u32,
                )
            };

            if next_ok == 0 {
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                if err == ERROR_NO_MORE_FILES {
                    break;
                }
                // Log and stop enumeration
                break;
            }
        }

        unsafe {
            FindVolumeClose(find_handle);
        }

        Ok(map)
    }

    fn get_volume_path_name(volume_guid_with_slash: &str) -> Option<String> {
        let wide = to_wide_null(volume_guid_with_slash);
        let mut path_names = [0u16; 512];
        let mut return_len = 0u32;

        let ok = unsafe {
            GetVolumePathNamesForVolumeNameW(
                wide.as_ptr(),
                path_names.as_mut_ptr(),
                path_names.len() as u32,
                &mut return_len,
            )
        };

        if ok != 0 && return_len > 1 {
            let first_null = path_names.iter().position(|&c| c == 0).unwrap_or(0);
            if first_null > 0 {
                let s = String::from_utf16_lossy(&path_names[..first_null]);
                let trimmed = s.trim_end_matches('\\').to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }

        None
    }

    fn get_volume_info(volume_guid_with_slash: &str) -> (Option<String>, Option<String>) {
        let wide = to_wide_null(volume_guid_with_slash);
        let mut name_buf = [0u16; 260];
        let mut fs_buf = [0u16; 260];

        let ok = unsafe {
            GetVolumeInformationW(
                wide.as_ptr(),
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                fs_buf.as_mut_ptr(),
                fs_buf.len() as u32,
            )
        };

        if ok != 0 {
            let name_len = name_buf.iter().position(|&c| c == 0).unwrap_or(0);
            let fs_len = fs_buf.iter().position(|&c| c == 0).unwrap_or(0);

            let label = if name_len > 0 {
                Some(String::from_utf16_lossy(&name_buf[..name_len]))
            } else {
                None
            };

            let fs = if fs_len > 0 {
                Some(String::from_utf16_lossy(&fs_buf[..fs_len]))
            } else {
                None
            };

            (label, fs)
        } else {
            // Failed GetVolumeInformation => typed unknown
            (None, None)
        }
    }
}
