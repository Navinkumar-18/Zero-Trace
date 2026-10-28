//! Windows BlockBackend implementation (Phase D-a, piece 1 — read-only facts).
//!
//! Hard rules (Phase D-a):
//! - Every disk and volume handle is opened with `dwDesiredAccess = 0` or `FILE_READ_ATTRIBUTES` only.
//!   Zero write access is ever requested.
//! - Every destructive / write operation returns `BackendError::Unsupported`.
//! - Pure byte parsing is delegated to `crate::backend::windows_parse`.
//! - Discovery is fail-closed: a drive that is absent is skipped, but
//!   access-denied, an unreadable volume, a failed/short geometry probe or a
//!   `FindNextVolumeW` error is a typed error — never a silent skip, never
//!   `size_bytes = 0`.
//!
//! Note: this pass reports facts only. The `C:` / system-disk refusal and all
//! write paths arrive in a later piece.

#[cfg(not(target_os = "windows"))]
pub use crate::backend::unsupported::UnsupportedBackend as WindowsBackend;

#[cfg(not(target_os = "windows"))]
pub fn windows_backend() -> WindowsBackend {
    crate::backend::unsupported::UnsupportedBackend::new("windows", "windows")
}

/// Pure discovery decisions, shared by the Windows implementation and unit
/// tests. Kept platform-neutral (no Win32 calls) so every error path can be
/// exercised on Linux without a device.
#[cfg(any(target_os = "windows", test))]
pub(crate) mod discovery {
    use crate::backend::windows_parse::{ParseError, ParsedGeometry, ParsedVolumeExtents};
    use crate::backend::BackendError;

    /// Result of opening a physical drive or enumerated volume.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum OpenFailure {
        NotFound,
        AccessDenied,
        Other(u32),
    }

    /// Only "file/path not found" means absent: `Ok(())` tells the scan to
    /// skip this slot. Access-denied and every other Win32 error are fatal for
    /// discovery, so they return `Err`.
    pub(crate) fn decide_drive_open(outcome: OpenFailure) -> Result<(), BackendError> {
        match outcome {
            OpenFailure::NotFound => Ok(()),
            OpenFailure::AccessDenied => Err(BackendError::Io(
                "Access denied probing a physical drive".to_string(),
            )),
            OpenFailure::Other(code) => Err(BackendError::Io(format!(
                "Error probing a physical drive (Win32 error {})",
                code
            ))),
        }
    }

    /// An enumerated volume that cannot be opened or queried is a failure, not
    /// an absent volume.
    pub(crate) fn volume_open_error(outcome: OpenFailure) -> BackendError {
        match outcome {
            OpenFailure::NotFound => BackendError::Unavailable(
                "Enumerated volume disappeared before it could be read".to_string(),
            ),
            OpenFailure::AccessDenied => {
                BackendError::Io("Access denied reading an enumerated volume".to_string())
            }
            OpenFailure::Other(code) => BackendError::Io(format!(
                "Failed to read an enumerated volume (Win32 error {})",
                code
            )),
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum FindNextOutcome {
        Found,
        NoMoreFiles,
        Failed(u32),
    }

    /// `Ok(true)` = another volume was returned; `Ok(false)` = clean end of
    /// enumeration; `Err` = any other `FindNextVolumeW` failure.
    pub(crate) fn decide_find_next(outcome: FindNextOutcome) -> Result<bool, BackendError> {
        match outcome {
            FindNextOutcome::Found => Ok(true),
            FindNextOutcome::NoMoreFiles => Ok(false),
            FindNextOutcome::Failed(code) => Err(BackendError::Io(format!(
                "FindNextVolumeW failed (Win32 error {})",
                code
            ))),
        }
    }

    /// A failed or malformed geometry probe must never produce a device with
    /// `size_bytes = 0`; it is a typed error instead.
    pub(crate) fn decide_geometry_probe(
        ioctl_ok: bool,
        win32_error: u32,
        parsed: Option<Result<ParsedGeometry, ParseError>>,
    ) -> Result<ParsedGeometry, BackendError> {
        if !ioctl_ok {
            return Err(BackendError::Io(format!(
                "Drive geometry probe failed (Win32 error {})",
                win32_error
            )));
        }
        let parsed = parsed.ok_or_else(|| {
            BackendError::Io("Drive geometry probe returned no buffer".to_string())
        })?;
        let geom =
            parsed.map_err(|e| BackendError::Io(format!("Malformed drive geometry: {}", e)))?;
        if geom.size_bytes == 0 {
            return Err(BackendError::Unavailable(
                "Drive geometry probe reported zero size".to_string(),
            ));
        }
        Ok(geom)
    }

    /// A volume must map to exactly one disk extent for the current
    /// partition-mapping model. Unreadable, empty or multi-extent volumes are
    /// typed errors rather than silently skipped.
    pub(crate) fn decide_volume_extents(
        ioctl_ok: bool,
        win32_error: u32,
        parsed: Option<Result<ParsedVolumeExtents, ParseError>>,
    ) -> Result<ParsedVolumeExtents, BackendError> {
        if !ioctl_ok {
            return Err(BackendError::Io(format!(
                "Volume disk-extent probe failed (Win32 error {})",
                win32_error
            )));
        }
        let parsed = parsed.ok_or_else(|| {
            BackendError::Io("Volume disk-extent probe returned no buffer".to_string())
        })?;
        let parsed = parsed
            .map_err(|e| BackendError::Io(format!("Malformed volume disk extents: {}", e)))?;
        if parsed.extents.is_empty() {
            return Err(BackendError::Unavailable(
                "Volume reported no disk extents".to_string(),
            ));
        }
        if parsed.is_multi_extent || parsed.extents.len() != 1 {
            return Err(BackendError::Unavailable(format!(
                "Volume spans {} disk extents; cannot map it to one partition",
                parsed.extents.len()
            )));
        }
        Ok(parsed)
    }

    /// D-a piece 2: a boot/system volume may span several disks; every member
    /// disk must be protected. Unlike `decide_volume_extents` (partition
    /// mapping needs exactly one extent), multi-extent volumes are valid here.
    /// An unreadable, empty or malformed probe is a typed error, never an
    /// empty disk set.
    pub(crate) fn decide_boot_volume_disks(
        ioctl_ok: bool,
        win32_error: u32,
        parsed: Option<Result<ParsedVolumeExtents, ParseError>>,
    ) -> Result<Vec<u32>, BackendError> {
        if !ioctl_ok {
            return Err(BackendError::Io(format!(
                "Volume disk-extent probe failed (Win32 error {})",
                win32_error
            )));
        }
        let parsed = parsed.ok_or_else(|| {
            BackendError::Io("Volume disk-extent probe returned no buffer".to_string())
        })?;
        let parsed = parsed
            .map_err(|e| BackendError::Io(format!("Malformed volume disk extents: {}", e)))?;
        if parsed.extents.is_empty() {
            return Err(BackendError::Unavailable(
                "Volume reported no disk extents".to_string(),
            ));
        }
        let mut disks: Vec<u32> = parsed.extents.iter().map(|e| e.disk_number).collect();
        disks.sort_unstable();
        disks.dedup();
        Ok(disks)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::backend::windows_parse::{ParsedExtent, ParsedGeometry};

        fn geometry(size_bytes: u64) -> ParsedGeometry {
            ParsedGeometry {
                size_bytes,
                bytes_per_sector: 512,
            }
        }

        fn extents(count: u32, multi: bool) -> ParsedVolumeExtents {
            ParsedVolumeExtents {
                extents: (0..count)
                    .map(|i| ParsedExtent {
                        disk_number: i,
                        starting_offset: u64::from(i) * 1024,
                        extent_length: 1024,
                    })
                    .collect(),
                is_multi_extent: multi,
            }
        }

        #[test]
        fn not_found_drive_is_the_only_absent_outcome() {
            assert!(decide_drive_open(OpenFailure::NotFound).is_ok());
        }

        #[test]
        fn access_denied_drive_is_an_error_not_absent() {
            let err = decide_drive_open(OpenFailure::AccessDenied).unwrap_err();
            assert!(matches!(err, BackendError::Io(_)));
            assert!(err.to_string().contains("Access denied"));
        }

        #[test]
        fn other_drive_open_error_is_typed() {
            let err = decide_drive_open(OpenFailure::Other(32)).unwrap_err();
            assert!(matches!(err, BackendError::Io(_)));
            assert!(err.to_string().contains("Win32 error 32"));
        }

        #[test]
        fn enumerating_volume_failures_are_typed() {
            assert!(matches!(
                volume_open_error(OpenFailure::NotFound),
                BackendError::Unavailable(_)
            ));
            assert!(matches!(
                volume_open_error(OpenFailure::AccessDenied),
                BackendError::Io(_)
            ));
            let other = volume_open_error(OpenFailure::Other(21));
            assert!(matches!(other, BackendError::Io(_)));
            assert!(other.to_string().contains("Win32 error 21"));
        }

        #[test]
        fn find_next_found_and_no_more_files_are_clean() {
            assert!(decide_find_next(FindNextOutcome::Found).unwrap());
            assert!(!decide_find_next(FindNextOutcome::NoMoreFiles).unwrap());
        }

        #[test]
        fn find_next_other_error_is_not_a_silent_break() {
            let err = decide_find_next(FindNextOutcome::Failed(5)).unwrap_err();
            assert!(matches!(err, BackendError::Io(_)));
            assert!(err.to_string().contains("FindNextVolumeW failed"));
            assert!(err.to_string().contains("Win32 error 5"));
        }

        #[test]
        fn geometry_ioctl_failure_is_typed() {
            let err = decide_geometry_probe(false, 5, None).unwrap_err();
            assert!(matches!(err, BackendError::Io(_)));
            assert!(err.to_string().contains("geometry probe failed"));
        }

        #[test]
        fn geometry_malformed_or_missing_buffer_is_typed() {
            let malformed =
                decide_geometry_probe(true, 0, Some(Err(ParseError("short".to_string()))))
                    .unwrap_err();
            assert!(matches!(malformed, BackendError::Io(_)));
            assert!(malformed.to_string().contains("Malformed drive geometry"));

            let missing = decide_geometry_probe(true, 0, None).unwrap_err();
            assert!(matches!(missing, BackendError::Io(_)));
        }

        #[test]
        fn geometry_zero_size_is_rejected_not_reported() {
            let err = decide_geometry_probe(true, 0, Some(Ok(geometry(0)))).unwrap_err();
            assert!(matches!(err, BackendError::Unavailable(_)));
            assert!(err.to_string().contains("zero size"));
        }

        #[test]
        fn geometry_success_returns_the_nonzero_size() {
            let geom = decide_geometry_probe(true, 0, Some(Ok(geometry(4096)))).unwrap();
            assert_eq!(geom.size_bytes, 4096);
            assert_eq!(geom.bytes_per_sector, 512);
        }

        #[test]
        fn volume_extent_ioctl_and_parse_failures_are_typed() {
            let ioctl = decide_volume_extents(false, 5, None).unwrap_err();
            assert!(matches!(ioctl, BackendError::Io(_)));

            let malformed =
                decide_volume_extents(true, 0, Some(Err(ParseError("short".to_string()))))
                    .unwrap_err();
            assert!(matches!(malformed, BackendError::Io(_)));
            assert!(malformed
                .to_string()
                .contains("Malformed volume disk extents"));
        }

        #[test]
        fn empty_or_multi_extent_volume_is_rejected_not_skipped() {
            let empty = decide_volume_extents(true, 0, Some(Ok(extents(0, false)))).unwrap_err();
            assert!(matches!(empty, BackendError::Unavailable(_)));
            assert!(empty.to_string().contains("no disk extents"));

            let multi = decide_volume_extents(true, 0, Some(Ok(extents(2, true)))).unwrap_err();
            assert!(matches!(multi, BackendError::Unavailable(_)));
            assert!(multi.to_string().contains("2 disk extents"));
            assert!(multi.to_string().contains("cannot map"));
        }

        #[test]
        fn single_extent_volume_is_accepted() {
            let parsed = decide_volume_extents(true, 0, Some(Ok(extents(1, false)))).unwrap();
            assert_eq!(parsed.extents.len(), 1);
        }

        // -------------------------------------------------------------------
        // D-a piece 2: boot/system volume -> disk set.
        // -------------------------------------------------------------------

        #[test]
        fn boot_volume_multi_disk_extents_map_to_every_member_disk() {
            let disks = decide_boot_volume_disks(true, 0, Some(Ok(extents(2, true)))).unwrap();
            assert_eq!(disks, vec![0, 1]);
        }

        #[test]
        fn boot_volume_extent_failures_are_typed_not_empty() {
            let ioctl = decide_boot_volume_disks(false, 5, None).unwrap_err();
            assert!(matches!(ioctl, BackendError::Io(_)));

            let malformed =
                decide_boot_volume_disks(true, 0, Some(Err(ParseError("short".to_string()))))
                    .unwrap_err();
            assert!(matches!(malformed, BackendError::Io(_)));

            let empty = decide_boot_volume_disks(true, 0, Some(Ok(extents(0, false)))).unwrap_err();
            assert!(matches!(empty, BackendError::Unavailable(_)));
            assert!(empty.to_string().contains("no disk extents"));
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::{windows_backend, WindowsBackend};

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::HashMap;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_ENVVAR_NOT_FOUND, ERROR_FILE_NOT_FOUND,
        ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationW,
        GetVolumeNameForVolumeMountPointW, GetVolumePathNamesForVolumeNameW,
        FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Environment::GetEnvironmentVariableW;
    use windows_sys::Win32::System::Ioctl::{
        PropertyStandardQuery, StorageDeviceProperty, StorageDeviceSeekPenaltyProperty,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROPERTY_QUERY,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    use crate::backend::windows_parse::{
        crash_dump_volume_roots, hibernation_volume_roots, pagefile_volume_roots,
        parse_disk_geometry_ex, parse_drive_layout_ex, parse_reg_dword, parse_reg_multi_sz,
        parse_reg_sz, parse_seek_penalty_descriptor, parse_storage_device_descriptor,
        parse_volume_disk_extents, windows_volume_root,
    };
    use crate::backend::{
        BackendCapabilities, BackendError, BlockBackend, DeviceGeometry, DeviceInfo, DiskSetFact,
        ElevationFact, ExclusiveHandle, MountState, PartitionFacts, Relation, StatFact,
        WindowsBootFacts,
    };
    use crate::guard::ValidatedTarget;
    use crate::types::{BootEnvironment, ExecuteError};

    use super::discovery::{
        decide_boot_volume_disks, decide_drive_open, decide_find_next, decide_geometry_probe,
        decide_volume_extents, volume_open_error, FindNextOutcome, OpenFailure,
    };

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
    fn open_read_only_handle(
        path: &str,
        access_attributes_only: bool,
    ) -> Result<ScopedHandle, BackendError> {
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
                return Err(BackendError::Unavailable(format!(
                    "Device not found: {}",
                    path
                )));
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

    fn classify_open_failure(err: u32) -> OpenFailure {
        if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
            OpenFailure::NotFound
        } else if err == ERROR_ACCESS_DENIED {
            OpenFailure::AccessDenied
        } else {
            OpenFailure::Other(err)
        }
    }

    /// Opens an enumerated volume read-only. Unlike an absent physical-drive
    /// scan slot, a volume returned by `FindFirstVolumeW`/`FindNextVolumeW`
    /// that cannot be opened is a typed discovery error.
    fn open_volume_read_only(path: &str) -> Result<ScopedHandle, BackendError> {
        let wide = to_wide_null(path);
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
            return Err(volume_open_error(classify_open_failure(err)));
        }

        ScopedHandle::new(handle)
            .ok_or_else(|| BackendError::Io(format!("Invalid volume handle for {}", path)))
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
                    // Only file/path-not-found is an absent scan slot; every
                    // other Win32 error aborts discovery.
                    decide_drive_open(classify_open_failure(err))?;
                    continue;
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

                // Fail closed: a failed, short or malformed geometry probe is a
                // typed error. It must never become `size_bytes = 0`.
                let geom = if ok != 0 {
                    let returned = (bytes_returned as usize).min(geom_buf.len());
                    decide_geometry_probe(
                        true,
                        0,
                        Some(parse_disk_geometry_ex(&geom_buf[..returned])),
                    )?
                } else {
                    let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                    decide_geometry_probe(false, err, None)?
                };
                let size_bytes = geom.size_bytes;

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
                    let returned = (bytes_returned as usize).min(desc_buf.len());
                    parse_storage_device_descriptor(&desc_buf[..returned]).ok()
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
                    let returned = (bytes_returned as usize).min(seek_buf.len());
                    parse_seek_penalty_descriptor(&seek_buf[..returned]).unwrap_or(true)
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

        fn windows_boot_facts(&self) -> Result<Option<WindowsBootFacts>, BackendError> {
            collect_boot_facts().map(Some)
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
            Err(BackendError::Unsupported(
                "raw reads on Windows in this pass",
            ))
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

        fn exec(
            &self,
            _program: &str,
            _args: &[&str],
        ) -> Result<(String, String, i32), BackendError> {
            Err(BackendError::Unsupported(
                "external command exec on Windows",
            ))
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

            let geom = if ok != 0 {
                let returned = (bytes_returned as usize).min(geom_buf.len());
                decide_geometry_probe(true, 0, Some(parse_disk_geometry_ex(&geom_buf[..returned])))?
            } else {
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                decide_geometry_probe(false, err, None)?
            };

            Ok(DeviceGeometry {
                size_bytes: geom.size_bytes,
                logical_block_size: geom.bytes_per_sector,
            })
        }

        // -- Actions (Refused) -------------------------------------------------

        fn unmount(&self, _target: &ValidatedTarget) -> Result<(), BackendError> {
            Err(BackendError::Unsupported("unmount on Windows"))
        }

        fn open_exclusive(
            &self,
            _target: &ValidatedTarget,
        ) -> Result<ExclusiveHandle, BackendError> {
            Err(BackendError::Unsupported(
                "exclusive write access on Windows",
            ))
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
            Err(BackendError::Unsupported(
                "partition-table re-read on Windows",
            ))
        }
    }

    // -----------------------------------------------------------------------
    // D-a piece 2: boot/system facts (read-only)
    // -----------------------------------------------------------------------

    const PAGEFILE_KEY: &str =
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
    const POWER_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Power";
    const CRASH_KEY: &str = r"SYSTEM\CurrentControlSet\Control\CrashControl";

    /// RAII wrapper for a registry key handle.
    struct ScopedRegKey(HKEY);

    impl Drop for ScopedRegKey {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    RegCloseKey(self.0);
                }
            }
        }
    }

    /// Reads a registry value as raw bytes. `Ok(None)` = value or key absent;
    /// every other failure is a typed error (the guard treats it as an
    /// unreadable boot fact and refuses).
    fn read_registry_value(subkey: &str, value: &str) -> Result<Option<Vec<u8>>, BackendError> {
        let subkey_w = to_wide_null(subkey);
        let mut key: HKEY = std::ptr::null_mut();
        let rc =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr(), 0, KEY_READ, &mut key) };
        if rc != ERROR_SUCCESS {
            if rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND {
                return Ok(None);
            }
            return Err(BackendError::Unavailable(format!(
                "Cannot open registry key {} (Win32 error {})",
                subkey, rc
            )));
        }
        let key = ScopedRegKey(key);

        let value_w = to_wide_null(value);
        let mut buf = vec![0u8; 65536];
        let mut len = buf.len() as u32;
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                value_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        if rc != ERROR_SUCCESS {
            return Err(BackendError::Unavailable(format!(
                "Cannot read registry value {}\\{} (Win32 error {})",
                subkey, value, rc
            )));
        }
        if len as usize > buf.len() {
            return Err(BackendError::Unavailable(format!(
                "Registry value {}\\{} is larger than the read buffer",
                subkey, value
            )));
        }
        buf.truncate(len as usize);
        Ok(Some(buf))
    }

    fn read_registry_string(subkey: &str, value: &str) -> Result<Option<String>, BackendError> {
        match read_registry_value(subkey, value)? {
            None => Ok(None),
            Some(bytes) => parse_reg_sz(&bytes)
                .map(Some)
                .map_err(|e| BackendError::Unavailable(e.to_string())),
        }
    }

    /// Reads an environment variable. `Ok(None)` = variable not defined.
    fn get_env_var(name: &str) -> Result<Option<String>, BackendError> {
        let name_w = to_wide_null(name);
        let mut buf = vec![0u16; 32768];
        let len =
            unsafe { GetEnvironmentVariableW(name_w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == ERROR_ENVVAR_NOT_FOUND {
                return Ok(None);
            }
            return Err(BackendError::Unavailable(format!(
                "Cannot read environment variable {} (Win32 error {})",
                name, err
            )));
        }
        if len as usize >= buf.len() {
            return Err(BackendError::Unavailable(format!(
                "Environment variable {} is larger than the read buffer",
                name
            )));
        }
        Ok(Some(String::from_utf16_lossy(&buf[..len as usize])))
    }

    fn get_system_windows_directory() -> Result<String, BackendError> {
        let mut buf = vec![0u16; 32768];
        let len = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            return Err(BackendError::Unavailable(format!(
                "GetSystemWindowsDirectoryW failed (Win32 error {})",
                err
            )));
        }
        if len as usize >= buf.len() {
            return Err(BackendError::Unavailable(
                "Windows system directory is larger than the read buffer".to_string(),
            ));
        }
        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn current_module_path() -> Result<String, BackendError> {
        let mut buf = vec![0u16; 32768];
        let len =
            unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            return Err(BackendError::Unavailable(format!(
                "GetModuleFileNameW failed (Win32 error {})",
                err
            )));
        }
        if len as usize >= buf.len() {
            return Err(BackendError::Unavailable(
                "Executable path is larger than the read buffer".to_string(),
            ));
        }
        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn parent_windows_path(path: &str) -> Option<&str> {
        path.rfind('\\').map(|idx| &path[..idx])
    }

    /// Resolves a volume root to its `\\?\Volume{GUID}\` path.
    fn volume_guid_path_for_root(root: &str) -> Result<String, BackendError> {
        let mut normalized = root.trim().to_string();
        if !normalized.ends_with('\\') {
            normalized.push('\\');
        }
        if normalized.to_ascii_lowercase().starts_with(r"\\?\volume{") {
            return Ok(normalized);
        }

        let wide = to_wide_null(&normalized);
        let mut buf = [0u16; 512];
        let ok = unsafe {
            GetVolumeNameForVolumeMountPointW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        if ok == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            return Err(BackendError::Unavailable(format!(
                "Cannot resolve the volume for {} (Win32 error {})",
                root, err
            )));
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        if len == 0 {
            return Err(BackendError::Unavailable(format!(
                "Empty volume name for {}",
                root
            )));
        }
        Ok(String::from_utf16_lossy(&buf[..len]))
    }

    /// All disk numbers a volume spans. A multi-disk volume returns every
    /// member disk (the guard protects all of them).
    fn disk_numbers_for_volume_root(root: &str) -> Result<Vec<u32>, BackendError> {
        let guid = volume_guid_path_for_root(root)?;
        let volume_path = guid.trim_end_matches('\\');
        let handle = open_volume_read_only(volume_path)?;
        let mut extents_buf = vec![0u8; 4096];
        let mut bytes_returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle.get(),
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
            let returned = (bytes_returned as usize).min(extents_buf.len());
            decide_boot_volume_disks(
                true,
                0,
                Some(parse_volume_disk_extents(&extents_buf[..returned])),
            )
        } else {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            decide_boot_volume_disks(false, err, None)
        }
    }

    fn disk_set_from_roots(roots: &[String]) -> DiskSetFact {
        let mut disks = Vec::new();
        for root in roots {
            match disk_numbers_for_volume_root(root) {
                Ok(mut found) => disks.append(&mut found),
                Err(e) => {
                    return DiskSetFact::unreadable(format!(
                        "Cannot map volume {} to a disk: {}",
                        root, e
                    ))
                }
            }
        }
        DiskSetFact::known(disks)
    }

    fn read_pagefile_disks(system_drive: Option<&str>) -> DiskSetFact {
        match read_registry_value(PAGEFILE_KEY, "PagingFiles") {
            Err(e) => DiskSetFact::unreadable(e.to_string()),
            // No configured paging file value: a known empty set, not an
            // unreadable fact.
            Ok(None) => DiskSetFact::known(std::iter::empty::<u32>()),
            Ok(Some(bytes)) => match parse_reg_multi_sz(&bytes) {
                Err(e) => DiskSetFact::unreadable(e.to_string()),
                Ok(entries) => match pagefile_volume_roots(&entries, system_drive.unwrap_or("")) {
                    Err(e) => DiskSetFact::unreadable(e.to_string()),
                    Ok(roots) => disk_set_from_roots(&roots),
                },
            },
        }
    }

    fn read_hibernation_disks(system_drive: Option<&str>) -> DiskSetFact {
        match read_registry_value(POWER_KEY, "HibernateEnabled") {
            Err(e) => DiskSetFact::unreadable(e.to_string()),
            // TODO-VERIFY: a missing HibernateEnabled value is reported as
            // unreadable rather than assumed "disabled" (fail closed).
            Ok(None) => DiskSetFact::unreadable(
                "HibernateEnabled registry value is missing; cannot determine whether hiberfil.sys exists"
                    .to_string(),
            ),
            Ok(Some(bytes)) => match parse_reg_dword(&bytes) {
                Err(e) => DiskSetFact::unreadable(e.to_string()),
                Ok(0) => DiskSetFact::known(std::iter::empty::<u32>()),
                Ok(enabled) => match system_drive {
                    Some(drive) => disk_set_from_roots(&hibernation_volume_roots(enabled, drive)),
                    None => DiskSetFact::unreadable(
                        "Cannot resolve the system drive for the hibernation file".to_string(),
                    ),
                },
            },
        }
    }

    fn read_crashdump_disks(system_root: Option<&str>, system_drive: Option<&str>) -> DiskSetFact {
        let enabled = match read_registry_value(CRASH_KEY, "CrashDumpEnabled") {
            Err(e) => return DiskSetFact::unreadable(e.to_string()),
            // TODO-VERIFY: missing CrashDumpEnabled is treated as unreadable
            // (fail closed) instead of guessing Windows' default.
            Ok(None) => {
                return DiskSetFact::unreadable(
                    "CrashDumpEnabled registry value is missing; cannot determine the crash-dump target"
                        .to_string(),
                )
            }
            Ok(Some(bytes)) => match parse_reg_dword(&bytes) {
                Ok(value) => value,
                Err(e) => return DiskSetFact::unreadable(e.to_string()),
            },
        };
        if enabled == 0 {
            return DiskSetFact::known(std::iter::empty::<u32>());
        }

        let dump_file = match read_registry_string(CRASH_KEY, "DumpFile") {
            Ok(value) => value,
            Err(e) => return DiskSetFact::unreadable(e.to_string()),
        };
        let minidump_dir = match read_registry_string(CRASH_KEY, "MinidumpDir") {
            Ok(value) => value,
            Err(e) => return DiskSetFact::unreadable(e.to_string()),
        };

        match crash_dump_volume_roots(
            enabled,
            dump_file.as_deref(),
            minidump_dir.as_deref(),
            system_root.unwrap_or(""),
            system_drive.unwrap_or(""),
        ) {
            Err(e) => DiskSetFact::unreadable(e.to_string()),
            Ok(roots) => disk_set_from_roots(&roots),
        }
    }

    fn read_app_disks() -> DiskSetFact {
        let exe = match current_module_path() {
            Ok(path) => path,
            Err(e) => {
                return DiskSetFact::unreadable(format!(
                    "Cannot read the Zero Trace executable path: {}",
                    e
                ))
            }
        };
        let mut paths = vec![exe.clone()];

        // TODO-VERIFY: the Flutter/Dart side chooses the application data
        // directory. `%LOCALAPPDATA%\ZeroTrace` is the expected default; when
        // it is unavailable we fall back to the executable's own directory.
        match get_env_var("LOCALAPPDATA") {
            Ok(Some(local)) if !local.trim().is_empty() => {
                paths.push(format!("{}\\ZeroTrace", local.trim_end_matches('\\')));
            }
            Ok(_) => {
                if let Some(dir) = parent_windows_path(&exe) {
                    paths.push(dir.to_string());
                }
            }
            Err(e) => {
                return DiskSetFact::unreadable(format!(
                    "Cannot read LOCALAPPDATA for the Zero Trace data directory: {}",
                    e
                ))
            }
        }

        let mut roots = Vec::new();
        for path in &paths {
            match windows_volume_root(path) {
                Some(root) => roots.push(root),
                None => {
                    return DiskSetFact::unreadable(format!(
                        "Cannot resolve the volume for Zero Trace path '{}'",
                        path
                    ))
                }
            }
        }
        disk_set_from_roots(&roots)
    }

    /// `TOKEN_QUERY` only; reads `TokenElevation` from the current process.
    fn read_elevation() -> Result<bool, BackendError> {
        let mut token: HANDLE = std::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            return Err(BackendError::Unavailable(format!(
                "OpenProcessToken failed (Win32 error {})",
                err
            )));
        }
        let token = ScopedHandle::new(token)
            .ok_or_else(|| BackendError::Io("Invalid process token handle".to_string()))?;

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token.get(),
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        };
        if ok == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            return Err(BackendError::Unavailable(format!(
                "GetTokenInformation(TokenElevation) failed (Win32 error {})",
                err
            )));
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    /// Reads every boot/system fact. Any field that cannot be read stays
    /// `Unreadable` (with its reason); it is never turned into an empty set.
    fn collect_boot_facts() -> Result<WindowsBootFacts, BackendError> {
        let system_dir = get_system_windows_directory();
        let system_root = system_dir
            .as_ref()
            .ok()
            .and_then(|path| windows_volume_root(path));

        let system_drive = match get_env_var("SystemDrive") {
            Ok(Some(value)) => windows_volume_root(&value).or_else(|| system_root.clone()),
            // The environment read failed or the variable is absent: derive
            // the boot volume from the documented Windows directory instead.
            Ok(None) | Err(_) => system_root.clone(),
        };

        let system_disks = match (&system_dir, &system_root) {
            (Err(e), _) => {
                DiskSetFact::unreadable(format!("Cannot read the Windows system directory: {}", e))
            }
            (Ok(_), None) => DiskSetFact::unreadable(
                "Cannot resolve the volume of the Windows system directory".to_string(),
            ),
            (Ok(_), Some(root)) => disk_set_from_roots(std::slice::from_ref(root)),
        };

        let boot_disks = match &system_drive {
            Some(drive) => disk_set_from_roots(std::slice::from_ref(drive)),
            None => DiskSetFact::unreadable(
                "Cannot resolve the Windows boot volume (SystemDrive)".to_string(),
            ),
        };

        let pagefile_disks = read_pagefile_disks(system_drive.as_deref());
        let hibernation_disks = read_hibernation_disks(system_drive.as_deref());
        let crashdump_disks = read_crashdump_disks(system_root.as_deref(), system_drive.as_deref());
        let app_disks = read_app_disks();
        let elevated = match read_elevation() {
            Ok(value) => ElevationFact::Known(value),
            Err(e) => ElevationFact::Unreadable(e.to_string()),
        };

        Ok(WindowsBootFacts {
            system_disks,
            boot_disks,
            pagefile_disks,
            hibernation_disks,
            crashdump_disks,
            app_disks,
            elevated,
        })
    }

    #[derive(Debug, Clone)]
    struct MappedVolume {
        drive_letter: Option<String>,
        label: Option<String>,
        fs_type: Option<String>,
    }

    /// Enumerates all volumes and maps (disk_number, starting_offset) -> MappedVolume.
    ///
    /// The `FindVolume` handle is always closed, including on the error paths.
    fn collect_volume_mappings() -> Result<HashMap<(u32, u64), MappedVolume>, BackendError> {
        let mut volume_name = [0u16; 512];

        let find_handle =
            unsafe { FindFirstVolumeW(volume_name.as_mut_ptr(), volume_name.len() as u32) };

        if find_handle == INVALID_HANDLE_VALUE {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == ERROR_NO_MORE_FILES {
                return Ok(HashMap::new());
            }
            return Err(BackendError::Io(format!(
                "FindFirstVolumeW failed (Win32 error {})",
                err
            )));
        }

        let result = collect_volume_mappings_from(find_handle, &mut volume_name);
        unsafe {
            FindVolumeClose(find_handle);
        }
        result
    }

    fn collect_volume_mappings_from(
        find_handle: HANDLE,
        volume_name: &mut [u16; 512],
    ) -> Result<HashMap<(u32, u64), MappedVolume>, BackendError> {
        let mut map = HashMap::new();

        loop {
            let vol_guid_path = String::from_utf16_lossy(
                &volume_name[..volume_name.iter().position(|&c| c == 0).unwrap_or(0)],
            );

            // Strip trailing backslash to open device handle (e.g. `\\?\Volume{...}`)
            let vol_dev_path = vol_guid_path.trim_end_matches('\\');

            // An enumerated volume that cannot be opened is an error, not an
            // absent device. This keeps access-denied and vanished volumes
            // visible instead of silently dropping their partitions.
            let vol_handle = open_volume_read_only(vol_dev_path)?;
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

            let parsed = if ok != 0 {
                let returned = (bytes_returned as usize).min(extents_buf.len());
                decide_volume_extents(
                    true,
                    0,
                    Some(parse_volume_disk_extents(&extents_buf[..returned])),
                )?
            } else {
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                decide_volume_extents(false, err, None)?
            };

            // decide_volume_extents guarantees exactly one extent.
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

            let next_outcome = if unsafe {
                FindNextVolumeW(
                    find_handle,
                    volume_name.as_mut_ptr(),
                    volume_name.len() as u32,
                )
            } != 0
            {
                FindNextOutcome::Found
            } else {
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                if err == ERROR_NO_MORE_FILES {
                    FindNextOutcome::NoMoreFiles
                } else {
                    FindNextOutcome::Failed(err)
                }
            };

            if !decide_find_next(next_outcome)? {
                break;
            }
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
