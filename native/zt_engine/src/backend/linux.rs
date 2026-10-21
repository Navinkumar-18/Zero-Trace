//! C3: the Linux backend — the **only real** backend.
//!
//! Every fact the shared guard chain consumes is produced here by the same
//! sysfs/proc/libc operations the engine has always used (injected through
//! [`FsContext`] so fixture-driven tests keep working unchanged). The
//! backend never decides anything safety-relevant; it reports facts and
//! executes primitives. All policy lives in [`crate::guard`].

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::backend::{
    BackendCapabilities, BackendError, BlockBackend, DeviceInfo, ExclusiveHandle,
    HandleReader, MountState, PartitionFacts, Relation, StatFact,
};
use crate::execute::{
    canonicalize_device_path, detect_boot_environment_ctx, map_open_excl_error, DirectBlockWriter,
    FsContext,
};
use crate::guard::ValidatedTarget;
use crate::types::{dev_major, dev_minor, BlockWriter, BootEnvironment, ExecuteError};

/// BLKDISCARD ioctl number (`_IO(0x12, 119)`).
const BLKDISCARD: libc::c_ulong = 0x1277;

/// Read side of an exclusive handle: a plain read-only fd, `pread`-based.
struct StdFileReader {
    file: fs::File,
}

impl HandleReader for StdFileReader {
    fn read_at(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; len];
        let mut read = 0usize;
        while read < len {
            let n = self.file.read_at(&mut buf[read..], offset + read as u64)?;
            if n == 0 {
                break;
            }
            read += n;
        }
        buf.truncate(read);
        Ok(buf)
    }
}

/// The Linux implementation of [`BlockBackend`]. Constructed with the same
/// injected [`FsContext`] the historic code used (`/proc`, `/sys`, `/dev`
/// by default; tempdir fixtures in tests).
pub struct LinuxBackend {
    ctx: FsContext,
}

impl LinuxBackend {
    pub fn new(ctx: FsContext) -> Self {
        Self { ctx }
    }

    /// Real system roots (`/proc`, `/sys`, `/dev`).
    pub fn system() -> Self {
        Self::new(FsContext::default())
    }

    pub fn ctx(&self) -> &FsContext {
        &self.ctx
    }

    fn class_block(&self) -> PathBuf {
        self.ctx.sys_root.join("class/block")
    }
}

impl BlockBackend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn platform(&self) -> &'static str {
        "linux"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::full()
    }

    // -- Discovery ---------------------------------------------------------

    fn enumerate_devices(&self) -> Result<Vec<DeviceInfo>, BackendError> {
        // Whole-device enumeration (model/serial/transport/rotational) is
        // performed by the Dart layer via lsblk/smartctl on Linux; the engine
        // has no equivalent yet. Refuse rather than half-implement.
        Err(BackendError::Unsupported(
            "whole-device enumeration is performed by the Dart layer (lsblk) on Linux",
        ))
    }

    fn enumerate_partitions(&self, device: &str) -> Result<Vec<PartitionFacts>, BackendError> {
        let report = crate::partitions::enumerate_partitions_ctx(device, &self.ctx)
            .map_err(|e| BackendError::Unavailable(e.to_string()))?;
        Ok(report
            .partitions
            .iter()
            .map(|p| PartitionFacts {
                name: p.name.clone(),
                partition_number: p.partition_number,
                start_sector: p.start_sector,
                size_sectors: p.size_bytes / 512,
                fs_type: p.fs_type.clone(),
                label: p.label.clone(),
            })
            .collect())
    }

    // -- Facts consumed by the shared guard chain --------------------------

    fn read_mount_state(&self) -> Result<MountState, BackendError> {
        // Historic fallback chain: self/mountinfo → mountinfo → mounts →
        // fail closed. Error strings are byte-identical to the originals
        // (the guard chain wraps them into BootDiskProtection).
        let mountinfo_path = self.ctx.proc_root.join("self/mountinfo");
        let content = if mountinfo_path.exists() {
            fs::read_to_string(&mountinfo_path)
                .map_err(|e| BackendError::Unavailable(format!("Cannot read mountinfo: {}", e)))?
        } else {
            let alt = self.ctx.proc_root.join("mountinfo");
            let alt_mounts = self.ctx.proc_root.join("mounts");
            if alt.exists() {
                fs::read_to_string(&alt)
                    .map_err(|e| BackendError::Unavailable(format!("Cannot read mountinfo: {}", e)))?
            } else if alt_mounts.exists() {
                fs::read_to_string(&alt_mounts)
                    .map_err(|e| BackendError::Unavailable(format!("Cannot read mounts: {}", e)))?
            } else {
                return Err(BackendError::Unavailable(
                    "No mountinfo or mounts file found: fail closed".to_string(),
                ));
            }
        };
        let swaps = fs::read_to_string(self.ctx.proc_root.join("swaps")).unwrap_or_default();
        let mounts = fs::read_to_string(self.ctx.proc_root.join("mounts")).unwrap_or_default();
        Ok(MountState {
            mountinfo: content,
            mounts,
            swaps,
        })
    }

    fn mountinfo_self(&self) -> Result<Option<String>, BackendError> {
        let p = self.ctx.proc_root.join("self/mountinfo");
        if p.exists() {
            fs::read_to_string(&p)
                .map(Some)
                .map_err(|e| BackendError::Unavailable(format!("Cannot read mountinfo: {}", e)))
        } else {
            Ok(None)
        }
    }

    fn mounts_file(&self) -> String {
        fs::read_to_string(self.ctx.proc_root.join("mounts")).unwrap_or_default()
    }

    fn boot_environment(&self) -> Result<BootEnvironment, ExecuteError> {
        detect_boot_environment_ctx(&self.ctx)
    }

    fn canonicalize_path(&self, path: &str, dry_run: bool) -> Result<String, ExecuteError> {
        canonicalize_device_path(path, dry_run, &self.ctx)
    }

    fn sysfs_class_attr(
        &self,
        block_name: &str,
        attr_rel: &str,
    ) -> Result<Option<String>, BackendError> {
        let p = self.class_block().join(block_name).join(attr_rel);
        if !p.exists() {
            return Ok(None);
        }
        fs::read_to_string(&p)
            .map(Some)
            .map_err(|e| BackendError::Io(e.to_string()))
    }

    fn sysfs_block_names(&self) -> Vec<String> {
        fs::read_dir(self.class_block())
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn sysfs_block_exists(&self, name: &str) -> bool {
        self.class_block().join(name).exists()
    }

    fn sysfs_parent_link(&self, name: &str) -> Option<String> {
        let link = fs::read_link(self.class_block().join(name)).ok()?;
        let parent = link.parent()?.file_name()?.to_string_lossy().to_string();
        Some(parent)
    }

    fn sysfs_related_names(&self, name: &str, relation: Relation) -> Vec<String> {
        let rel = match relation {
            Relation::Holders => "holders",
            Relation::Slaves => "slaves",
        };
        let dir = self.class_block().join(name).join(rel);
        if !dir.exists() {
            return Vec::new();
        }
        fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn btrfs_member_devices(&self) -> Vec<String> {
        let btrfs_sys = self.ctx.sys_root.join("fs/btrfs");
        let mut out = Vec::new();
        if btrfs_sys.exists() {
            if let Ok(entries) = fs::read_dir(&btrfs_sys) {
                for entry in entries.flatten() {
                    let devices_dir = entry.path().join("devices");
                    if devices_dir.exists() {
                        if let Ok(dev_entries) = fs::read_dir(&devices_dir) {
                            for dev_entry in dev_entries.flatten() {
                                out.push(dev_entry.file_name().to_string_lossy().to_string());
                            }
                        }
                    }
                }
            }
        }
        out
    }

    fn sysfs_root_display(&self) -> String {
        self.ctx.sys_root.display().to_string()
    }

    fn device_file_path(&self, device: &str, canonical: &str) -> PathBuf {
        if self.ctx.dev_root != Path::new("/dev") {
            let rel = device.strip_prefix("/dev/").unwrap_or(device);
            self.ctx.dev_root.join(rel)
        } else {
            PathBuf::from(canonical)
        }
    }

    fn stat_backing_device(&self, path: &str) -> Option<(u32, u32)> {
        // Historic gate: only the real system's /proc has meaningful st_dev
        // resolution for swap files; fixture contexts return None.
        if self.ctx.proc_root == Path::new("/proc") {
            fs::metadata(path)
                .ok()
                .map(|m| (dev_major(m.dev()), dev_minor(m.dev())))
        } else {
            None
        }
    }

    fn read_raw(&self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>, BackendError> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = fs::File::open(path).map_err(|e| BackendError::Io(e.to_string()))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| BackendError::Io(e.to_string()))?;
        let mut buf = vec![0u8; len as usize];
        file.read_exact(&mut buf)
            .map_err(|e| BackendError::Io(e.to_string()))?;
        Ok(buf)
    }

    fn stat_path(&self, path: &str) -> Result<StatFact, BackendError> {
        let meta = fs::metadata(path).map_err(|e| BackendError::Io(e.to_string()))?;
        let mode = meta.mode();
        Ok(StatFact {
            rdev: meta.rdev(),
            ino: meta.ino(),
            is_block: (mode & libc::S_IFMT) == libc::S_IFBLK,
            is_regular: (mode & libc::S_IFMT) == libc::S_IFREG,
        })
    }

    fn probe_exclusive_open(
        &self,
        canonical_path: &str,
        device: &str,
    ) -> Result<StatFact, ExecuteError> {
        // Verbatim historic O_EXCL probe: open, map EBUSY, fstat, close,
        // require block-or-regular.
        let c_path = std::ffi::CString::new(canonical_path)
            .map_err(|e| ExecuteError::CommandFailed(format!("Invalid path CString: {}", e)))?;

        unsafe {
            let fd = libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_EXCL | libc::O_CLOEXEC,
            );
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(map_open_excl_error(err, device));
            }

            let mut stat_buf: libc::stat = std::mem::zeroed();
            let res = libc::fstat(fd, &mut stat_buf);
            libc::close(fd);

            if res < 0 {
                return Err(ExecuteError::CommandFailed(format!(
                    "fstat failed on device {}: {}",
                    device,
                    std::io::Error::last_os_error()
                )));
            }

            let mode = stat_buf.st_mode;
            let is_blk = (mode & libc::S_IFMT) == libc::S_IFBLK;
            let is_reg = (mode & libc::S_IFMT) == libc::S_IFREG;
            if !is_blk && !is_reg {
                return Err(ExecuteError::UnsupportedOperation(format!(
                    "Device {} is neither a block device nor a regular file",
                    device
                )));
            }

            Ok(StatFact {
                rdev: stat_buf.st_rdev,
                ino: stat_buf.st_ino,
                is_block: is_blk,
                is_regular: is_reg,
            })
        }
    }

    fn exec(&self, program: &str, args: &[&str]) -> Result<(String, String, i32), BackendError> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| BackendError::Io(e.to_string()))?;
        Ok((
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            output.status.code().unwrap_or(-1),
        ))
    }

    // -- Actions -----------------------------------------------------------
    // `unmount`, `device_geometry` and `read_at` come from the trait's
    // shared default methods (composed from the facts above).

    fn open_exclusive(&self, target: &ValidatedTarget) -> Result<ExclusiveHandle, BackendError> {
        let path = target.canonical_path().to_string();
        let writer =
            DirectBlockWriter::open(&path, target.guard_identity()).map_err(|e| {
                BackendError::Io(match &e {
                    // Preserve the raw message body for diagnostics.
                    ExecuteError::CommandFailed(m)
                    | ExecuteError::DeviceNotFound(m)
                    | ExecuteError::UnsupportedOperation(m) => m.clone(),
                    other => other.to_string(),
                })
            })?;
        let io_mode = writer.io_mode();
        let logical_block_size = writer.logical_block_size();
        let reader = fs::File::open(&path).map_err(|e| BackendError::Io(e.to_string()))?;
        Ok(ExclusiveHandle::new(
            target.clone(),
            path,
            io_mode,
            logical_block_size,
            Box::new(writer),
            Box::new(StdFileReader { file: reader }),
        ))
    }

    fn discard_range(
        &self,
        handle: &ExclusiveHandle,
        offset: u64,
        len: u64,
    ) -> Result<(), BackendError> {
        // Primitive: issue BLKDISCARD for exactly [offset, offset+len) on an
        // O_EXCL reopen of the validated target. Alignment/chunking policy
        // belongs to shared code, not here.
        let path = handle.path();
        let c_path = std::ffi::CString::new(path)
            .map_err(|e| BackendError::Io(format!("Invalid path: {}", e)))?;
        let fd =
            unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_EXCL | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(BackendError::Io(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let mut range: [u64; 2] = [offset, len];
        let res = unsafe { libc::ioctl(fd, BLKDISCARD, range.as_mut_ptr()) };
        let ioctl_err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        if res < 0 {
            return Err(BackendError::Io(ioctl_err.to_string()));
        }
        Ok(())
    }
}
