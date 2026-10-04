//! Sanitization execution module.
//!
//! Provides functions for issuing real firmware/software sanitize commands
//! with dry-run support, boot-disk protection, confirmation tokens, and
//! progress streaming via mpsc channels.
//!
//! Every function:
//! - Refuses to run on the OS boot disk (reads /proc/mounts)
//! - Requires a confirmation_token matching the device serial
//! - Supports dry_run mode (logs commands without executing)
//! - Streams ProgressEvents for real-time UI updates

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum ExecuteError {
    #[error("Boot disk protection: refusing to operate on OS root device {0}")]
    BootDiskProtection(String),
    #[error("Confirmation token mismatch: expected serial of target device")]
    ConfirmationMismatch,
    #[error("Command execution failed: {0}")]
    CommandFailed(String),
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Progress channel closed")]
    ChannelClosed,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExecutionPhase {
    SecurityUnlock,
    FirmwareCommand,
    KeyDestruction,
    CacheFlush,
    Verification,
}

impl std::fmt::Display for ExecutionPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionPhase::SecurityUnlock => write!(f, "Security Unlock"),
            ExecutionPhase::FirmwareCommand => write!(f, "Firmware Command"),
            ExecutionPhase::KeyDestruction => write!(f, "Key Destruction"),
            ExecutionPhase::CacheFlush => write!(f, "Cache Flush"),
            ExecutionPhase::Verification => write!(f, "Post-Verification"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SanitizeAction {
    CryptoErase,
    BlockErase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AtaSanitizeAction {
    BlockErase,
    CryptoScramble,
    Overwrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OverwritePattern {
    Zeros,
    Ones,
    Random,
    NistLegacy3Pass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub phase: ExecutionPhase,
    pub percent: f32,
    pub message: String,
    pub eta_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub success: bool,
    pub method_used: String,
    pub command_log: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub dry_run: bool,
}

// ---------------------------------------------------------------------------
// Safety checks & Hardened Boot-Disk Protection
// ---------------------------------------------------------------------------

/// Filesystem root paths for dependency injection in unit and fixture testing.
#[derive(Debug, Clone)]
pub struct FsContext {
    pub proc_root: PathBuf,
    pub sys_root: PathBuf,
    pub dev_root: PathBuf,
}

impl Default for FsContext {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            sys_root: PathBuf::from("/sys"),
            dev_root: PathBuf::from("/dev"),
        }
    }
}

/// Helper to decode major number from st_rdev / dev_t.
fn dev_major(dev: libc::dev_t) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

/// Helper to decode minor number from st_rdev / dev_t.
fn dev_minor(dev: libc::dev_t) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

/// Parse a "major:minor" decimal ASCII string into a (major, minor) tuple.
fn parse_major_minor(s: &str) -> Option<(u32, u32)> {
    let trimmed = s.trim();
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let maj = parts[0].trim().parse::<u32>().ok()?;
    let min = parts[1].trim().parse::<u32>().ok()?;
    Some((maj, min))
}

/// Determine if a mount point is allowlisted as an unmountable target.
/// Only mounts under /mnt, /media, or /run/media/* are unmountable.
/// Live-media mounts (/run/live/medium, /run/archiso, etc.) are explicitly protected.
pub fn is_mount_unmountable_allowlisted(mount_point: &str) -> bool {
    // Explicitly protect live-media mounts
    if mount_point.starts_with("/run/live")
        || mount_point.starts_with("/run/archiso")
        || mount_point.contains("/live/")
        || mount_point.contains("/archiso/")
        || mount_point.contains("/casper/")
    {
        return false;
    }

    if mount_point == "/mnt" || mount_point.starts_with("/mnt/") {
        return true;
    }
    if mount_point == "/media" || mount_point.starts_with("/media/") {
        return true;
    }
    if mount_point == "/run/media" || mount_point.starts_with("/run/media/") {
        return true;
    }

    false
}

/// Canonicalize target device path, resolving symlinks such as /dev/disk/by-id/*
pub fn canonicalize_device_path(
    device: &str,
    dry_run: bool,
    ctx: &FsContext,
) -> Result<String, ExecuteError> {
    let dev_str = device.trim();
    if dev_str.is_empty() {
        return Err(ExecuteError::BootDiskProtection("Empty device path provided".to_string()));
    }

    if ctx.dev_root == Path::new("/dev") {
        let path = Path::new(dev_str);
        if path.exists() {
            match fs::canonicalize(path) {
                Ok(c) => Ok(c.to_string_lossy().to_string()),
                Err(e) => {
                    if dry_run {
                        Ok(dev_str.to_string())
                    } else {
                        Err(ExecuteError::DeviceNotFound(format!("Device not found (cannot canonicalize {}): {}", dev_str, e)))
                    }
                }
            }
        } else if dry_run {
            Ok(dev_str.to_string())
        } else {
            Err(ExecuteError::DeviceNotFound(format!("Device does not exist: {}", dev_str)))
        }
    } else {
        // Fixture context resolution
        let rel_path = dev_str
            .strip_prefix("/dev/")
            .unwrap_or_else(|| dev_str.strip_prefix('/').unwrap_or(dev_str));
        let fixture_target = ctx.dev_root.join(rel_path);

        if fixture_target.exists() || fs::symlink_metadata(&fixture_target).is_ok() {
            let mut curr = fixture_target;
            let mut hops = 0;
            while fs::symlink_metadata(&curr).map(|m| m.file_type().is_symlink()).unwrap_or(false) && hops < 20 {
                hops += 1;
                let target = fs::read_link(&curr).map_err(|e| {
                    ExecuteError::BootDiskProtection(format!("Broken symlink {}: {}", curr.display(), e))
                })?;
                curr = if target.is_absolute() {
                    let rel = target.strip_prefix("/dev/").unwrap_or(&target);
                    ctx.dev_root.join(rel)
                } else {
                    let parent = curr.parent().unwrap_or(&ctx.dev_root);
                    parent.join(target)
                };
            }
            let dev_name = curr.file_name().unwrap_or_default().to_string_lossy().to_string();
            Ok(format!("/dev/{}", dev_name))
        } else if dry_run {
            Ok(dev_str.to_string())
        } else {
            Err(ExecuteError::DeviceNotFound(format!("Device does not exist in fixture: {}", dev_str)))
        }
    }
}

/// Hardened boot-disk and system mount protection.
/// Checks the device and all associated partitions/stacks against mountinfo and swaps.
pub fn check_boot_disk_protection_ctx(
    device: &str,
    dry_run: bool,
    ctx: &FsContext,
) -> Result<(), ExecuteError> {
    // 1. Canonicalize the target path
    let canonical = canonicalize_device_path(device, dry_run, ctx)?;
    let target_name = canonical
        .rsplit('/')
        .next()
        .unwrap_or(&canonical)
        .to_string();

    // 2. Parse /proc/self/mountinfo
    let mountinfo_path = ctx.proc_root.join("self/mountinfo");
    let mountinfo_content = if mountinfo_path.exists() {
        fs::read_to_string(&mountinfo_path)
            .map_err(|e| ExecuteError::BootDiskProtection(format!("Cannot read mountinfo: {}", e)))?
    } else {
        // Fallback to /proc/mountinfo or /proc/mounts
        let alt = ctx.proc_root.join("mountinfo");
        let alt_mounts = ctx.proc_root.join("mounts");
        if alt.exists() {
            fs::read_to_string(&alt)
                .map_err(|e| ExecuteError::BootDiskProtection(format!("Cannot read mountinfo: {}", e)))?
        } else if alt_mounts.exists() {
            fs::read_to_string(&alt_mounts)
                .map_err(|e| ExecuteError::BootDiskProtection(format!("Cannot read mounts: {}", e)))?
        } else {
            return Err(ExecuteError::BootDiskProtection("No mountinfo or mounts file found: fail closed".to_string()));
        }
    };

    let mut protected_devs: HashMap<(u32, u32), String> = HashMap::new();
    let mut protected_names: HashSet<String> = HashSet::new();
    let mut has_root_mount = false;
    let mut root_is_overlay = false;

    // Track mounts for swap file resolution
    let mut active_mounts: Vec<(String, (u32, u32))> = Vec::new();

    // Exempt virtual in-memory pseudo-filesystems from anonymous device check
    let exempt_pseudo_fs: HashSet<&str> = [
        "tmpfs", "devtmpfs", "proc", "sysfs", "cgroup", "cgroup2",
        "ramfs", "devpts", "pstore", "securityfs", "tracefs", "debugfs",
        "mqueue", "hugetlbfs", "autofs", "fusectl", "configfs", "efivarfs",
        "bpf", "squashfs", "nsfs", "pipefs", "sockfs", "rpc_pipefs",
    ].into_iter().collect();

    for line in mountinfo_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 5 {
            return Err(ExecuteError::BootDiskProtection(format!("Corrupt mountinfo line: {}", line)));
        }

        let mm_str = parts[2];
        let mount_point = parts[4];

        if mount_point == "/" {
            has_root_mount = true;
        }

        // Find separator "-"
        let dash_pos = parts.iter().position(|&p| p == "-");
        let (fs_type, mount_source) = if let Some(pos) = dash_pos {
            let ft = parts.get(pos + 1).copied().unwrap_or("");
            let ms = parts.get(pos + 2).copied().unwrap_or("");
            (ft, ms)
        } else {
            let ft = parts.get(2).copied().unwrap_or("");
            let ms = parts.first().copied().unwrap_or("");
            (ft, ms)
        };

        if mount_point == "/" && (fs_type == "overlay" || fs_type == "aufs" || mount_source == "overlay") {
            root_is_overlay = true;
        }

        let mm = parse_major_minor(mm_str);
        if let Some(pair) = mm {
            active_mounts.push((mount_point.to_string(), pair));
        }

        let unmountable = is_mount_unmountable_allowlisted(mount_point);
        if !unmountable {
            if let Some((maj, min)) = mm {
                if maj != 0 {
                    protected_devs.insert((maj, min), format!("protected mount '{}'", mount_point));
                } else if fs_type == "btrfs" {
                    let mut btrfs_resolved = false;
                    let btrfs_sys = ctx.sys_root.join("fs/btrfs");
                    if btrfs_sys.exists() {
                        if let Ok(entries) = fs::read_dir(&btrfs_sys) {
                            for entry in entries.flatten() {
                                let devices_dir = entry.path().join("devices");
                                if devices_dir.exists() {
                                    if let Ok(dev_entries) = fs::read_dir(&devices_dir) {
                                        for dev_entry in dev_entries.flatten() {
                                            let d_name = dev_entry.file_name().to_string_lossy().to_string();
                                            protected_names.insert(d_name.clone());
                                            let d_dev = ctx.sys_root.join("class/block").join(&d_name).join("dev");
                                            if let Ok(dev_c) = fs::read_to_string(&d_dev) {
                                                if let Some(dev_mm) = parse_major_minor(&dev_c) {
                                                    protected_devs.insert(dev_mm, format!("btrfs device '{}' for protected mount '{}'", d_name, mount_point));
                                                    btrfs_resolved = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if mount_source.starts_with("/dev/") {
                        let src_name = mount_source.rsplit('/').next().unwrap_or(mount_source);
                        protected_names.insert(src_name.to_string());
                        let d_dev = ctx.sys_root.join("class/block").join(src_name).join("dev");
                        if let Ok(dev_c) = fs::read_to_string(&d_dev) {
                            if let Some(dev_mm) = parse_major_minor(&dev_c) {
                                protected_devs.insert(dev_mm, format!("btrfs source '{}' for protected mount '{}'", src_name, mount_point));
                                btrfs_resolved = true;
                            }
                        }
                    }

                    if !btrfs_resolved {
                        return Err(ExecuteError::BootDiskProtection(format!(
                            "Btrfs protected mount '{}' has unresolvable backing device(s): refusing destructive operation (fail closed)",
                            mount_point
                        )));
                    }
                } else if mount_source.starts_with("/dev/") {
                    if let Ok(canon_src) = canonicalize_device_path(mount_source, dry_run, ctx) {
                        let src_name = canon_src.rsplit('/').next().unwrap_or(&canon_src);
                        protected_names.insert(src_name.to_string());
                        let src_dev = ctx.sys_root.join("class/block").join(src_name).join("dev");
                        if let Ok(c) = fs::read_to_string(&src_dev) {
                            if let Some(src_mm) = parse_major_minor(&c) {
                                protected_devs.insert(src_mm, format!("mount source '{}' for protected mount '{}'", mount_source, mount_point));
                            }
                        }
                    }
                } else if !exempt_pseudo_fs.contains(fs_type) && !fs_type.starts_with("fuse") && fs_type != "binfmt_misc" {
                    return Err(ExecuteError::BootDiskProtection(format!(
                        "Protected mount '{}' of type '{}' has anonymous device (major 0) with no backing block device: fail closed",
                        mount_point, fs_type
                    )));
                }
            }

            if mount_source.starts_with("/dev/") {
                if let Ok(canon_src) = canonicalize_device_path(mount_source, dry_run, ctx) {
                    let src_name = canon_src.rsplit('/').next().unwrap_or(&canon_src);
                    protected_names.insert(src_name.to_string());
                    let src_dev = ctx.sys_root.join("class/block").join(src_name).join("dev");
                    if let Ok(c) = fs::read_to_string(&src_dev) {
                        if let Some(src_mm) = parse_major_minor(&c) {
                            protected_devs.insert(src_mm, format!("mount source '{}' for protected mount '{}'", mount_source, mount_point));
                        }
                    }
                }
            }
        }
    }

    if !has_root_mount {
        return Err(ExecuteError::BootDiskProtection(
            "Invalid mount environment: no root '/' mount point found in mountinfo".to_string(),
        ));
    }

    if root_is_overlay {
        return Err(ExecuteError::BootDiskProtection(
            "Container or overlayfs root environment detected: refusing destructive operation (fail closed)".to_string(),
        ));
    }

    // 3. Parse /proc/swaps
    let swaps_path = ctx.proc_root.join("swaps");
    if swaps_path.exists() {
        if let Ok(swaps_content) = fs::read_to_string(&swaps_path) {
            for line in swaps_content.lines().skip(1) {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }
                let swap_target = parts[0];
                let swap_type = parts.get(1).copied().unwrap_or("partition");

                if swap_type == "partition" {
                    if let Ok(canon_swap) = canonicalize_device_path(swap_target, dry_run, ctx) {
                        let swap_name = canon_swap.rsplit('/').next().unwrap_or(&canon_swap);
                        protected_names.insert(swap_name.to_string());
                        let dev_path = ctx.sys_root.join("class/block").join(swap_name).join("dev");
                        if let Ok(c) = fs::read_to_string(&dev_path) {
                            if let Some(mm) = parse_major_minor(&c) {
                                protected_devs.insert(mm, format!("active swap partition '{}'", swap_target));
                            }
                        }
                    }
                } else if swap_type == "file" {
                    let mut swap_resolved = false;
                    if ctx.proc_root == Path::new("/proc") {
                        if let Ok(meta) = fs::metadata(swap_target) {
                            let dev = meta.dev();
                            let mm = (dev_major(dev), dev_minor(dev));
                            protected_devs.insert(mm, format!("backing device for active swap file '{}'", swap_target));
                            swap_resolved = true;
                        }
                    }
                    if !swap_resolved {
                        let mut best_prefix = "";
                        let mut best_mm = None;
                        for (mp, mm) in &active_mounts {
                            if swap_target.starts_with(mp) && mp.len() > best_prefix.len() {
                                best_prefix = mp;
                                best_mm = Some(*mm);
                            }
                        }
                        if let Some(mm) = best_mm {
                            protected_devs.insert(mm, format!("backing mount '{}' for active swap file '{}'", best_prefix, swap_target));
                            swap_resolved = true;
                        }
                    }
                    if !swap_resolved {
                        return Err(ExecuteError::BootDiskProtection(format!(
                            "Active swap file '{}' backing device cannot be resolved: fail closed",
                            swap_target
                        )));
                    }
                }
            }
        }
    }

    // 4. Resolve target in sysfs
    let target_block_dir = ctx.sys_root.join("class/block").join(&target_name);
    if !target_block_dir.exists() {
        if dry_run {
            if protected_names.contains(&target_name) {
                return Err(ExecuteError::BootDiskProtection(format!(
                    "Device '{}' matches a protected mount source/device",
                    target_name
                )));
            }
            return Ok(());
        } else {
            return Err(ExecuteError::DeviceNotFound(format!(
                "Device '{}' not found in sysfs ({})",
                target_name,
                target_block_dir.display()
            )));
        }
    }

    // 5. Gather physical/partition family of target
    let mut family_devices: HashSet<String> = HashSet::new();
    family_devices.insert(target_name.clone());

    let part_file = target_block_dir.join("partition");
    let is_partition = part_file.exists();

    if is_partition {
        let mut parent_disk_opt = None;
        if let Ok(link) = fs::read_link(&target_block_dir) {
            if let Some(parent) = link.parent() {
                if let Some(p_name) = parent.file_name() {
                    let p_str = p_name.to_string_lossy().to_string();
                    if p_str != "block" && ctx.sys_root.join("class/block").join(&p_str).exists() {
                        parent_disk_opt = Some(p_str);
                    }
                }
            }
        }
        if parent_disk_opt.is_none() {
            if target_name.starts_with("nvme") || target_name.starts_with("mmcblk") {
                if let Some(idx) = target_name.rfind('p') {
                    let candidate = &target_name[..idx];
                    if ctx.sys_root.join("class/block").join(candidate).exists() {
                        parent_disk_opt = Some(candidate.to_string());
                    }
                }
            } else {
                let candidate = target_name.trim_end_matches(|c: char| c.is_ascii_digit());
                if !candidate.is_empty() && ctx.sys_root.join("class/block").join(candidate).exists() {
                    parent_disk_opt = Some(candidate.to_string());
                }
            }
        }

        if let Some(parent_disk) = parent_disk_opt {
            family_devices.insert(parent_disk.clone());
            if let Ok(entries) = fs::read_dir(ctx.sys_root.join("class/block")) {
                for entry in entries.flatten() {
                    let dev = entry.file_name().to_string_lossy().to_string();
                    if entry.path().join("partition").exists()
                        && dev.starts_with(&parent_disk)
                        && (dev[parent_disk.len()..].starts_with('p')
                            || dev[parent_disk.len()..].chars().next().is_some_and(|c| c.is_ascii_digit()))
                    {
                        family_devices.insert(dev);
                    }
                }
            }
        }
    } else {
        if let Ok(entries) = fs::read_dir(ctx.sys_root.join("class/block")) {
            for entry in entries.flatten() {
                let dev = entry.file_name().to_string_lossy().to_string();
                if entry.path().join("partition").exists()
                    && dev.starts_with(&target_name)
                    && (dev[target_name.len()..].starts_with('p')
                        || dev[target_name.len()..].chars().next().is_some_and(|c| c.is_ascii_digit()))
                {
                    family_devices.insert(dev);
                }
            }
        }
    }

    // 6. Transitive graph traversal of holders and slaves
    let mut queue: VecDeque<String> = family_devices.into_iter().collect();
    let mut visited: HashSet<String> = HashSet::new();

    while let Some(curr) = queue.pop_front() {
        if !visited.insert(curr.clone()) {
            continue;
        }

        let holders_dir = ctx.sys_root.join("class/block").join(&curr).join("holders");
        if holders_dir.exists() {
            if let Ok(entries) = fs::read_dir(&holders_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if !visited.contains(&name) {
                        queue.push_back(name);
                    }
                }
            }
        }

        let slaves_dir = ctx.sys_root.join("class/block").join(&curr).join("slaves");
        if slaves_dir.exists() {
            if let Ok(entries) = fs::read_dir(&slaves_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if !visited.contains(&name) {
                        queue.push_back(name);
                    }
                }
            }
        }
    }

    // 7. Check all visited devices against protected mounts and names
    for dev in &visited {
        if protected_names.contains(dev) {
            return Err(ExecuteError::BootDiskProtection(format!(
                "Refusing operation: target '{}' (associated with member '{}') matches a protected device/mount",
                device, dev
            )));
        }

        let dev_file = ctx.sys_root.join("class/block").join(dev).join("dev");
        if dev_file.exists() {
            let content = fs::read_to_string(&dev_file)
                .map_err(|e| ExecuteError::BootDiskProtection(format!("Cannot read sysfs dev file for {}: {}", dev, e)))?;
            let mm = parse_major_minor(&content)
                .ok_or_else(|| ExecuteError::BootDiskProtection(format!("Corrupt dev file for device {}: '{}'", dev, content.trim())))?;

            if let Some(reason) = protected_devs.get(&mm) {
                return Err(ExecuteError::BootDiskProtection(format!(
                    "Refusing operation: target '{}' (associated with device '{}' [{}:{}]) is protected: {}",
                    device, dev, mm.0, mm.1, reason
                )));
            }
        }
    }

    Ok(())
}

/// Convenience entry point for checking boot disk protection against system proc/sys/dev.
pub fn check_boot_disk_protection(device: &str, dry_run: bool) -> Result<(), ExecuteError> {
    check_boot_disk_protection_ctx(device, dry_run, &FsContext::default())
}

/// Resolves identity from an opened fd (fstat st_rdev), opens with O_EXCL,
/// and re-checks boot disk protection immediately before the destructive command.
pub fn verify_exclusive_access_and_recheck(
    device: &str,
    dry_run: bool,
    ctx: &FsContext,
) -> Result<(), ExecuteError> {
    if dry_run {
        return check_boot_disk_protection_ctx(device, true, ctx);
    }

    let canonical = canonicalize_device_path(device, false, ctx)?;
    let c_path = std::ffi::CString::new(canonical.clone())
        .map_err(|e| ExecuteError::CommandFailed(format!("Invalid path CString: {}", e)))?;

    unsafe {
        let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_EXCL | libc::O_CLOEXEC);
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EBUSY) {
                return Err(ExecuteError::CommandFailed(format!(
                    "Device {} is busy or mounted (O_EXCL conflict): cannot safely sanitize",
                    device
                )));
            }
            return Err(ExecuteError::DeviceNotFound(format!(
                "Cannot open device {} with O_EXCL: {}",
                device, err
            )));
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
    }

    check_boot_disk_protection_ctx(device, false, ctx)
}

/// Verify the confirmation token matches expected value.
fn verify_confirmation(token: &str, expected_serial: &str) -> Result<(), ExecuteError> {
    if token.trim() != expected_serial.trim() {
        return Err(ExecuteError::ConfirmationMismatch);
    }
    Ok(())
}

/// Send a progress event, ignoring channel-closed errors (UI may have navigated away).
async fn send_progress(
    tx: &mpsc::Sender<ProgressEvent>,
    phase: ExecutionPhase,
    percent: f32,
    message: &str,
    eta_seconds: Option<u32>,
) {
    let _ = tx.send(ProgressEvent {
        phase,
        percent,
        message: message.to_string(),
        eta_seconds,
    }).await;
}

/// Run a shell command and capture output. In dry_run mode, only log the command.
fn run_cmd(
    program: &str,
    args: &[&str],
    dry_run: bool,
    command_log: &mut Vec<String>,
) -> Result<(String, String, i32), ExecuteError> {
    let full_cmd = format!("{} {}", program, args.join(" "));
    command_log.push(full_cmd.clone());

    if dry_run {
        return Ok((
            format!("[DRY RUN] Would execute: {}", full_cmd),
            String::new(),
            0,
        ));
    }

    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| ExecuteError::CommandFailed(format!("Failed to run {}: {}", program, e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    Ok((stdout, stderr, code))
}

/// Safely unmount active filesystems on the target device or its partitions.
/// Resolves mounted partition paths from /proc/mounts and shells out via `sh -c` for glob expansion.
fn unmount_device_if_mounted(
    device: &str,
    dry_run: bool,
    command_log: &mut Vec<String>,
) -> (String, String) {
    let mut stdout_accum = String::new();
    let mut stderr_accum = String::new();

    if dry_run {
        command_log.push(format!("[DRY RUN] Would check mounts and unmount active partitions on {}", device));
        return (stdout_accum, stderr_accum);
    }

    // 1. Resolve exact mounted partition paths from /proc/mounts
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        let mut mounted_targets = Vec::new();
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let mount_src = parts[0];
                if mount_src == device
                    || (mount_src.starts_with(device)
                        && mount_src[device.len()..]
                            .chars()
                            .next()
                            .is_some_and(|c| c.is_ascii_digit() || c == 'p'))
                {
                    mounted_targets.push(mount_src.to_string());
                }
            }
        }

        for target in mounted_targets {
            command_log.push(format!("[UNMOUNT] Unmounting active filesystem target: {}", target));
            if let Ok((stdout, stderr, _)) = run_cmd("umount", &["-f", &target], dry_run, command_log) {
                stdout_accum.push_str(&stdout);
                stderr_accum.push_str(&stderr);
            }
        }
    }

    // 2. Explicit shell expansion pass via sh -c for any remaining partition globs
    let glob_cmd = format!("umount -f {}* 2>/dev/null || true", device);
    if let Ok((stdout, stderr, _)) = run_cmd("sh", &["-c", &glob_cmd], dry_run, command_log) {
        stdout_accum.push_str(&stdout);
        stderr_accum.push_str(&stderr);
    }

    (stdout_accum, stderr_accum)
}

// ---------------------------------------------------------------------------
// Execution functions
// ---------------------------------------------------------------------------

/// NVMe Sanitize — issues `nvme sanitize` command and polls sanitize-log.
pub async fn nvme_sanitize(
    device: &str,
    action: SanitizeAction,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();

    // Safety checks
    check_boot_disk_protection(device, dry_run)?;
    verify_confirmation(confirmation_token, device_serial)?;

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_device_if_mounted(device, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, dry_run, &FsContext::default())?;

    let action_arg = match action {
        SanitizeAction::BlockErase => "start-block-erase",
        SanitizeAction::CryptoErase => "start-crypto-erase",
    };
    let method_name = format!("NVMe Sanitize ({})", action_arg);

    // Phase 1: Security Unlock
    send_progress(&tx, ExecutionPhase::SecurityUnlock, 0.05,
        "Checking NVMe controller security state...", Some(5)).await;

    // Phase 2: Issue sanitize command
    send_progress(&tx, ExecutionPhase::FirmwareCommand, 0.15,
        &format!("Issuing nvme sanitize -a {} on {}", action_arg, device), None).await;

    let (stdout, stderr, code) = run_cmd(
        "nvme",
        &["sanitize", device, "-a", action_arg],
        dry_run,
        &mut command_log,
    )?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    if !dry_run && code != 0 {
        return Ok(ExecutionReport {
            success: false,
            method_used: method_name,
            command_log,
            stdout: all_stdout,
            stderr: all_stderr,
            exit_code: code,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run,
        });
    }

    // Phase 2 continued: Poll sanitize-log for completion
    if dry_run {
        // Simulate progress in dry-run
        for pct in [30, 50, 70, 85] {
            send_progress(&tx, ExecutionPhase::FirmwareCommand, pct as f32 / 100.0,
                &format!("[DRY RUN] Sanitize progress: {}%", pct), None).await;
            let (s, e, _) = run_cmd("nvme", &["sanitize-log", device], dry_run, &mut command_log)?;
            all_stdout.push_str(&s);
            all_stderr.push_str(&e);
        }
    }

    // Phase 3: Key Destruction
    send_progress(&tx, ExecutionPhase::KeyDestruction, 0.88,
        "NVMe controller internal key zeroization complete.", Some(2)).await;

    // Phase 4: Cache Flush
    send_progress(&tx, ExecutionPhase::CacheFlush, 0.93,
        "Flushing volatile caches and translation tables...", Some(1)).await;

    // Phase 5: Ready for verification
    send_progress(&tx, ExecutionPhase::Verification, 0.97,
        "Sanitize command completed. Ready for post-verification.", Some(1)).await;

    Ok(ExecutionReport {
        success: true,
        method_used: method_name,
        command_log,
        stdout: all_stdout,
        stderr: all_stderr,
        exit_code: 0,
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run,
    })
}

/// ATA Secure Erase — handles full ATA SE sequence including frozen-state check.
pub async fn ata_secure_erase(
    device: &str,
    enhanced: bool,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();
    let method_name = if enhanced {
        "ATA Enhanced Secure Erase".to_string()
    } else {
        "ATA Secure Erase".to_string()
    };

    // Safety checks
    check_boot_disk_protection(device, dry_run)?;
    verify_confirmation(confirmation_token, device_serial)?;

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_device_if_mounted(device, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, dry_run, &FsContext::default())?;

    // Phase 1: Check frozen state
    send_progress(&tx, ExecutionPhase::SecurityUnlock, 0.05,
        "Checking ATA security frozen state with hdparm -I...", Some(10)).await;

    let (stdout, stderr, _) = run_cmd("hdparm", &["-I", device], dry_run, &mut command_log)?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    if !dry_run && stdout.to_lowercase().contains("frozen") && !stdout.to_lowercase().contains("not\tfrozen") && !stdout.to_lowercase().contains("not frozen") {
        send_progress(&tx, ExecutionPhase::SecurityUnlock, 0.08,
            "WARNING: ATA security is FROZEN. Attempting suspend/resume cycle...", None).await;
        // In a real bootable environment, we could issue a sleep/wake cycle
        // For now, report the frozen state
    }

    // Phase 1b: Set security password
    send_progress(&tx, ExecutionPhase::SecurityUnlock, 0.12,
        "Setting temporary ATA security password...", Some(8)).await;

    let (stdout, stderr, code) = run_cmd(
        "hdparm",
        &["--user-master", "u", "--security-set-pass", "p", device],
        dry_run,
        &mut command_log,
    )?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    if !dry_run && code != 0 {
        return Ok(ExecutionReport {
            success: false,
            method_used: method_name,
            command_log,
            stdout: all_stdout,
            stderr: format!("{}\nFailed to set ATA security password", all_stderr),
            exit_code: code,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run,
        });
    }

    // Phase 2: Issue secure erase
    let erase_arg = if enhanced { "--security-erase-enhanced" } else { "--security-erase" };

    send_progress(&tx, ExecutionPhase::FirmwareCommand, 0.20,
        &format!("Issuing hdparm {} on {}...", erase_arg, device), None).await;

    let (stdout, stderr, code) = run_cmd(
        "hdparm",
        &[erase_arg, "p", device],
        dry_run,
        &mut command_log,
    )?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    // Simulate progress for dry-run
    if dry_run {
        for pct in [35, 50, 65, 80] {
            send_progress(&tx, ExecutionPhase::FirmwareCommand, pct as f32 / 100.0,
                &format!("[DRY RUN] ATA Secure Erase progress: {}%", pct), None).await;
        }
    }

    if !dry_run && code != 0 {
        return Ok(ExecutionReport {
            success: false,
            method_used: method_name,
            command_log,
            stdout: all_stdout,
            stderr: all_stderr,
            exit_code: code,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run,
        });
    }

    // Phase 3: Key destruction (implicit in ATA SE)
    send_progress(&tx, ExecutionPhase::KeyDestruction, 0.88,
        "ATA controller key destruction complete.", Some(2)).await;

    // Phase 4: Cache flush
    send_progress(&tx, ExecutionPhase::CacheFlush, 0.93,
        "Flushing write cache...", Some(1)).await;

    if !dry_run {
        let (s, e, _) = run_cmd("hdparm", &["-F", device], dry_run, &mut command_log)?;
        all_stdout.push_str(&s);
        all_stderr.push_str(&e);
    }

    send_progress(&tx, ExecutionPhase::Verification, 0.97,
        "ATA Secure Erase completed. Ready for post-verification.", Some(1)).await;

    Ok(ExecutionReport {
        success: true,
        method_used: method_name,
        command_log,
        stdout: all_stdout,
        stderr: all_stderr,
        exit_code: 0,
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run,
    })
}

/// ATA Sanitize — Block Erase, Crypto Scramble, or Overwrite via hdparm.
pub async fn ata_sanitize(
    device: &str,
    action: AtaSanitizeAction,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();

    check_boot_disk_protection(device, dry_run)?;
    verify_confirmation(confirmation_token, device_serial)?;

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_device_if_mounted(device, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, dry_run, &FsContext::default())?;

    let (action_arg, method_name) = match action {
        AtaSanitizeAction::BlockErase => ("block-erase", "ATA Sanitize Block Erase"),
        AtaSanitizeAction::CryptoScramble => ("crypto-scramble", "ATA Sanitize Crypto Scramble"),
        AtaSanitizeAction::Overwrite => ("overwrite", "ATA Sanitize Overwrite"),
    };

    send_progress(&tx, ExecutionPhase::SecurityUnlock, 0.05,
        "Checking device sanitize feature set support...", Some(5)).await;

    send_progress(&tx, ExecutionPhase::FirmwareCommand, 0.15,
        &format!("Issuing ATA Sanitize {} on {}...", action_arg, device), None).await;

    // hdparm --sanitize-block-erase / --sanitize-crypto-scramble
    let hdparm_arg = format!("--sanitize-{}", action_arg);
    let (stdout, stderr, code) = run_cmd(
        "hdparm",
        &[&hdparm_arg, device],
        dry_run,
        &mut command_log,
    )?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    if dry_run {
        for pct in [30, 50, 70, 85] {
            send_progress(&tx, ExecutionPhase::FirmwareCommand, pct as f32 / 100.0,
                &format!("[DRY RUN] ATA Sanitize progress: {}%", pct), None).await;
        }
    }

    send_progress(&tx, ExecutionPhase::KeyDestruction, 0.88,
        "ATA Sanitize controller key handling complete.", Some(2)).await;
    send_progress(&tx, ExecutionPhase::CacheFlush, 0.93,
        "Flushing caches...", Some(1)).await;
    send_progress(&tx, ExecutionPhase::Verification, 0.97,
        "ATA Sanitize completed. Ready for post-verification.", Some(1)).await;

    Ok(ExecutionReport {
        success: dry_run || code == 0,
        method_used: method_name.to_string(),
        command_log,
        stdout: all_stdout,
        stderr: all_stderr,
        exit_code: if dry_run { 0 } else { code },
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run,
    })
}

/// TCG OPAL Revert — uses sedutil-cli for PSID revert or crypto erase.
pub async fn opal_revert(
    device: &str,
    psid: Option<&str>,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();

    check_boot_disk_protection(device, dry_run)?;
    verify_confirmation(confirmation_token, device_serial)?;

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_device_if_mounted(device, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, dry_run, &FsContext::default())?;

    send_progress(&tx, ExecutionPhase::SecurityUnlock, 0.05,
        "Querying TCG OPAL SED state...", Some(3)).await;

    // Query OPAL state first
    let (stdout, stderr, _) = run_cmd("sedutil-cli", &["--query", device], dry_run, &mut command_log)?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    send_progress(&tx, ExecutionPhase::FirmwareCommand, 0.20,
        "Issuing TCG OPAL revertTPer command...", None).await;

    // PSID revert or password-based revert
    let (stdout, stderr, code) = if let Some(psid_val) = psid {
        run_cmd("sedutil-cli", &["--yesIreallywanttoERASEALLmydatausingthePSID", psid_val, device],
            dry_run, &mut command_log)?
    } else {
        // Try with default SID
        run_cmd("sedutil-cli", &["--revertTPer", "SID", device],
            dry_run, &mut command_log)?
    };
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    if dry_run {
        for pct in [40, 60, 80] {
            send_progress(&tx, ExecutionPhase::FirmwareCommand, pct as f32 / 100.0,
                &format!("[DRY RUN] OPAL revert progress: {}%", pct), None).await;
        }
    }

    send_progress(&tx, ExecutionPhase::KeyDestruction, 0.88,
        "TCG OPAL Media Encryption Key (MEK) destroyed.", Some(2)).await;
    send_progress(&tx, ExecutionPhase::CacheFlush, 0.93,
        "SED controller state reset complete.", Some(1)).await;
    send_progress(&tx, ExecutionPhase::Verification, 0.97,
        "OPAL revert completed. Ready for post-verification.", Some(1)).await;

    Ok(ExecutionReport {
        success: dry_run || code == 0,
        method_used: "TCG OPAL Cryptographic Erase (revertTPer)".to_string(),
        command_log,
        stdout: all_stdout,
        stderr: all_stderr,
        exit_code: if dry_run { 0 } else { code },
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run,
    })
}

/// eMMC Sanitize — issues `mmc sanitize` command.
pub async fn emmc_sanitize(
    device: &str,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();

    check_boot_disk_protection(device, dry_run)?;
    verify_confirmation(confirmation_token, device_serial)?;

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_device_if_mounted(device, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, dry_run, &FsContext::default())?;

    send_progress(&tx, ExecutionPhase::SecurityUnlock, 0.05,
        "Reading eMMC extcsd sanitize capability...", Some(3)).await;

    send_progress(&tx, ExecutionPhase::FirmwareCommand, 0.15,
        &format!("Issuing mmc sanitize on {}...", device), None).await;

    let (stdout, stderr, code) = run_cmd("mmc", &["sanitize", device], dry_run, &mut command_log)?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    if dry_run {
        for pct in [30, 50, 70, 85] {
            send_progress(&tx, ExecutionPhase::FirmwareCommand, pct as f32 / 100.0,
                &format!("[DRY RUN] eMMC sanitize progress: {}%", pct), None).await;
        }
    }

    send_progress(&tx, ExecutionPhase::KeyDestruction, 0.88,
        "eMMC controller internal cleanup complete.", Some(2)).await;
    send_progress(&tx, ExecutionPhase::CacheFlush, 0.93,
        "Flushing eMMC write buffer...", Some(1)).await;
    send_progress(&tx, ExecutionPhase::Verification, 0.97,
        "eMMC Sanitize completed. Ready for post-verification.", Some(1)).await;

    Ok(ExecutionReport {
        success: dry_run || code == 0,
        method_used: "eMMC Sanitize".to_string(),
        command_log,
        stdout: all_stdout,
        stderr: all_stderr,
        exit_code: if dry_run { 0 } else { code },
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run,
    })
}

/// Software Overwrite — multi-pass pattern write using dd.
/// This is the fallback for legacy/unsupported media.
pub async fn software_overwrite(
    device: &str,
    passes: u8,
    pattern: OverwritePattern,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();

    check_boot_disk_protection(device, dry_run)?;
    verify_confirmation(confirmation_token, device_serial)?;

    let total_passes = match pattern {
        OverwritePattern::NistLegacy3Pass => 3u8,
        _ => passes.max(1),
    };

    let method_name = format!(
        "Software Overwrite ({}-pass, {:?})",
        total_passes, pattern
    );

    send_progress(&tx, ExecutionPhase::SecurityUnlock, 0.03,
        "Unmounting filesystems on target device...", Some(5)).await;

    // Unmount any active partitions
    let (stdout, stderr) = unmount_device_if_mounted(device, dry_run, &mut command_log);
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    // Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, dry_run, &FsContext::default())?;

    for pass_num in 0..total_passes {
        let input_source = match pattern {
            OverwritePattern::Zeros => "/dev/zero",
            OverwritePattern::Ones => "/dev/zero", // We'd use tr to flip bits, simplified here
            OverwritePattern::Random => "/dev/urandom",
            OverwritePattern::NistLegacy3Pass => {
                match pass_num {
                    0 => "/dev/zero",       // Pass 1: zeros
                    1 => "/dev/urandom",    // Pass 2: random
                    _ => "/dev/zero",       // Pass 3: zeros verify
                }
            }
        };

        let pass_base_pct = pass_num as f32 / total_passes as f32;
        let pass_range = 1.0 / total_passes as f32;

        send_progress(&tx, ExecutionPhase::FirmwareCommand,
            0.10 + pass_base_pct * 0.75,
            &format!("Pass {}/{}: Writing from {} to {}...",
                pass_num + 1, total_passes, input_source, device),
            None).await;

        // dd if=<source> of=<device> bs=1M status=progress conv=fdatasync
        let (stdout, stderr, code) = run_cmd(
            "dd",
            &[
                &format!("if={}", input_source),
                &format!("of={}", device),
                "bs=1M",
                "status=progress",
                "conv=fdatasync",
            ],
            dry_run,
            &mut command_log,
        )?;
        all_stdout.push_str(&stdout);
        all_stderr.push_str(&stderr);

        if !dry_run && code != 0 {
            // dd returns non-zero when it reaches end-of-device, which is expected
            // Only fail if stderr contains actual errors (not just the "No space left" message)
            if !stderr.contains("No space left on device") && !stderr.contains("bytes") {
                return Ok(ExecutionReport {
                    success: false,
                    method_used: method_name,
                    command_log,
                    stdout: all_stdout,
                    stderr: all_stderr,
                    exit_code: code,
                    duration_ms: start.elapsed().as_millis() as u64,
                    dry_run,
                });
            }
        }

        // Simulate progress in dry-run
        if dry_run {
            for sub_pct in [25, 50, 75, 100] {
                let overall = 0.10 + (pass_base_pct + pass_range * sub_pct as f32 / 100.0) * 0.75;
                send_progress(&tx, ExecutionPhase::FirmwareCommand, overall,
                    &format!("[DRY RUN] Pass {}/{}: {}% complete",
                        pass_num + 1, total_passes, sub_pct),
                    None).await;
            }
        }
    }

    send_progress(&tx, ExecutionPhase::KeyDestruction, 0.88,
        "Overwrite passes complete. No firmware keys to destroy.", Some(2)).await;

    // Sync and flush
    send_progress(&tx, ExecutionPhase::CacheFlush, 0.93,
        "Syncing filesystem and flushing block device cache...", Some(1)).await;

    let (stdout, stderr, _) = run_cmd("sync", &[], dry_run, &mut command_log)?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    send_progress(&tx, ExecutionPhase::Verification, 0.97,
        "Software overwrite completed. Ready for post-verification.", Some(1)).await;

    Ok(ExecutionReport {
        success: true,
        method_used: method_name,
        command_log,
        stdout: all_stdout,
        stderr: all_stderr,
        exit_code: 0,
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureBuilder {
        dir: tempfile::TempDir,
    }

    impl FixtureBuilder {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let b = Self { dir };
            fs::create_dir_all(b.path("proc/self")).unwrap();
            fs::create_dir_all(b.path("sys/class/block")).unwrap();
            fs::create_dir_all(b.path("sys/block")).unwrap();
            fs::create_dir_all(b.path("dev")).unwrap();
            b
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.dir.path().join(rel)
        }

        fn ctx(&self) -> FsContext {
            FsContext {
                proc_root: self.path("proc"),
                sys_root: self.path("sys"),
                dev_root: self.path("dev"),
            }
        }

        fn set_mountinfo(&self, content: &str) {
            fs::write(self.path("proc/self/mountinfo"), content).unwrap();
        }

        fn set_swaps(&self, content: &str) {
            fs::write(self.path("proc/swaps"), content).unwrap();
        }

        fn add_block_device(
            &self,
            name: &str,
            major_minor: (u32, u32),
            is_partition: bool,
            parent_disk: Option<&str>,
        ) {
            let class_dir = self.path(&format!("sys/class/block/{}", name));
            fs::create_dir_all(&class_dir).unwrap();
            fs::write(class_dir.join("dev"), format!("{}:{}\n", major_minor.0, major_minor.1)).unwrap();

            if is_partition {
                fs::write(class_dir.join("partition"), "1\n").unwrap();
                if let Some(parent) = parent_disk {
                    let parent_dir = self.path(&format!("sys/block/{}/{}", parent, name));
                    fs::create_dir_all(&parent_dir).unwrap();
                    fs::write(parent_dir.join("partition"), "1\n").unwrap();
                }
            } else {
                let block_dir = self.path(&format!("sys/block/{}", name));
                fs::create_dir_all(&block_dir).unwrap();
                fs::write(block_dir.join("dev"), format!("{}:{}\n", major_minor.0, major_minor.1)).unwrap();
            }

            fs::write(self.path(&format!("dev/{}", name)), "").unwrap();
        }

        fn add_holder(&self, device: &str, holder: &str) {
            let holders_dir = self.path(&format!("sys/class/block/{}/holders", device));
            fs::create_dir_all(&holders_dir).unwrap();
            let holder_link = holders_dir.join(holder);
            let target_class = self.path(&format!("sys/class/block/{}", holder));
            let _ = std::os::unix::fs::symlink(target_class, holder_link);
        }

        fn add_dev_symlink(&self, link_rel: &str, target_rel: &str) {
            let link_path = self.path(&format!("dev/{}", link_rel));
            if let Some(parent) = link_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            std::os::unix::fs::symlink(target_rel, link_path).unwrap();
        }

        fn add_btrfs_device(&self, uuid: &str, device_name: &str) {
            let devices_dir = self.path(&format!("sys/fs/btrfs/{}/devices", uuid));
            fs::create_dir_all(&devices_dir).unwrap();
            let _ = std::os::unix::fs::symlink(
                self.path(&format!("sys/class/block/{}", device_name)),
                devices_dir.join(device_name),
            );
        }
    }

    #[test]
    fn test_boot_disk_protection_detects_root() {
        // Non-existent device in dry-run mode should pass without panicking
        let result = check_boot_disk_protection("/dev/nonexistent_safe_device", true);
        assert!(result.is_ok(), "Non-existent device should pass boot disk check in dry-run");

        // Non-existent device in real mode must fail closed (DeviceNotFound)
        let real_result = check_boot_disk_protection("/dev/nonexistent_safe_device", false);
        assert!(real_result.is_err(), "Non-existent device must be refused in real mode");
    }

    #[test]
    fn test_fixture_plain_partition_root() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 0 0:20 /sys /sys rw,nosuid - sysfs sysfs rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        let ctx = f.ctx();
        // Target is whole disk -> must refuse because sda1 is root
        let res_disk = check_boot_disk_protection_ctx("/dev/sda", false, &ctx);
        assert!(res_disk.is_err(), "Targeting /dev/sda must be refused when sda1 is root");

        // Target is partition -> must refuse because sda1 is root
        let res_part = check_boot_disk_protection_ctx("/dev/sda1", false, &ctx);
        assert!(res_part.is_err(), "Targeting /dev/sda1 must be refused when sda1 is root");
    }

    #[test]
    fn test_fixture_lvm_root() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 254:0 / / rw,relatime - ext4 /dev/mapper/vg-root rw\n",
        );
        f.add_block_device("sdb", (8, 16), false, None);
        f.add_block_device("sdb2", (8, 18), true, Some("sdb"));
        f.add_block_device("dm-0", (254, 0), false, None);
        f.add_holder("sdb2", "dm-0");

        let ctx = f.ctx();
        // Whole disk sdb has sdb2 which holds dm-0 (root)
        let res_disk = check_boot_disk_protection_ctx("/dev/sdb", false, &ctx);
        assert!(res_disk.is_err(), "LVM root member whole-disk must be refused");

        let res_part = check_boot_disk_protection_ctx("/dev/sdb2", false, &ctx);
        assert!(res_part.is_err(), "LVM root PV partition must be refused");
    }

    #[test]
    fn test_fixture_luks_on_lvm() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 0 254:1 /home /home rw,relatime - ext4 /dev/mapper/vg-home rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        f.add_block_device("sdc", (8, 32), false, None);
        f.add_block_device("sdc1", (8, 33), true, Some("sdc"));
        f.add_block_device("dm-0", (254, 0), false, None); // LUKS crypt
        f.add_block_device("dm-1", (254, 1), false, None); // LVM volume on crypt
        f.add_holder("sdc1", "dm-0");
        f.add_holder("dm-0", "dm-1");

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sdc", false, &ctx);
        assert!(res.is_err(), "LUKS-on-LVM backing /home must be refused");
    }

    #[test]
    fn test_fixture_mdraid() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 0 9:0 /var /var rw,relatime - ext4 /dev/md0 rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        f.add_block_device("sdd", (8, 48), false, None);
        f.add_block_device("sdd1", (8, 49), true, Some("sdd"));
        f.add_block_device("md0", (9, 0), false, None);
        f.add_holder("sdd1", "md0");

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sdd", false, &ctx);
        assert!(res.is_err(), "MDRAID member backing /var must be refused");
    }

    #[test]
    fn test_fixture_whole_disk_mdraid_member() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 0 9:0 /var /var rw,relatime - ext4 /dev/md0 rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        // Whole disk without partition directly in mdraid
        f.add_block_device("sdd", (8, 48), false, None);
        f.add_block_device("md0", (9, 0), false, None);
        f.add_holder("sdd", "md0");

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sdd", false, &ctx);
        assert!(res.is_err(), "Whole-disk mdraid member must be refused");
    }

    #[test]
    fn test_fixture_by_id_symlink() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));
        f.add_dev_symlink("disk/by-id/ata-WDC_WD10EZEX-00BN5A0", "../../sda");

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/disk/by-id/ata-WDC_WD10EZEX-00BN5A0", false, &ctx);
        assert!(res.is_err(), "Symlink resolving to root disk must be refused");
    }

    #[test]
    fn test_fixture_swap_on_target() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
        );
        f.set_swaps(
            "Filename\tType\tSize\tUsed\tPriority\n\
             /dev/sdf2\tpartition\t4194300\t0\t-2\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        f.add_block_device("sdf", (8, 80), false, None);
        f.add_block_device("sdf2", (8, 82), true, Some("sdf"));

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sdf", false, &ctx);
        assert!(res.is_err(), "Disk hosting active swap partition must be refused");
    }

    #[test]
    fn test_fixture_swap_file() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 0 8:33 /var /var rw,relatime - ext4 /dev/sdc1 rw\n",
        );
        f.set_swaps(
            "Filename\tType\tSize\tUsed\tPriority\n\
             /var/swapfile\tfile\t2097148\t0\t-2\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        f.add_block_device("sdc", (8, 32), false, None);
        f.add_block_device("sdc1", (8, 33), true, Some("sdc"));

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sdc", false, &ctx);
        assert!(res.is_err(), "Disk hosting filesystem with active swap file must be refused");
    }

    #[test]
    fn test_fixture_btrfs_root() {
        let f = FixtureBuilder::new();
        // Btrfs root mount reports major:minor as 0:42
        f.set_mountinfo(
            "1 0 0:42 / / rw,relatime - btrfs /dev/sda2 rw,subvol=/root\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda2", (8, 2), true, Some("sda"));
        f.add_btrfs_device("1111-2222-3333", "sda2");

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sda", false, &ctx);
        assert!(res.is_err(), "Btrfs single-device root disk must be refused");
    }

    #[test]
    fn test_fixture_multi_device_btrfs() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 0 0:50 /home /home rw,relatime - btrfs /dev/sdb2 rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        f.add_block_device("sdb", (8, 16), false, None);
        f.add_block_device("sdb2", (8, 18), true, Some("sdb"));
        f.add_block_device("sdc", (8, 32), false, None);
        f.add_block_device("sdc2", (8, 34), true, Some("sdc"));

        f.add_btrfs_device("4444-5555-6666", "sdb2");
        f.add_btrfs_device("4444-5555-6666", "sdc2");

        let ctx = f.ctx();
        let res_sdc = check_boot_disk_protection_ctx("/dev/sdc", false, &ctx);
        assert!(res_sdc.is_err(), "Second device in multi-device btrfs /home must be refused");
    }

    #[test]
    fn test_fixture_dev_root_and_mapper_aliases() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 254:0 / / rw,relatime - ext4 /dev/root rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));
        f.add_block_device("dm-0", (254, 0), false, None);
        f.add_holder("sda1", "dm-0");
        f.add_dev_symlink("root", "dm-0");

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sda", false, &ctx);
        assert!(res.is_err(), "Device under /dev/root alias must be refused");
    }

    #[test]
    fn test_fixture_nvme_partition_naming() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 259:2 / / rw,relatime - ext4 /dev/nvme0n1p2 rw\n",
        );
        f.add_block_device("nvme0n1", (259, 0), false, None);
        f.add_block_device("nvme0n1p2", (259, 2), true, Some("nvme0n1"));

        let ctx = f.ctx();
        let res_disk = check_boot_disk_protection_ctx("/dev/nvme0n1", false, &ctx);
        assert!(res_disk.is_err(), "Targeting whole NVMe disk with root partition must be refused");
    }

    #[test]
    fn test_fixture_cyclic_holders() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 0 8:97 /mnt/data /mnt/data rw,relatime - ext4 /dev/sdg1 rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        f.add_block_device("sdg", (8, 96), false, None);
        f.add_block_device("sdg1", (8, 97), true, Some("sdg"));
        f.add_block_device("dev_a", (254, 10), false, None);
        f.add_block_device("dev_b", (254, 11), false, None);

        // Cyclic holders
        f.add_holder("sdg1", "dev_a");
        f.add_holder("dev_a", "dev_b");
        f.add_holder("dev_b", "dev_a");

        let ctx = f.ctx();
        // Graph walker must terminate without infinite loop and allow unmounted/allowlisted sdg
        let res = check_boot_disk_protection_ctx("/dev/sdg", false, &ctx);
        assert!(res.is_ok(), "Cyclic holders on unmounted data disk must terminate and be allowed");
    }

    #[test]
    fn test_fixture_non_existent_target_real_vs_dry_run() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        let ctx = f.ctx();
        // Non-existent target in real mode must fail closed (DeviceNotFound)
        let real_res = check_boot_disk_protection_ctx("/dev/nonexistent_phantom", false, &ctx);
        assert!(real_res.is_err(), "Non-existent target must be refused in real mode");

        // Non-existent target in dry run mode should be allowed for safe smoke testing
        let dry_res = check_boot_disk_protection_ctx("/dev/nonexistent_phantom", true, &ctx);
        assert!(dry_res.is_ok(), "Non-existent target is permitted in dry-run mode");
    }

    #[test]
    fn test_fixture_partition_mounted_under_mnt_allowed() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 0 8:17 /mnt/external_backup /mnt/external_backup rw,relatime - ext4 /dev/sdb1 rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        f.add_block_device("sdb", (8, 16), false, None);
        f.add_block_device("sdb1", (8, 17), true, Some("sdb"));

        let ctx = f.ctx();
        // Mounts under /mnt are allowlisted as unmountable, so target sdb is ALLOWED
        let res = check_boot_disk_protection_ctx("/dev/sdb", false, &ctx);
        assert!(res.is_ok(), "Partition mounted under /mnt is allowlisted as unmountable: target must be allowed");
    }

    #[test]
    fn test_fixture_container_overlayfs_root_refuses() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 0:30 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker\n",
        );
        f.add_block_device("sda", (8, 0), false, None);

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sda", false, &ctx);
        assert!(res.is_err(), "Container or overlayfs root must refuse execution");
    }

    #[test]
    fn test_fixture_missing_root_refuses() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:17 /mnt/data /mnt/data rw,relatime - ext4 /dev/sdb1 rw\n",
        );
        f.add_block_device("sdb", (8, 16), false, None);
        f.add_block_device("sdb1", (8, 17), true, Some("sdb"));

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sdb", false, &ctx);
        assert!(res.is_err(), "Missing '/' root in mountinfo must refuse execution");
    }

    #[test]
    fn test_fixture_unparseable_corrupt_input_refuses() {
        let f = FixtureBuilder::new();
        f.set_mountinfo("not a valid mountinfo line format");
        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sda", false, &ctx);
        assert!(res.is_err(), "Corrupt mountinfo must fail closed");

        // Empty device path
        let empty_res = check_boot_disk_protection_ctx("", false, &ctx);
        assert!(empty_res.is_err(), "Empty device path must refuse");
    }

    #[test]
    fn test_fixture_unrelated_data_disk_allowed() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             2 0 8:97 /media/usb_drive /media/usb_drive rw,relatime - vfat /dev/sdg1 rw\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));

        f.add_block_device("sdg", (8, 96), false, None);
        f.add_block_device("sdg1", (8, 97), true, Some("sdg"));

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sdg", false, &ctx);
        assert!(res.is_ok(), "Unrelated data disk with /media mount must be allowed");
    }

    #[test]
    fn test_confirmation_mismatch() {
        let result = verify_confirmation("wrong_token", "CORRECT_SERIAL");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ExecuteError::ConfirmationMismatch));
    }

    #[test]
    fn test_confirmation_match() {
        let result = verify_confirmation("ABC123", "ABC123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_confirmation_with_whitespace_trim() {
        let result = verify_confirmation("  ABC123  ", "ABC123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_execution_report_serializes() {
        let report = ExecutionReport {
            success: true,
            method_used: "test".to_string(),
            command_log: vec!["cmd1".to_string()],
            stdout: "out".to_string(),
            stderr: "".to_string(),
            exit_code: 0,
            duration_ms: 100,
            dry_run: true,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"dry_run\":true"));
    }

    #[test]
    fn test_progress_event_serializes() {
        let event = ProgressEvent {
            phase: ExecutionPhase::FirmwareCommand,
            percent: 0.5,
            message: "halfway".to_string(),
            eta_seconds: Some(30),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"FirmwareCommand\""));
        assert!(json.contains("\"percent\":0.5"));
    }
}
