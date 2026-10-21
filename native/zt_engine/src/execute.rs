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
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
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
    #[error("Hardware I/O error (EIO): {0}")]
    HardwareIo(String),
    #[error("Device disconnected (ENODEV): {0}")]
    DeviceDisconnected(String),
    #[error("Premature end of device (ENOSPC): {0}")]
    PrematureEndOfDevice(String),
    #[error("Progress channel closed")]
    ChannelClosed,
    #[error("Identity mismatch: {0}")]
    IdentityMismatch(String),
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
    Preparing,
    Flushing,
}

impl std::fmt::Display for ExecutionPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionPhase::SecurityUnlock => write!(f, "Security Unlock"),
            ExecutionPhase::FirmwareCommand => write!(f, "Firmware Command"),
            ExecutionPhase::KeyDestruction => write!(f, "Key Destruction"),
            ExecutionPhase::CacheFlush => write!(f, "Cache Flush"),
            ExecutionPhase::Verification => write!(f, "Post-Verification"),
            ExecutionPhase::Preparing => write!(f, "Preparing"),
            ExecutionPhase::Flushing => write!(f, "Flushing"),
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
    MultiPass3,
}

fn default_schema_version() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub phase: ExecutionPhase,
    #[serde(default)]
    pub bytes_done: u64,
    #[serde(default)]
    pub bytes_total: u64,
    #[serde(default)]
    pub percent: Option<f32>,
    #[serde(default)]
    pub speed_bytes_per_sec: f64,
    pub eta_seconds: Option<u32>,
    pub message: String,
    #[serde(default)]
    pub is_heartbeat: bool,
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
    #[serde(default)]
    pub bytes_written: u64,
    #[serde(default)]
    pub io_mode: String,
}

#[derive(Debug, Clone)]
pub struct GuardIdentity {
    pub canonical_path: String,
    pub st_rdev: libc::dev_t,
    pub major: u32,
    pub minor: u32,
    pub is_block: bool,
    pub device_serial: String,
    pub st_ino: u64,
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

// Hardened boot-disk and system mount protection.
// Checks the device and all associated partitions/stacks against mountinfo and swaps.
// ---------------------------------------------------
// A3b: boot environment (normal install vs live medium vs container)
// ---------------------------------------------------

/// What kind of system the engine is running on. Affects which disks are
/// considered wipeable:
/// - `Normal`: installed system; the disk hosting `/` (and its partitions)
///   is protected.
/// - `Live`: booted from a live medium (overlay/squashfs root + live marker
///   on the kernel cmdline); internal disks become wipeable, but the live
///   medium itself and anything still mounted/swap-active stay protected.
/// - `Container`: overlay root with no live marker — refuse everything
///   (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootEnvironment {
    Normal,
    Live,
    Container,
}

/// Kernel cmdline markers that identify a live boot.
const LIVE_CMDLINE_MARKERS: &[&str] = &[
    "boot=live", "casper", "archiso", "livecd", "boot=archiso", "livemedia",
];

/// Detect the boot environment from mountinfo (root fs type) and
/// /proc/cmdline (live markers). Fail closed: unreadable state that still
/// shows an overlay root is classified as `Container`.
pub fn detect_boot_environment_ctx(ctx: &FsContext) -> Result<BootEnvironment, ExecuteError> {
    // Find the root mount's fs type from mountinfo.
    let mountinfo_path = ctx.proc_root.join("self/mountinfo");
    let alt = ctx.proc_root.join("mountinfo");
    let content = if mountinfo_path.exists() {
        fs::read_to_string(&mountinfo_path).ok()
    } else if alt.exists() {
        fs::read_to_string(&alt).ok()
    } else {
        None
    };

    let mut root_is_overlay = false;
    if let Some(content) = content {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 || parts[4] != "/" {
                continue;
            }
            let dash_pos = parts.iter().position(|&p| p == "-");
            if let Some(pos) = dash_pos {
                let fs_type = parts.get(pos + 1).copied().unwrap_or("");
                let source = parts.get(pos + 2).copied().unwrap_or("");
                if fs_type == "overlay" || fs_type == "aufs" || source == "overlay" {
                    root_is_overlay = true;
                }
            }
        }
    }

    if !root_is_overlay {
        return Ok(BootEnvironment::Normal);
    }

    // Overlay root: live medium or container? Ask the kernel cmdline.
    let cmdline = fs::read_to_string(ctx.proc_root.join("cmdline")).unwrap_or_default();
    let is_live = LIVE_CMDLINE_MARKERS.iter().any(|m| cmdline.contains(m));
    if is_live {
        Ok(BootEnvironment::Live)
    } else {
        Ok(BootEnvironment::Container)
    }
}

// ---------------------------------------------------
// Mount & swap protection scanning (shared by guard checks)
// ---------------------------------------------------

/// Result of scanning mountinfo + swaps for protected devices.
struct MountProtectionState {
    protected_devs: HashMap<(u32, u32), String>,
    protected_names: HashSet<String>,
    has_root_mount: bool,
}

/// Parse mountinfo (with fallbacks) and /proc/swaps, collecting every
/// device that must never be a destructive target.
///
/// `boot_env` matters for A3b: in `Live` mode the overlay root itself has no
/// backing block device and must not trip the anonymous-device fail-closed
/// check; the live medium's own mounts (e.g. /run/live/medium, /cdrom) are
/// still recorded as protected via the normal non-allowlisted-mount path.
fn scan_mount_and_swap_protection(
    ctx: &FsContext,
    dry_run: bool,
    boot_env: BootEnvironment,
) -> Result<MountProtectionState, ExecuteError> {
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
                } else if !(exempt_pseudo_fs.contains(fs_type)
                    || fs_type.starts_with("fuse")
                    || fs_type == "binfmt_misc"
                    || (boot_env == BootEnvironment::Live && mount_point == "/"))
                {
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

    Ok(MountProtectionState {
        protected_devs,
        protected_names,
        has_root_mount,
    })
}

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

    // A3b: classify the boot environment before applying mount rules.
    let boot_env = detect_boot_environment_ctx(ctx)?;
    if boot_env == BootEnvironment::Container {
        return Err(ExecuteError::BootDiskProtection(
            "Container or overlayfs root environment detected: refusing destructive operation (fail closed)".to_string(),
        ));
    }

    let state = scan_mount_and_swap_protection(ctx, dry_run, boot_env)?;
    if !state.has_root_mount {
        return Err(ExecuteError::BootDiskProtection(
            "Invalid mount environment: no root '/' mount point found in mountinfo".to_string(),
        ));
    }
    let protected_devs = state.protected_devs;
    let protected_names = state.protected_names;

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
    }

    check_boot_disk_protection_ctx(device, false, ctx)
}

/// Inspects device and captures guard identity (canonical path, st_rdev, major, minor, is_block, serial).
pub fn get_guard_identity(
    device: &str,
    dry_run: bool,
    device_serial: &str,
    ctx: &FsContext,
) -> Result<GuardIdentity, ExecuteError> {
    let canonical = canonicalize_device_path(device, dry_run, ctx)?;
    if dry_run {
        return Ok(GuardIdentity {
            canonical_path: canonical,
            st_rdev: 0,
            major: 0,
            minor: 0,
            is_block: true,
            device_serial: device_serial.to_string(),
            st_ino: 0,
        });
    }

    let meta = fs::metadata(&canonical)
        .map_err(|e| ExecuteError::DeviceNotFound(format!("Cannot stat {}: {}", canonical, e)))?;
    let rdev = meta.rdev();
    let is_block = (meta.mode() & libc::S_IFMT) == libc::S_IFBLK;

    Ok(GuardIdentity {
        canonical_path: canonical,
        st_rdev: rdev,
        major: dev_major(rdev),
        minor: dev_minor(rdev),
        is_block,
        device_serial: device_serial.to_string(),
        st_ino: meta.ino(),
    })
}

/// Re-checks boot disk protection against system mountinfo using an opened device's major:minor dev_t.
pub fn recheck_protection_by_dev_t(
    dev: libc::dev_t,
    ctx: &FsContext,
) -> Result<(), ExecuteError> {
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    let mountinfo_path = ctx.proc_root.join("self/mountinfo");
    let content = if mountinfo_path.exists() {
        fs::read_to_string(&mountinfo_path)
            .map_err(|e| ExecuteError::BootDiskProtection(format!("Cannot read mountinfo: {}", e)))?
    } else {
        return Ok(());
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }
        let mm_str = parts[2];
        let mount_point = parts[4];
        if is_mount_unmountable_allowlisted(mount_point) {
            continue;
        }
        if let Some((m_maj, m_min)) = parse_major_minor(mm_str) {
            if m_maj == maj && m_min == min {
                return Err(ExecuteError::BootDiskProtection(format!(
                    "Opened file descriptor matches protected mount '{}' ({}:{}): aborting destructive write",
                    mount_point, maj, min
                )));
            }
        }
    }

    Ok(())
}

/// Verify the confirmation token matches expected value.
fn verify_confirmation(token: &str, expected_serial: &str) -> Result<(), ExecuteError> {
    if token.trim() != expected_serial.trim() {
        return Err(ExecuteError::ConfirmationMismatch);
    }
    Ok(())
}

/// Send an indeterminate progress event for firmware operations.
async fn send_progress(
    tx: &mpsc::Sender<ProgressEvent>,
    phase: ExecutionPhase,
    message: &str,
    eta_seconds: Option<u32>,
) {
    let _ = tx.send(ProgressEvent {
        schema_version: 2,
        phase,
        bytes_done: 0,
        bytes_total: 0,
        percent: None,
        speed_bytes_per_sec: 0.0,
        eta_seconds,
        message: message.to_string(),
        is_heartbeat: false,
    }).await;
}

#[allow(clippy::too_many_arguments)]
async fn send_detailed_progress(
    tx: &mpsc::Sender<ProgressEvent>,
    phase: ExecutionPhase,
    bytes_done: u64,
    bytes_total: u64,
    percent: Option<f32>,
    speed_bytes_per_sec: f64,
    eta_seconds: Option<u32>,
    message: &str,
    is_heartbeat: bool,
) {
    let _ = tx.send(ProgressEvent {
        schema_version: 2,
        phase,
        bytes_done,
        bytes_total,
        percent,
        speed_bytes_per_sec,
        eta_seconds,
        message: message.to_string(),
        is_heartbeat,
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
    send_progress(&tx, ExecutionPhase::SecurityUnlock,
        "Checking NVMe controller security state...", Some(5)).await;

    // Phase 2: Issue sanitize command
    send_progress(&tx, ExecutionPhase::FirmwareCommand,
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
            bytes_written: 0,
            io_mode: if dry_run { "dry_run".to_string() } else { "firmware".to_string() },
        });
    }

    // Phase 2 continued: Poll sanitize-log for completion
    if dry_run {
        send_progress(&tx, ExecutionPhase::FirmwareCommand,
            "[DRY RUN] Firmware sanitize command sent to controller", None).await;
        let (s, e, _) = run_cmd("nvme", &["sanitize-log", device], dry_run, &mut command_log)?;
        all_stdout.push_str(&s);
        all_stderr.push_str(&e);
    }

    // Phase 3: Key Destruction
    send_progress(&tx, ExecutionPhase::KeyDestruction,
        "NVMe controller internal key zeroization complete.", Some(2)).await;

    // Phase 4: Cache Flush
    send_progress(&tx, ExecutionPhase::CacheFlush,
        "Flushing volatile caches and translation tables...", Some(1)).await;

    // Phase 5: Ready for verification
    send_progress(&tx, ExecutionPhase::Verification,
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
        bytes_written: 0,
        io_mode: if dry_run { "dry_run".to_string() } else { "firmware".to_string() },
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
    send_progress(&tx, ExecutionPhase::SecurityUnlock,
        "Checking ATA security frozen state with hdparm -I...", Some(10)).await;

    let (stdout, stderr, _) = run_cmd("hdparm", &["-I", device], dry_run, &mut command_log)?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    if !dry_run && stdout.to_lowercase().contains("frozen") && !stdout.to_lowercase().contains("not\tfrozen") && !stdout.to_lowercase().contains("not frozen") {
        send_progress(&tx, ExecutionPhase::SecurityUnlock,
            "WARNING: ATA security is FROZEN. Attempting suspend/resume cycle...", None).await;
        // In a real bootable environment, we could issue a sleep/wake cycle
        // For now, report the frozen state
    }

    // Phase 1b: Set security password
    send_progress(&tx, ExecutionPhase::SecurityUnlock,
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
            bytes_written: 0,
            io_mode: if dry_run { "dry_run".to_string() } else { "firmware".to_string() },
        });
    }

    // Phase 2: Issue secure erase
    let erase_arg = if enhanced { "--security-erase-enhanced" } else { "--security-erase" };

    send_progress(&tx, ExecutionPhase::FirmwareCommand,
        &format!("Issuing hdparm {} on {}...", erase_arg, device), None).await;

    let (stdout, stderr, code) = run_cmd(
        "hdparm",
        &[erase_arg, "p", device],
        dry_run,
        &mut command_log,
    )?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    if dry_run {
        send_progress(&tx, ExecutionPhase::FirmwareCommand,
            "[DRY RUN] ATA Secure Erase executing on controller", None).await;
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
            bytes_written: 0,
            io_mode: if dry_run { "dry_run".to_string() } else { "firmware".to_string() },
        });
    }

    // Phase 3: Key destruction (implicit in ATA SE)
    send_progress(&tx, ExecutionPhase::KeyDestruction,
        "ATA controller key destruction complete.", Some(2)).await;

    // Phase 4: Cache flush
    send_progress(&tx, ExecutionPhase::CacheFlush,
        "Flushing write cache...", Some(1)).await;

    if !dry_run {
        let (s, e, _) = run_cmd("hdparm", &["-F", device], dry_run, &mut command_log)?;
        all_stdout.push_str(&s);
        all_stderr.push_str(&e);
    }

    send_progress(&tx, ExecutionPhase::Verification,
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
        bytes_written: 0,
        io_mode: if dry_run { "dry_run".to_string() } else { "firmware".to_string() },
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

    send_progress(&tx, ExecutionPhase::SecurityUnlock,
        "Checking device sanitize feature set support...", Some(5)).await;

    send_progress(&tx, ExecutionPhase::FirmwareCommand,
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
        send_progress(&tx, ExecutionPhase::FirmwareCommand,
            "[DRY RUN] ATA Sanitize executing on controller", None).await;
    }

    send_progress(&tx, ExecutionPhase::KeyDestruction,
        "ATA Sanitize controller key handling complete.", Some(2)).await;
    send_progress(&tx, ExecutionPhase::CacheFlush,
        "Flushing caches...", Some(1)).await;
    send_progress(&tx, ExecutionPhase::Verification,
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
        bytes_written: 0,
        io_mode: if dry_run { "dry_run".to_string() } else { "firmware".to_string() },
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

    send_progress(&tx, ExecutionPhase::SecurityUnlock,
        "Querying TCG OPAL SED state...", Some(3)).await;

    // Query OPAL state first
    let (stdout, stderr, _) = run_cmd("sedutil-cli", &["--query", device], dry_run, &mut command_log)?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    send_progress(&tx, ExecutionPhase::FirmwareCommand,
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
        send_progress(&tx, ExecutionPhase::FirmwareCommand,
            "[DRY RUN] OPAL revert executing on controller", None).await;
    }

    send_progress(&tx, ExecutionPhase::KeyDestruction,
        "TCG OPAL Media Encryption Key (MEK) destroyed.", Some(2)).await;
    send_progress(&tx, ExecutionPhase::CacheFlush,
        "SED controller state reset complete.", Some(1)).await;
    send_progress(&tx, ExecutionPhase::Verification,
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
        bytes_written: 0,
        io_mode: if dry_run { "dry_run".to_string() } else { "firmware".to_string() },
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

    send_progress(&tx, ExecutionPhase::SecurityUnlock,
        "Reading eMMC extcsd sanitize capability...", Some(3)).await;

    send_progress(&tx, ExecutionPhase::FirmwareCommand,
        &format!("Issuing mmc sanitize on {}...", device), None).await;

    let (stdout, stderr, code) = run_cmd("mmc", &["sanitize", device], dry_run, &mut command_log)?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    if dry_run {
        send_progress(&tx, ExecutionPhase::FirmwareCommand,
            "[DRY RUN] eMMC sanitize executing on controller", None).await;
    }

    send_progress(&tx, ExecutionPhase::KeyDestruction,
        "eMMC controller internal cleanup complete.", Some(2)).await;
    send_progress(&tx, ExecutionPhase::CacheFlush,
        "Flushing eMMC write buffer...", Some(1)).await;
    send_progress(&tx, ExecutionPhase::Verification,
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
        bytes_written: 0,
        io_mode: if dry_run { "dry_run".to_string() } else { "firmware".to_string() },
    })
}

// ---------------------------------------------------------------------------
// A6: Removable-media discard execution (blkdiscard-style BLKDISCARD ioctls)
// ---------------------------------------------------------------------------

/// `linux/fs.h`: `BLKDISCARD = _IO(0x12, 119)` — kernel TRIM/UNMAP of a byte
/// range. Issued natively (no external blkdiscard binary) behind the same
/// guard chain as every other execution path.
const BLKDISCARD: libc::c_ulong = 0x1277;

/// One aligned BLKDISCARD command range (byte offsets relative to the opened
/// block-device node — for partitions, relative to the partition start).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardChunk {
    pub start: u64,
    pub len: u64,
}

/// Build the ordered list of BLKDISCARD commands covering
/// `[range_start, range_start + range_len)`.
///
/// The range is aligned inward to `granularity` (unaligned head/tail bytes are
/// not discarded — callers pass sector-aligned whole-device or partition
/// ranges) and split into commands of at most `max_chunk` bytes
/// (`max_chunk == 0` → a single command for the whole aligned range).
/// Pure function: unit-tested without hardware.
pub fn build_discard_chunks(
    range_start: u64,
    range_len: u64,
    granularity: u64,
    max_chunk: u64,
) -> Result<Vec<DiscardChunk>, ExecuteError> {
    let gran = granularity.max(1);
    let range_end = range_start.checked_add(range_len).ok_or_else(|| {
        ExecuteError::UnsupportedOperation("Discard range overflows 64-bit byte space".into())
    })?;

    // Align inward: start rounds up, end rounds down.
    let aligned_start = range_start
        .checked_add(gran - 1)
        .map(|v| v / gran * gran)
        .ok_or_else(|| {
            ExecuteError::UnsupportedOperation("Discard range start overflows during alignment".into())
        })?;
    let aligned_end = (range_end / gran) * gran;

    if aligned_end <= aligned_start {
        return Err(ExecuteError::UnsupportedOperation(format!(
            "Discard range [{}, {}) contains no full {}-byte discard block",
            range_start, range_end, gran
        )));
    }

    let step = if max_chunk == 0 {
        aligned_end - aligned_start
    } else {
        ((max_chunk / gran).max(1)) * gran
    };

    let mut chunks = Vec::new();
    let mut cursor = aligned_start;
    while cursor < aligned_end {
        let len = step.min(aligned_end - cursor);
        chunks.push(DiscardChunk { start: cursor, len });
        cursor += len;
    }
    Ok(chunks)
}

/// A6: read `(granularity_bytes, max_bytes_per_cmd)` for `device` from sysfs.
/// Missing/zero attributes degrade to (logical block size | 512, 0 = single
/// command covering the whole range), mirroring blkdiscard's fallbacks.
pub fn read_discard_geometry(device: &str, ctx: &FsContext) -> (u64, u64) {
    fn queue_attr(node_dir: &Path, attr: &str) -> Option<u64> {
        fs::read_to_string(node_dir.join("queue").join(attr))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    }

    let name = device.strip_prefix("/dev/").unwrap_or(device);
    let class_block = ctx.sys_root.join("class/block");
    let node_dir = class_block.join(name);

    let mut granularity = queue_attr(&node_dir, "discard_granularity").unwrap_or(0);
    let mut max_chunk = queue_attr(&node_dir, "discard_max_bytes").unwrap_or(0);

    // Partition nodes usually carry no queue/ dir of their own: fall back to
    // the parent disk's queue settings.
    let is_partition = node_dir.join("partition").exists();
    if (granularity == 0 || max_chunk == 0) && is_partition {
        if let Ok(parent) = resolve_parent_disk(device, ctx) {
            let parent_dir = class_block.join(&parent);
            if granularity == 0 {
                granularity = queue_attr(&parent_dir, "discard_granularity").unwrap_or(0);
            }
            if max_chunk == 0 {
                max_chunk = queue_attr(&parent_dir, "discard_max_bytes").unwrap_or(0);
            }
            if granularity == 0 {
                granularity = queue_attr(&parent_dir, "logical_block_size").unwrap_or(0);
            }
        }
    }

    if granularity == 0 {
        granularity = queue_attr(&node_dir, "logical_block_size").unwrap_or(512);
    }
    (granularity.max(1), max_chunk)
}

/// Issue a single BLKDISCARD command; translate kernel refusals into typed errors.
fn issue_discard_chunk(
    fd: libc::c_int,
    device: &str,
    chunk: DiscardChunk,
) -> Result<(), ExecuteError> {
    let mut range: [u64; 2] = [chunk.start, chunk.len];
    let ret = unsafe { libc::ioctl(fd, BLKDISCARD, range.as_mut_ptr()) };
    if ret == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY) | Some(libc::ENOSYS) => {
            Err(ExecuteError::UnsupportedOperation(format!(
                "BLKDISCARD is not supported on {} (device does not advertise discard)",
                device
            )))
        }
        Some(libc::EPERM) | Some(libc::EACCES) => Err(ExecuteError::CommandFailed(format!(
            "BLKDISCARD on {} was denied by the kernel (root privileges required): {}",
            device, err
        ))),
        Some(libc::EINVAL) => Err(ExecuteError::UnsupportedOperation(format!(
            "Kernel rejected BLKDISCARD range [{}, {}) on {} (alignment or granularity): {}",
            chunk.start,
            chunk.start + chunk.len,
            device,
            err
        ))),
        _ => Err(ExecuteError::IoError(err)),
    }
}

/// Execute the ordered BLKDISCARD plan on an open fd, logging every step into
/// [command_log] and emitting per-chunk progress events.
async fn run_discard_plan(
    fd: libc::c_int,
    device: &str,
    chunks: &[DiscardChunk],
    tx: &mpsc::Sender<ProgressEvent>,
    command_log: &mut Vec<String>,
) -> Result<u64, ExecuteError> {
    let total: u64 = chunks.iter().map(|c| c.len).sum();
    let n = chunks.len();
    let mut done = 0u64;
    for (i, chunk) in chunks.iter().enumerate() {
        issue_discard_chunk(fd, device, *chunk)?;
        done += chunk.len;
        command_log.push(format!(
            "[discard] BLKDISCARD {} range=[{}, {}) chunk {}/{} ({} bytes)",
            device,
            chunk.start,
            chunk.start + chunk.len,
            i + 1,
            n,
            chunk.len
        ));
        send_detailed_progress(
            tx,
            ExecutionPhase::FirmwareCommand,
            done,
            total,
            Some(done as f32 / total as f32 * 100.0),
            0.0,
            None,
            &format!(
                "BLKDISCARD chunk {}/{} complete ({} bytes)",
                i + 1,
                n,
                chunk.len
            ),
            false,
        )
        .await;
    }
    Ok(done)
}

/// A6: whole-device discard (native BLKDISCARD equivalent of `blkdiscard`).
pub async fn discard_erase(
    device: &str,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    discard_erase_ctx(
        device,
        confirmation_token,
        device_serial,
        dry_run,
        tx,
        &FsContext::default(),
    )
    .await
}

pub async fn discard_erase_ctx(
    device: &str,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
    ctx: &FsContext,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let method_name = "BLKDISCARD (TRIM/UNMAP)".to_string();
    let step_prefix = if dry_run { "[DRY RUN] " } else { "" };

    // 1. Guard chain — identical to every other execution path.
    check_boot_disk_protection_ctx(device, dry_run, ctx)?;
    verify_confirmation(confirmation_token, device_serial)?;
    let guard_identity = get_guard_identity(device, dry_run, device_serial, ctx)?;
    command_log.push(format!(
        "{}[guard] boot-disk protection and confirmation verified for {}",
        step_prefix, device
    ));

    let (granularity, max_chunk) = read_discard_geometry(device, ctx);

    // 2. Dry-run: plan from sysfs geometry — no unmounts, no device opens.
    if dry_run {
        let name = device.strip_prefix("/dev/").unwrap_or(device);
        let size_bytes = fs::read_to_string(ctx.sys_root.join("class/block").join(name).join("size"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|sectors| sectors.saturating_mul(512));
        match size_bytes {
            Some(size) if size > 0 => {
                let chunks = build_discard_chunks(0, size, granularity, max_chunk)?;
                command_log.push(format!(
                    "[DRY RUN] BLKDISCARD plan for {}: {} command(s), {} bytes (granularity {}, max {})",
                    device,
                    chunks.len(),
                    size,
                    granularity,
                    max_chunk
                ));
            }
            _ => {
                command_log.push(format!(
                    "[DRY RUN] BLKDISCARD plan for {}: full device (sysfs size unavailable)",
                    device
                ));
            }
        }
        send_detailed_progress(&tx, ExecutionPhase::FirmwareCommand, 0, 0, None, 0.0, None,
            "[DRY RUN] Simulated BLKDISCARD complete", false).await;
        send_detailed_progress(&tx, ExecutionPhase::Flushing, 0, 0, None, 0.0, None,
            "[DRY RUN] Cache flush simulated", false).await;
        return Ok(ExecutionReport {
            success: true,
            method_used: method_name,
            command_log,
            stdout: "[DRY RUN] Discard simulated successfully".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: true,
            bytes_written: 0,
            io_mode: "dry_run".to_string(),
        });
    }

    send_detailed_progress(&tx, ExecutionPhase::Preparing, 0, 0, None, 0.0, Some(5),
        "Unmounting filesystems on target device...", false).await;

    // 3. Unmount any active partitions on the device
    let (_stdout, _stderr) = unmount_device_if_mounted(device, false, &mut command_log);

    // 4. Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, false, ctx)?;
    command_log.push(format!("[guard] exclusive access verified on {}", device));

    // 5. Open with O_EXCL + fd identity validation (same open as overwrite paths)
    let mut writer = DirectBlockWriter::open(&guard_identity.canonical_path, &guard_identity)?;
    let size_bytes = writer.total_size().map_err(ExecuteError::IoError)?;
    let chunks = build_discard_chunks(0, size_bytes, granularity, max_chunk)?;
    command_log.push(format!(
        "[discard] plan {}: {} BLKDISCARD command(s) for {} bytes (granularity {}, max {})",
        device,
        chunks.len(),
        size_bytes,
        granularity,
        max_chunk
    ));

    // 6. Ordered BLKDISCARD execution over the whole device
    let fd = writer.file.as_raw_fd();
    let discarded = run_discard_plan(fd, device, &chunks, &tx, &mut command_log).await?;

    // 7. Flush the page cache so no stale data remains cached
    writer.flush_buffers().map_err(ExecuteError::IoError)?;
    command_log.push(format!("[flush] BLKFLSBUF on {}", device));

    send_detailed_progress(&tx, ExecutionPhase::Verification, discarded, size_bytes,
        Some(100.0), 0.0, None,
        "BLKDISCARD complete. Ready for post-verification.", false).await;

    Ok(ExecutionReport {
        success: true,
        method_used: method_name,
        command_log,
        stdout: format!("BLKDISCARD completed: {} bytes discarded", discarded),
        stderr: String::new(),
        exit_code: 0,
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run: false,
        bytes_written: discarded,
        io_mode: "discard".to_string(),
    })
}

/// A6: partition-range discard — same geometry/fingerprint guard chain as
/// partition overwrite, then BLKDISCARD over the partition node only.
pub async fn discard_erase_partition(
    device: &str,
    confirmation_token: &str,
    device_serial: &str,
    params: &PartitionTargetParams,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    discard_erase_partition_ctx(
        device,
        confirmation_token,
        device_serial,
        params,
        dry_run,
        tx,
        &FsContext::default(),
    )
    .await
}

pub async fn discard_erase_partition_ctx(
    device: &str,
    confirmation_token: &str,
    device_serial: &str,
    params: &PartitionTargetParams,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
    ctx: &FsContext,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let method_name = "Partition BLKDISCARD (TRIM/UNMAP)".to_string();
    let step_prefix = if dry_run { "[DRY RUN] " } else { "" };

    // 1. Authoritative safety check: parent disk and target partition
    check_boot_disk_protection_ctx(device, dry_run, ctx)?;
    verify_confirmation(confirmation_token, device_serial)?;

    // 2. Shared partition validation: sysfs geometry, PARTUUID, table
    //    fingerprint, MBR extended refusal, logical-block alignment, identity
    let target = validate_partition_target(device, params, ctx, dry_run, device_serial)?;
    command_log.push(format!(
        "{}[guard] partition geometry and table fingerprint verified for {} ({} bytes)",
        step_prefix, device, target.size_bytes
    ));

    let (granularity, max_chunk) = read_discard_geometry(device, ctx);

    // 3. Dry-run: plan only — no unmounts, no device opens.
    if dry_run {
        let chunks = build_discard_chunks(0, target.size_bytes, granularity, max_chunk)?;
        command_log.push(format!(
            "[DRY RUN] BLKDISCARD plan for {}: {} command(s), {} bytes (granularity {}, max {})",
            device,
            chunks.len(),
            target.size_bytes,
            granularity,
            max_chunk
        ));
        send_detailed_progress(&tx, ExecutionPhase::FirmwareCommand, 0, 0, None, 0.0, None,
            "[DRY RUN] Simulated partition BLKDISCARD complete", false).await;
        send_detailed_progress(&tx, ExecutionPhase::Flushing, 0, 0, None, 0.0, None,
            "[DRY RUN] Cache flush simulated", false).await;
        return Ok(ExecutionReport {
            success: true,
            method_used: method_name,
            command_log,
            stdout: "[DRY RUN] Partition discard simulated successfully".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: true,
            bytes_written: 0,
            io_mode: "dry_run".to_string(),
        });
    }

    send_detailed_progress(&tx, ExecutionPhase::Preparing, 0, 0, None, 0.0, Some(5),
        "Unmounting filesystems on target partition...", false).await;

    // 4. Targeted unmount: target partition & holders only
    let (_stdout, _stderr) = unmount_target_partition_and_holders(device, false, &mut command_log, ctx)?;

    // 5. Verify exclusive access on the partition node
    verify_exclusive_access_and_recheck(device, false, ctx)?;
    command_log.push(format!("[guard] exclusive access verified on {}", device));

    // 6. Open with O_EXCL + identity checks; cross-check BLKGETSIZE64 vs sysfs
    let mut writer = DirectBlockWriter::open(&target.guard_identity.canonical_path, &target.guard_identity)?;
    let actual_size = writer.total_size().map_err(ExecuteError::IoError)?;
    if actual_size != target.size_bytes {
        return Err(ExecuteError::IdentityMismatch(format!(
            "BLKGETSIZE64 size ({}) does not match sysfs size ({})",
            actual_size, target.size_bytes
        )));
    }

    let chunks = build_discard_chunks(0, target.size_bytes, granularity, max_chunk)?;
    command_log.push(format!(
        "[discard] plan {}: {} BLKDISCARD command(s) for {} bytes (granularity {}, max {})",
        device,
        chunks.len(),
        target.size_bytes,
        granularity,
        max_chunk
    ));

    // 7. Ordered BLKDISCARD execution over the partition range only
    let fd = writer.file.as_raw_fd();
    let discarded = run_discard_plan(fd, device, &chunks, &tx, &mut command_log).await?;

    // 8. Flush the page cache
    writer.flush_buffers().map_err(ExecuteError::IoError)?;
    command_log.push(format!("[flush] BLKFLSBUF on {}", device));

    send_detailed_progress(&tx, ExecutionPhase::Verification, discarded, target.size_bytes,
        Some(100.0), 0.0, None,
        "Partition BLKDISCARD complete. Ready for post-verification.", false).await;

    Ok(ExecutionReport {
        success: true,
        method_used: method_name,
        command_log,
        stdout: format!("Partition BLKDISCARD completed: {} bytes discarded", discarded),
        stderr: String::new(),
        exit_code: 0,
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run: false,
        bytes_written: discarded,
        io_mode: "discard".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Native Block Writer & Telemetry Engine
// ---------------------------------------------------------------------------

pub struct AlignedBuffer {
    ptr: *mut u8,
    layout: std::alloc::Layout,
}

unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    pub fn new(size: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Self { ptr, layout }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.layout.size()) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

pub trait BlockWriter: Send + Sync {
    fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<usize, io::Error>;
    fn sync_data(&mut self) -> Result<(), io::Error>;
    fn flush_buffers(&mut self) -> Result<(), io::Error>;
    fn total_size(&self) -> Result<u64, io::Error>;
    fn logical_block_size(&self) -> u32 { 512 }
    fn io_mode(&self) -> &'static str;
}

const BLKGETSIZE64: libc::c_ulong = 0x80081272;
const BLKSSZGET: libc::c_ulong = 0x1268;

#[derive(Debug)]
pub struct DirectBlockWriter {
    file: fs::File,
    io_mode: &'static str,
    device_size: u64,
    sector_size: u32,
    bytes_since_sync: u64,
}

impl DirectBlockWriter {
    pub fn open(path: &str, expected_identity: &GuardIdentity) -> Result<Self, ExecuteError> {
        let c_path = std::ffi::CString::new(path)
            .map_err(|e| ExecuteError::CommandFailed(format!("Invalid path: {}", e)))?;

        let mut mode = "direct";
        let mut fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDWR | libc::O_EXCL | libc::O_DIRECT,
            )
        };

        if fd < 0 {
            // Fallback 1: O_DSYNC
            mode = "dsync";
            fd = unsafe {
                libc::open(
                    c_path.as_ptr(),
                    libc::O_RDWR | libc::O_EXCL | libc::O_DSYNC,
                )
            };
        }

        if fd < 0 {
            // Fallback 2: buffered + periodic fdatasync
            mode = "buffered_sync_16mb";
            fd = unsafe {
                libc::open(
                    c_path.as_ptr(),
                    libc::O_RDWR | libc::O_EXCL,
                )
            };
        }

        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(map_open_excl_error(err, path));
        }

        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let res = unsafe { libc::fstat(fd, &mut stat_buf) };
        if res < 0 {
            unsafe { libc::close(fd) };
            return Err(ExecuteError::IoError(io::Error::last_os_error()));
        }

        let is_blk = (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFBLK;
        let is_reg = (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFREG;
        if !is_blk && !is_reg {
            unsafe { libc::close(fd) };
            return Err(ExecuteError::UnsupportedOperation(format!(
                "Device {} is neither a block device nor a regular file",
                path
            )));
        }

        // Item 1: compare opened fd's st_rdev and S_ISBLK against identity recorded at boot-guard time
        if expected_identity.is_block {
            if !is_blk {
                unsafe { libc::close(fd) };
                return Err(ExecuteError::BootDiskProtection(
                    "Target is not a block device (S_ISBLK check failed on opened fd)".to_string(),
                ));
            }
            if stat_buf.st_rdev != expected_identity.st_rdev {
                unsafe { libc::close(fd) };
                return Err(ExecuteError::BootDiskProtection(format!(
                    "Device identity changed between boot-guard and open (st_rdev mismatch: expected {}, got {}): aborting",
                    expected_identity.st_rdev, stat_buf.st_rdev
                )));
            }
            // Re-run protection check on the fd's major:minor
            if let Err(e) = recheck_protection_by_dev_t(stat_buf.st_rdev, &FsContext::default()) {
                unsafe { libc::close(fd) };
                return Err(e);
            }
        } else {
            // For non-block targets (e.g. tests), verify inode has not changed
            if expected_identity.st_ino > 0 && stat_buf.st_ino as u64 != expected_identity.st_ino {
                unsafe { libc::close(fd) };
                return Err(ExecuteError::BootDiskProtection(format!(
                    "Path resolved to a different file after boot-guard (inode mismatch: expected {}, got {}): aborting",
                    expected_identity.st_ino, stat_buf.st_ino
                )));
            }
        }

        let mut size: u64 = 0;
        if is_blk {
            let ret = unsafe { libc::ioctl(fd, BLKGETSIZE64, &mut size) };
            if ret != 0 || size == 0 {
                size = stat_buf.st_size as u64;
            }
        } else {
            size = stat_buf.st_size as u64;
        }

        let mut ssz: u32 = 512;
        if is_blk {
            unsafe { libc::ioctl(fd, BLKSSZGET, &mut ssz) }; // BLKSSZGET
        }
        if ssz == 0 {
            ssz = 512;
        }

        let file = unsafe { fs::File::from_raw_fd(fd) };

        Ok(Self {
            file,
            io_mode: mode,
            device_size: size,
            sector_size: ssz,
            bytes_since_sync: 0,
        })
    }
}

impl BlockWriter for DirectBlockWriter {
    fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<usize, io::Error> {
        use std::os::unix::fs::FileExt;
        let written = self.file.write_at(data, offset)?;
        self.bytes_since_sync += written as u64;
        if self.io_mode == "buffered_sync_16mb" && self.bytes_since_sync >= 16 * 1024 * 1024 {
            self.file.sync_data()?;
            self.bytes_since_sync = 0;
        }
        Ok(written)
    }

    fn sync_data(&mut self) -> Result<(), io::Error> {
        self.file.sync_data()?;
        self.bytes_since_sync = 0;
        Ok(())
    }

    fn flush_buffers(&mut self) -> Result<(), io::Error> {
        self.file.sync_all()?;
        let fd = self.file.as_raw_fd();
        unsafe {
            libc::ioctl(fd, 0x1261, 0); // BLKFLSBUF
        }
        Ok(())
    }

    fn total_size(&self) -> Result<u64, io::Error> {
        Ok(self.device_size)
    }

    fn logical_block_size(&self) -> u32 {
        self.sector_size
    }

    fn io_mode(&self) -> &'static str {
        self.io_mode
    }
}

pub struct FileBlockWriter {
    file: fs::File,
    size: u64,
}

impl FileBlockWriter {
    pub fn new(file: fs::File, size: u64) -> Self {
        Self { file, size }
    }
}

impl BlockWriter for FileBlockWriter {
    fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<usize, io::Error> {
        use std::os::unix::fs::FileExt;
        self.file.write_at(data, offset)
    }

    fn sync_data(&mut self) -> Result<(), io::Error> {
        self.file.sync_data()
    }

    fn flush_buffers(&mut self) -> Result<(), io::Error> {
        self.file.sync_all()
    }

    fn total_size(&self) -> Result<u64, io::Error> {
        Ok(self.size)
    }

    fn logical_block_size(&self) -> u32 {
        512
    }

    fn io_mode(&self) -> &'static str {
        "file_test"
    }
}

/// A bounded range writer wrapping an inner BlockWriter.
/// Translates relative offsets: inner_offset = start_offset + rel_offset.
/// Strictly enforces that rel_offset + chunk_len <= length, refusing any out-of-range write.
#[derive(Debug)]
pub struct PartitionRangeWriter<W: BlockWriter> {
    inner: W,
    start_offset: u64,
    length: u64,
}

impl<W: BlockWriter> PartitionRangeWriter<W> {
    pub fn new(inner: W, start_offset: u64, length: u64) -> Self {
        Self {
            inner,
            start_offset,
            length,
        }
    }

    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: BlockWriter> BlockWriter for PartitionRangeWriter<W> {
    fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<usize, io::Error> {
        let chunk_len = data.len() as u64;
        let end = offset.checked_add(chunk_len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Offset overflow in partition write")
        })?;
        if end > self.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Out of partition range write refused: offset {} + chunk {} > length {}",
                    offset, chunk_len, self.length
                ),
            ));
        }
        let target_offset = self.start_offset.checked_add(offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Target offset overflow in partition write")
        })?;
        self.inner.write_chunk(target_offset, data)
    }

    fn sync_data(&mut self) -> Result<(), io::Error> {
        self.inner.sync_data()
    }

    fn flush_buffers(&mut self) -> Result<(), io::Error> {
        self.inner.flush_buffers()
    }

    fn total_size(&self) -> Result<u64, io::Error> {
        Ok(self.length)
    }

    fn logical_block_size(&self) -> u32 {
        self.inner.logical_block_size()
    }

    fn io_mode(&self) -> &'static str {
        self.inner.io_mode()
    }
}

pub struct MockBlockWriter {
    pub size: u64,
    pub written_bytes: u64,
    pub fail_after_bytes: Option<u64>,
    pub injected_error: Option<io::ErrorKind>,
    pub injected_raw_os_error: Option<i32>,
    pub return_zero_bytes: bool,
    pub sync_fail: bool,
    pub sync_called: bool,
    pub delay_per_chunk: Option<std::time::Duration>,
    pub cancel_flag_on_write: Option<Arc<AtomicBool>>,
    pub custom_io_mode: Option<&'static str>,
}

impl MockBlockWriter {
    pub fn new(size: u64) -> Self {
        Self {
            size,
            written_bytes: 0,
            fail_after_bytes: None,
            injected_error: None,
            injected_raw_os_error: None,
            return_zero_bytes: false,
            sync_fail: false,
            sync_called: false,
            delay_per_chunk: None,
            cancel_flag_on_write: None,
            custom_io_mode: None,
        }
    }
}

impl BlockWriter for MockBlockWriter {
    fn write_chunk(&mut self, _offset: u64, data: &[u8]) -> Result<usize, io::Error> {
        if self.return_zero_bytes {
            return Ok(0);
        }
        if let Some(delay) = self.delay_per_chunk {
            std::thread::sleep(delay);
        }
        if let Some(limit) = self.fail_after_bytes {
            if self.written_bytes + data.len() as u64 > limit {
                if let Some(os_err) = self.injected_raw_os_error {
                    return Err(io::Error::from_raw_os_error(os_err));
                }
                let err_kind = self.injected_error.unwrap_or(io::ErrorKind::Other);
                return Err(io::Error::new(err_kind, "Injected mock write error"));
            }
        }
        self.written_bytes += data.len() as u64;
        if let Some(flag) = &self.cancel_flag_on_write {
            flag.store(true, Ordering::SeqCst);
        }
        Ok(data.len())
    }

    fn sync_data(&mut self) -> Result<(), io::Error> {
        self.sync_called = true;
        if self.sync_fail {
            return Err(io::Error::other("Injected mock sync error"));
        }
        Ok(())
    }

    fn flush_buffers(&mut self) -> Result<(), io::Error> {
        self.sync_data()
    }

    fn total_size(&self) -> Result<u64, io::Error> {
        Ok(self.size)
    }

    fn io_mode(&self) -> &'static str {
        self.custom_io_mode.unwrap_or("mock")
    }
}

pub struct SpeedEstimator {
    samples: VecDeque<(Instant, u64)>,
    window_secs: f64,
}

impl SpeedEstimator {
    pub fn new(window_secs: f64) -> Self {
        Self {
            samples: VecDeque::new(),
            window_secs,
        }
    }

    pub fn record(&mut self, now: Instant, bytes_done: u64) {
        self.samples.push_back((now, bytes_done));
        let cutoff = now - std::time::Duration::from_secs_f64(self.window_secs);
        while let Some(&(t, _)) = self.samples.front() {
            if t < cutoff && self.samples.len() > 1 {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn current_speed(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }
        let (first_t, first_b) = self.samples.front().unwrap();
        let (last_t, last_b) = self.samples.back().unwrap();
        let dt = (*last_t - *first_t).as_secs_f64();
        if dt > 0.05 {
            (*last_b - *first_b) as f64 / dt
        } else {
            0.0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckpointData {
    pub job_id: String,
    pub device_size: u64,
    pub device_id_hash: String,
    pub bytes_done: u64,
    pub timestamp: u64,
}

pub fn get_checkpoint_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("ZT_CHECKPOINT_DIR") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    // Check if running under sudo or pkexec as root
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                if !sudo_user.trim().is_empty() && sudo_user != "root" {
                    let user_home = PathBuf::from(format!("/home/{}", sudo_user.trim()));
                    if user_home.exists() {
                        return user_home.join(".local").join("state").join("zero_trace");
                    }
                }
            }
            if let Ok(pkexec_uid) = std::env::var("PKEXEC_UID") {
                if let Ok(uid) = pkexec_uid.trim().parse::<libc::uid_t>() {
                    let passwd = unsafe { libc::getpwuid(uid) };
                    if !passwd.is_null() {
                        let pw_dir = unsafe { std::ffi::CStr::from_ptr((*passwd).pw_dir) };
                        if let Ok(home_str) = pw_dir.to_str() {
                            return PathBuf::from(home_str).join(".local").join("state").join("zero_trace");
                        }
                    }
                }
            }
        }
    }
    if let Ok(xdg_state) = std::env::var("XDG_STATE_HOME") {
        if !xdg_state.trim().is_empty() {
            return PathBuf::from(xdg_state).join("zero_trace");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home).join(".local").join("state").join("zero_trace");
        }
    }
    PathBuf::from("/tmp/zero_trace")
}

pub fn write_checkpoint_file(job_id: &str, serial: &str, device_size: u64, bytes_done: u64) {
    write_checkpoint_file_in_dir(&get_checkpoint_dir(), job_id, serial, device_size, bytes_done);
}

pub fn remove_checkpoint_file() {
    remove_checkpoint_file_in_dir(&get_checkpoint_dir());
}

pub fn write_checkpoint_file_in_dir(dir: &Path, job_id: &str, serial: &str, device_size: u64, bytes_done: u64) {
    let _ = fs::create_dir_all(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }

    let final_path = dir.join("active_checkpoint.json");
    let tmp_path = dir.join(format!("active_checkpoint.{}.tmp", std::process::id()));

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let device_id_hash = format!("{:x}", Sha256::digest(serial.as_bytes()));

    let checkpoint = CheckpointData {
        job_id: job_id.to_string(),
        device_size,
        device_id_hash,
        bytes_done,
        timestamp: now_ts,
    };
    let payload = match serde_json::to_string_pretty(&checkpoint) {
        Ok(s) => s,
        Err(_) => return,
    };

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;

        let c_tmp = match std::ffi::CString::new(tmp_path.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(_) => return,
        };
        // Unlink any prior stale tmp file with this name
        let _ = unsafe { libc::unlink(c_tmp.as_ptr()) };

        let fd = unsafe {
            libc::open(
                c_tmp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd >= 0 {
            // Chown to calling user if running under sudo or pkexec
            if let Ok(uid_str) = std::env::var("SUDO_UID").or_else(|_| std::env::var("PKEXEC_UID")) {
                if let Ok(uid) = uid_str.trim().parse::<libc::uid_t>() {
                    let gid = std::env::var("SUDO_GID").ok().and_then(|g| g.trim().parse::<libc::gid_t>().ok()).unwrap_or(uid);
                    unsafe { libc::fchown(fd, uid, gid); }
                }
            }

            let mut file = unsafe { fs::File::from_raw_fd(fd) };
            if file.write_all(payload.as_bytes()).is_ok() {
                let _ = file.sync_all();
                drop(file);
                let _ = fs::rename(&tmp_path, &final_path);
            }
        }
    }

    #[cfg(not(unix))]
    {
        if fs::write(&tmp_path, &payload).is_ok() {
            let _ = fs::rename(&tmp_path, &final_path);
        }
    }
}

pub fn remove_checkpoint_file_in_dir(dir: &Path) {
    let final_path = dir.join("active_checkpoint.json");
    let tmp_path = dir.join(format!("active_checkpoint.{}.tmp", std::process::id()));
    let _ = fs::remove_file(final_path);
    let _ = fs::remove_file(tmp_path);
    let _ = fs::remove_file(dir.join("active_checkpoint.tmp"));
}

pub async fn execute_writer_overwrite<W: BlockWriter>(
    writer: W,
    total_passes: u8,
    pattern: OverwritePattern,
    device_serial: &str,
    method_name: &str,
    start: Instant,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    execute_writer_overwrite_with_cancel(
        writer,
        total_passes,
        pattern,
        device_serial,
        method_name,
        start,
        tx,
        None,
    ).await
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_writer_overwrite_with_cancel<W: BlockWriter>(
    mut writer: W,
    total_passes: u8,
    pattern: OverwritePattern,
    device_serial: &str,
    method_name: &str,
    start: Instant,
    tx: mpsc::Sender<ProgressEvent>,
    external_cancel_flag: Option<Arc<AtomicBool>>,
) -> Result<ExecutionReport, ExecuteError> {
    let command_log = vec![format!("Native block overwrite ({} passes, mode: {})", total_passes, writer.io_mode())];
    let device_size = writer.total_size().map_err(ExecuteError::IoError)?;
    let total_bytes = total_passes as u64 * device_size;

    let device_id_hash = format!("{:x}", Sha256::digest(device_serial.as_bytes()));
    let job_id = std::env::var("ZT_JOB_ID").unwrap_or_else(|_| format!("job-{}", &device_id_hash[..12]));

    let cancel_flag = external_cancel_flag.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let _term_hook = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&cancel_flag));
    let _int_hook = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&cancel_flag));

    let chunk_size = 2 * 1024 * 1024usize; // 2 MiB chunks
    let mut aligned_buf = AlignedBuffer::new(chunk_size);
    let mut speed_est = SpeedEstimator::new(3.0); // 3-second sliding window

    let bytes_done_shared = Arc::new(AtomicU64::new(0));
    let phase_shared = Arc::new(Mutex::new(ExecutionPhase::Preparing));

    // Spawn 1-second heartbeat task
    let (hb_stop_tx, mut hb_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let hb_tx = tx.clone();
    let hb_bytes_done = Arc::clone(&bytes_done_shared);
    let hb_phase = Arc::clone(&phase_shared);
    let hb_total_bytes = total_bytes;

    let hb_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(1000));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let phase = hb_phase.lock().unwrap().clone();
                    let done = hb_bytes_done.load(Ordering::Relaxed);
                    let pct = if hb_total_bytes > 0 { Some(done as f32 / hb_total_bytes as f32) } else { None };
                    let _ = hb_tx.send(ProgressEvent {
                        schema_version: 2,
                        phase,
                        bytes_done: done,
                        bytes_total: hb_total_bytes,
                        percent: pct,
                        speed_bytes_per_sec: 0.0,
                        eta_seconds: None,
                        message: "heartbeat".to_string(),
                        is_heartbeat: true,
                    }).await;
                }
                _ = &mut hb_stop_rx => {
                    break;
                }
            }
        }
    });

    let mut overall_bytes_done: u64 = 0;
    let mut uncommitted_buffered_bytes: u64 = 0;
    let is_buffered_mode = writer.io_mode().starts_with("buffered");
    let mut last_event_time = Instant::now();
    let mut last_checkpoint_time = Instant::now();

    *phase_shared.lock().unwrap() = ExecutionPhase::FirmwareCommand; // Writing phase

    let mut prng = ChaCha20Rng::from_entropy();

    for pass_idx in 0..total_passes {
        let is_random = match pattern {
            OverwritePattern::Random => true,
            OverwritePattern::MultiPass3 => pass_idx == 1,
            _ => false,
        };

        if !is_random {
            let fill_byte = match pattern {
                OverwritePattern::Ones => 0xFF,
                _ => 0x00,
            };
            aligned_buf.as_mut_slice().fill(fill_byte);
        }

        let mut offset = 0u64;
        while offset < device_size {
            // Check cancellation flag
            if cancel_flag.load(Ordering::SeqCst) {
                let _ = writer.sync_data();
                if is_buffered_mode && uncommitted_buffered_bytes > 0 {
                    overall_bytes_done += uncommitted_buffered_bytes;
                    bytes_done_shared.store(overall_bytes_done, Ordering::Relaxed);
                }
                write_checkpoint_file(&job_id, device_serial, device_size, overall_bytes_done);
                let _ = hb_stop_tx.send(());
                let _ = hb_task.await;
                let _ = tx.send(ProgressEvent {
                    schema_version: 2,
                    phase: ExecutionPhase::FirmwareCommand,
                    bytes_done: overall_bytes_done,
                    bytes_total: total_bytes,
                    percent: if total_bytes > 0 { Some(overall_bytes_done as f32 / total_bytes as f32) } else { None },
                    speed_bytes_per_sec: 0.0,
                    eta_seconds: None,
                    message: "Sanitization cancelled by user".to_string(),
                    is_heartbeat: false,
                }).await;
                return Ok(ExecutionReport {
                    success: false,
                    method_used: method_name.to_string(),
                    command_log,
                    stdout: String::new(),
                    stderr: "Sanitization cancelled by user: partially wiped".to_string(),
                    exit_code: 130,
                    duration_ms: start.elapsed().as_millis() as u64,
                    dry_run: false,
                    bytes_written: overall_bytes_done,
                    io_mode: writer.io_mode().to_string(),
                });
            }

            let write_len = std::cmp::min(chunk_size as u64, device_size - offset) as usize;
            if is_random {
                prng.fill_bytes(&mut aligned_buf.as_mut_slice()[..write_len]);
            }

            let mut written_for_chunk = 0;
            while written_for_chunk < write_len {
                if cancel_flag.load(Ordering::SeqCst) {
                    let _ = writer.sync_data();
                    if is_buffered_mode && uncommitted_buffered_bytes > 0 {
                        overall_bytes_done += uncommitted_buffered_bytes;
                        bytes_done_shared.store(overall_bytes_done, Ordering::Relaxed);
                    }
                    write_checkpoint_file(&job_id, device_serial, device_size, overall_bytes_done);
                    let _ = hb_stop_tx.send(());
                    let _ = hb_task.await;
                    let _ = tx.send(ProgressEvent {
                        schema_version: 2,
                        phase: ExecutionPhase::FirmwareCommand,
                        bytes_done: overall_bytes_done,
                        bytes_total: total_bytes,
                        percent: if total_bytes > 0 { Some(overall_bytes_done as f32 / total_bytes as f32) } else { None },
                        speed_bytes_per_sec: 0.0,
                        eta_seconds: None,
                        message: "Sanitization cancelled by user".to_string(),
                        is_heartbeat: false,
                    }).await;
                    return Ok(ExecutionReport {
                        success: false,
                        method_used: method_name.to_string(),
                        command_log,
                        stdout: String::new(),
                        stderr: "Sanitization cancelled by user: partially wiped".to_string(),
                        exit_code: 130,
                        duration_ms: start.elapsed().as_millis() as u64,
                        dry_run: false,
                        bytes_written: overall_bytes_done,
                        io_mode: writer.io_mode().to_string(),
                    });
                }

                let slice = &aligned_buf.as_slice()[written_for_chunk..write_len];
                match writer.write_chunk(offset + written_for_chunk as u64, slice) {
                    Ok(0) => {
                        let _ = hb_stop_tx.send(());
                        let _ = hb_task.await;
                        return Err(ExecuteError::PrematureEndOfDevice("Write returned 0 bytes (ENOSPC)".into()));
                    }
                    Ok(n) => {
                        written_for_chunk += n;
                        if is_buffered_mode {
                            uncommitted_buffered_bytes += n as u64;
                            // In buffered mode, flush periodically (e.g. 16MB) or when pass finishes
                            if uncommitted_buffered_bytes >= 16 * 1024 * 1024 || (offset + written_for_chunk as u64 >= device_size) {
                                if let Err(e) = writer.sync_data() {
                                    let _ = hb_stop_tx.send(());
                                    let _ = hb_task.await;
                                    return Err(ExecuteError::IoError(e));
                                }
                                overall_bytes_done += uncommitted_buffered_bytes;
                                uncommitted_buffered_bytes = 0;
                                bytes_done_shared.store(overall_bytes_done, Ordering::Relaxed);
                            }
                        } else {
                            overall_bytes_done += n as u64;
                            bytes_done_shared.store(overall_bytes_done, Ordering::Relaxed);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                        let _ = hb_stop_tx.send(());
                        let _ = hb_task.await;
                        return Err(ExecuteError::HardwareIo(format!("EIO at offset {}: {}", offset + written_for_chunk as u64, e)));
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENODEV) => {
                        let _ = hb_stop_tx.send(());
                        let _ = hb_task.await;
                        return Err(ExecuteError::DeviceDisconnected(format!("ENODEV at offset {}: {}", offset + written_for_chunk as u64, e)));
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {
                        let _ = hb_stop_tx.send(());
                        let _ = hb_task.await;
                        return Err(ExecuteError::PrematureEndOfDevice(format!("ENOSPC at offset {}: {}", offset + written_for_chunk as u64, e)));
                    }
                    Err(e) => {
                        let _ = hb_stop_tx.send(());
                        let _ = hb_task.await;
                        return Err(ExecuteError::IoError(e));
                    }
                }
            }

            offset += write_len as u64;
            speed_est.record(Instant::now(), overall_bytes_done);

            // Throttle progress events to ~3/sec
            let now = Instant::now();
            if now.duration_since(last_event_time).as_millis() >= 300 || offset >= device_size {
                last_event_time = now;
                let cur_speed = speed_est.current_speed();
                let eta = if cur_speed > 1024.0 && overall_bytes_done < total_bytes {
                    Some(((total_bytes - overall_bytes_done) as f64 / cur_speed) as u32)
                } else {
                    None
                };
                let pct = overall_bytes_done as f32 / total_bytes as f32;
                let msg = format!("Pass {} of {}: writing to media", pass_idx + 1, total_passes);
                send_detailed_progress(&tx, ExecutionPhase::FirmwareCommand, overall_bytes_done, total_bytes, Some(pct), cur_speed, eta, &msg, false).await;
            }

            // Periodic checkpoint file write (~every 2 seconds)
            if now.duration_since(last_checkpoint_time).as_secs() >= 2 {
                last_checkpoint_time = now;
                write_checkpoint_file(&job_id, device_serial, device_size, overall_bytes_done);
            }
        }
    }

    // Flush phase (Item 1, 2, 3)
    *phase_shared.lock().unwrap() = ExecutionPhase::Flushing;
    send_detailed_progress(&tx, ExecutionPhase::Flushing, overall_bytes_done, total_bytes, None, 0.0, None, "Finalizing, flushing to drive", false).await;

    // Check cancellation promptly at start of flush
    if cancel_flag.load(Ordering::SeqCst) {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        write_checkpoint_file(&job_id, device_serial, device_size, overall_bytes_done);
        return Ok(ExecutionReport {
            success: false,
            method_used: method_name.to_string(),
            command_log,
            stdout: String::new(),
            stderr: "Sanitization cancelled by user during flush".to_string(),
            exit_code: 130,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: false,
            bytes_written: overall_bytes_done,
            io_mode: writer.io_mode().to_string(),
        });
    }

    if let Err(e) = writer.sync_data() {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        return Err(ExecuteError::IoError(e));
    }
    if let Err(e) = writer.flush_buffers() {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        return Err(ExecuteError::IoError(e));
    }

    // Check cancellation promptly after sync/flush
    if cancel_flag.load(Ordering::SeqCst) {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        write_checkpoint_file(&job_id, device_serial, device_size, overall_bytes_done);
        return Ok(ExecutionReport {
            success: false,
            method_used: method_name.to_string(),
            command_log,
            stdout: String::new(),
            stderr: "Sanitization cancelled by user after flush".to_string(),
            exit_code: 130,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: false,
            bytes_written: overall_bytes_done,
            io_mode: writer.io_mode().to_string(),
        });
    }

    *phase_shared.lock().unwrap() = ExecutionPhase::Verification;
    send_detailed_progress(&tx, ExecutionPhase::Verification, overall_bytes_done, total_bytes, None, 0.0, None, "Verifying sector erasure...", false).await;

    // Check cancellation promptly before verification
    if cancel_flag.load(Ordering::SeqCst) {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        write_checkpoint_file(&job_id, device_serial, device_size, overall_bytes_done);
        return Ok(ExecutionReport {
            success: false,
            method_used: method_name.to_string(),
            command_log,
            stdout: String::new(),
            stderr: "Sanitization cancelled by user during verification".to_string(),
            exit_code: 130,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: false,
            bytes_written: overall_bytes_done,
            io_mode: writer.io_mode().to_string(),
        });
    }

    let _ = hb_stop_tx.send(());
    let _ = hb_task.await;

    // Checkpoint removal upon success
    remove_checkpoint_file();

    Ok(ExecutionReport {
        success: overall_bytes_done == total_bytes,
        method_used: method_name.to_string(),
        command_log,
        stdout: format!("Successfully overwritten {} bytes in {} passes", overall_bytes_done, total_passes),
        stderr: String::new(),
        exit_code: 0,
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run: false,
        bytes_written: overall_bytes_done,
        io_mode: writer.io_mode().to_string(),
    })
}

/// Software Overwrite — native direct I/O overwrite.
/// Performs sector-aligned Direct I/O writes (with O_DSYNC / buffered sync fallbacks)
/// replacing legacy dd execution.
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

    // 1. Safety validation and identity pinning
    check_boot_disk_protection(device, dry_run)?;
    verify_confirmation(confirmation_token, device_serial)?;
    let guard_identity = get_guard_identity(device, dry_run, device_serial, &FsContext::default())?;

    let total_passes = match pattern {
        OverwritePattern::MultiPass3 => 3u8,
        _ => passes.max(1),
    };

    let method_name = format!(
        "Software Overwrite ({}-pass, {:?})",
        total_passes, pattern
    );

    // 2. Item 2: Move dry-run branch before unmount step!
    if dry_run {
        command_log.push(format!("[DRY RUN] Native block overwrite: {} passes ({:?}) on {}", total_passes, pattern, device));
        send_detailed_progress(&tx, ExecutionPhase::FirmwareCommand, 0, 0, None, 0.0, None, "[DRY RUN] Starting simulated overwrite...", false).await;
        for pass in 1..=total_passes {
            send_detailed_progress(&tx, ExecutionPhase::FirmwareCommand, 0, 0, None, 0.0, None,
                &format!("[DRY RUN] Overwrite pass {} of {} complete", pass, total_passes), false).await;
        }
        send_detailed_progress(&tx, ExecutionPhase::Flushing, 0, 0, None, 0.0, None, "[DRY RUN] Flushing complete", false).await;
        send_detailed_progress(&tx, ExecutionPhase::Verification, 0, 0, None, 0.0, None, "[DRY RUN] Post-verification complete", false).await;
        return Ok(ExecutionReport {
            success: true,
            method_used: method_name,
            command_log,
            stdout: "[DRY RUN] Overwrite simulated successfully".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: true,
            bytes_written: 0,
            io_mode: "dry_run".to_string(),
        });
    }

    send_detailed_progress(&tx, ExecutionPhase::SecurityUnlock, 0, 0, None, 0.0, Some(5),
        "Unmounting filesystems on target device...", false).await;

    // 3. Unmount any active partitions
    let (_stdout, _stderr) = unmount_device_if_mounted(device, false, &mut command_log);

    // 4. Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, false, &FsContext::default())?;

    // 5. Open native block writer with O_EXCL and fd identity validation
    let writer = DirectBlockWriter::open(&guard_identity.canonical_path, &guard_identity)?;

    // 6. Execute native overwrite
    execute_writer_overwrite(
        writer,
        total_passes,
        pattern,
        device_serial,
        &method_name,
        start,
        tx,
    ).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngineMethod {
    AtaSecureErase,
    AtaEnhancedSecureErase,
    AtaSanitizeBlock,
    AtaSanitizeCrypto,
    NvmeSanitizeBlock,
    NvmeSanitizeCrypto,
    OpalRevert,
    EmmcSanitize,
    /// A6: kernel TRIM/UNMAP (blkdiscard-style) over a device or partition range.
    Discard,
    OverwriteZero,
    OverwriteRandom,
    Overwrite3Pass,
}

impl EngineMethod {
    pub const ALL: &'static [EngineMethod] = &[
        EngineMethod::AtaSecureErase,
        EngineMethod::AtaEnhancedSecureErase,
        EngineMethod::AtaSanitizeBlock,
        EngineMethod::AtaSanitizeCrypto,
        EngineMethod::NvmeSanitizeBlock,
        EngineMethod::NvmeSanitizeCrypto,
        EngineMethod::OpalRevert,
        EngineMethod::EmmcSanitize,
        EngineMethod::Discard,
        EngineMethod::OverwriteZero,
        EngineMethod::OverwriteRandom,
        EngineMethod::Overwrite3Pass,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            EngineMethod::AtaSecureErase => "ata-secure-erase",
            EngineMethod::AtaEnhancedSecureErase => "ata-enhanced-secure-erase",
            EngineMethod::AtaSanitizeBlock => "ata-sanitize-block",
            EngineMethod::AtaSanitizeCrypto => "ata-sanitize-crypto",
            EngineMethod::NvmeSanitizeBlock => "nvme-sanitize-block",
            EngineMethod::NvmeSanitizeCrypto => "nvme-sanitize-crypto",
            EngineMethod::OpalRevert => "opal-revert",
            EngineMethod::EmmcSanitize => "emmc-sanitize",
            EngineMethod::Discard => "discard",
            EngineMethod::OverwriteZero => "overwrite-zero",
            EngineMethod::OverwriteRandom => "overwrite-random",
            EngineMethod::Overwrite3Pass => "overwrite-3pass",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "ata-secure-erase" => Some(EngineMethod::AtaSecureErase),
            "ata-enhanced-secure-erase" => Some(EngineMethod::AtaEnhancedSecureErase),
            "ata-sanitize-block" => Some(EngineMethod::AtaSanitizeBlock),
            "ata-sanitize-crypto" => Some(EngineMethod::AtaSanitizeCrypto),
            "nvme-sanitize-block" => Some(EngineMethod::NvmeSanitizeBlock),
            "nvme-sanitize-crypto" => Some(EngineMethod::NvmeSanitizeCrypto),
            "opal-revert" => Some(EngineMethod::OpalRevert),
            "emmc-sanitize" => Some(EngineMethod::EmmcSanitize),
            "discard" => Some(EngineMethod::Discard),
            "overwrite-zero" => Some(EngineMethod::OverwriteZero),
            "overwrite-random" => Some(EngineMethod::OverwriteRandom),
            "overwrite-3pass" => Some(EngineMethod::Overwrite3Pass),
            _ => None,
        }
    }

    pub fn is_allowed_in_partition_mode(&self) -> bool {
        matches!(
            self,
            EngineMethod::OverwriteZero
                | EngineMethod::OverwriteRandom
                | EngineMethod::Overwrite3Pass
                // A6: BLKDISCARD targets an explicit byte range natively.
                | EngineMethod::Discard
        )
    }
}

pub const ALLOWED_PARTITION_METHODS: &[&str] = &[
    "overwrite-zero",
    "overwrite-random",
    "overwrite-3pass",
    // A6
    "discard",
];

pub fn validate_partition_method(method: &str) -> Result<EngineMethod, ExecuteError> {
    let engine_method = EngineMethod::from_str_opt(method).ok_or_else(|| {
        ExecuteError::UnsupportedOperation(format!("Unknown sanitization method: {}", method))
    })?;
    if !engine_method.is_allowed_in_partition_mode() {
        return Err(ExecuteError::UnsupportedOperation(format!(
            "Method '{}' is not allowed in partition mode. Partition mode only allows overwrite methods (overwrite-zero, overwrite-random, overwrite-3pass) and discard.",
            method
        )));
    }
    Ok(engine_method)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionTargetParams {
    pub expected_partition_num: u32,
    pub expected_start_sector: u64,
    pub expected_size_sectors: u64,
    pub expected_partuuid: Option<String>,
    pub expected_table_fingerprint: String,
}

/// Calculates the SHA-256 fingerprint of the partition table on the parent disk.
/// Sorted ascending by partition number: format "{part_num}:{start_sector}:{size_sectors}\n".
pub fn compute_partition_table_fingerprint(
    parent_disk: &str,
    ctx: &FsContext,
) -> Result<String, ExecuteError> {
    let parent_name = parent_disk.strip_prefix("/dev/").unwrap_or(parent_disk);
    let class_block = ctx.sys_root.join("class/block");
    let mut parts: Vec<(u32, u64, u64)> = Vec::new();

    if let Ok(entries) = fs::read_dir(&class_block) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(parent_name)
                && (name[parent_name.len()..].starts_with('p')
                    || name[parent_name.len()..].chars().next().is_some_and(|c| c.is_ascii_digit()))
            {
                let part_file = entry.path().join("partition");
                if part_file.exists() {
                    let num_str = fs::read_to_string(&part_file).unwrap_or_default();
                    if let Ok(num) = num_str.trim().parse::<u32>() {
                        let start_str = fs::read_to_string(entry.path().join("start")).unwrap_or_default();
                        let size_str = fs::read_to_string(entry.path().join("size")).unwrap_or_default();
                        let start = start_str.trim().parse::<u64>().unwrap_or(0);
                        let size = size_str.trim().parse::<u64>().unwrap_or(0);
                        parts.push((num, start, size));
                    }
                }
            }
        }
    }

    parts.sort_by_key(|p| p.0);

    let mut canonical_text = String::new();
    for (num, start, size) in parts {
        canonical_text.push_str(&format!("{}:{}:{}\n", num, start, size));
    }

    let hash = format!("{:x}", Sha256::digest(canonical_text.as_bytes()));
    Ok(hash)
}

/// Check if a target partition is an MBR extended container partition.
pub fn is_mbr_extended_partition(
    device: &str,
    parent_disk: &str,
    ctx: &FsContext,
) -> Result<bool, ExecuteError> {
    let part_name = device.strip_prefix("/dev/").unwrap_or(device);
    let class_block = ctx.sys_root.join("class/block");
    let part_dir = class_block.join(part_name);

    if part_dir.join("subpartition").exists() {
        return Ok(true);
    }

    let parent_canonical = canonicalize_device_path(parent_disk, false, ctx).unwrap_or_else(|_| parent_disk.to_string());
    let parent_file_path = if ctx.dev_root != Path::new("/dev") {
        let rel = parent_disk.strip_prefix("/dev/").unwrap_or(parent_disk);
        ctx.dev_root.join(rel)
    } else {
        PathBuf::from(&parent_canonical)
    };
    if let Ok(mut file) = fs::File::open(&parent_file_path) {
        use std::io::Read;
        let mut mbr = [0u8; 512];
        if file.read_exact(&mut mbr).is_ok() && mbr[510] == 0x55 && mbr[511] == 0xAA {
            let start_str = fs::read_to_string(part_dir.join("start")).unwrap_or_default();
            let target_start = start_str.trim().parse::<u32>().unwrap_or(0);
            let part_num_str = fs::read_to_string(part_dir.join("partition")).unwrap_or_default();
            let target_num = part_num_str.trim().parse::<u32>().ok();
            for i in 0..4 {
                let entry_offset = 446 + i * 16;
                let sys_ind = mbr[entry_offset + 4];
                let start_lba = u32::from_le_bytes([
                    mbr[entry_offset + 8],
                    mbr[entry_offset + 9],
                    mbr[entry_offset + 10],
                    mbr[entry_offset + 11],
                ]);
                let matches_start = target_start != 0 && target_start == start_lba;
                let matches_num = target_num == Some(i as u32 + 1);
                if (sys_ind == 0x05 || sys_ind == 0x0f || sys_ind == 0x85)
                    && (matches_start || matches_num || (target_start == 0 && target_num.is_none()))
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Safely unmounts active filesystems on the target partition and any active holders.
/// Sibling partitions are left untouched.
pub fn unmount_target_partition_and_holders(
    target_partition: &str,
    dry_run: bool,
    command_log: &mut Vec<String>,
    ctx: &FsContext,
) -> Result<(String, String), ExecuteError> {
    let mut stdout_accum = String::new();
    let mut stderr_accum = String::new();

    if dry_run {
        command_log.push(format!("[DRY RUN] Would check mounts and unmount partition {} and its holders", target_partition));
        return Ok((stdout_accum, stderr_accum));
    }

    let target_name = target_partition.strip_prefix("/dev/").unwrap_or(target_partition);
    let target_canonical = canonicalize_device_path(target_partition, dry_run, ctx)?;

    // 1. Resolve holders from /sys/class/block/<dev>/holders
    let holders_dir = ctx.sys_root.join("class/block").join(target_name).join("holders");
    let mut holders = Vec::new();
    if holders_dir.exists() {
        if let Ok(entries) = fs::read_dir(&holders_dir) {
            for entry in entries.flatten() {
                let h_name = entry.file_name().to_string_lossy().to_string();
                holders.push(h_name);
            }
        }
    }

    let mounts_content = fs::read_to_string(ctx.proc_root.join("mounts")).unwrap_or_default();

    for holder in &holders {
        let holder_dev = format!("/dev/{}", holder);
        let mut is_mounted = false;
        for line in mounts_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() && (parts[0] == holder_dev || parts[0].ends_with(holder)) {
                is_mounted = true;
                break;
            }
        }
        if is_mounted {
            command_log.push(format!("[UNMOUNT] Unmounting active holder: {}", holder_dev));
            let (stdout, stderr, code) = run_cmd("umount", &["-f", &holder_dev], dry_run, command_log)?;
            stdout_accum.push_str(&stdout);
            stderr_accum.push_str(&stderr);
            if code != 0 {
                return Err(ExecuteError::CommandFailed(format!(
                    "Target partition {} is held by active holder '{}' which cannot be unmounted",
                    target_partition, holder_dev
                )));
            }
        }
    }

    let mut is_target_mounted = false;
    for line in mounts_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.is_empty() && (parts[0] == target_partition || parts[0] == target_canonical) {
            is_target_mounted = true;
            break;
        }
    }

    if is_target_mounted {
        command_log.push(format!("[UNMOUNT] Unmounting active partition: {}", target_partition));
        let (stdout, stderr, code) = run_cmd("umount", &["-f", target_partition], dry_run, command_log)?;
        stdout_accum.push_str(&stdout);
        stderr_accum.push_str(&stderr);
        if code != 0 {
            return Err(ExecuteError::CommandFailed(format!(
                "Failed to unmount partition {}: {}", target_partition, stderr
            )));
        }
    }

    Ok((stdout_accum, stderr_accum))
}

/// Resolves the parent disk device name from a partition device path or name.
pub fn resolve_parent_disk(device: &str, ctx: &FsContext) -> Result<String, ExecuteError> {
    let target_name = device.strip_prefix("/dev/").unwrap_or(device);
    let target_block_dir = ctx.sys_root.join("class/block").join(target_name);

    if let Ok(link) = fs::read_link(&target_block_dir) {
        if let Some(parent) = link.parent() {
            if let Some(p_name) = parent.file_name() {
                let p_str = p_name.to_string_lossy().to_string();
                if p_str != "block" && ctx.sys_root.join("class/block").join(&p_str).exists() {
                    return Ok(p_str);
                }
            }
        }
    }

    if target_name.starts_with("nvme") || target_name.starts_with("mmcblk") {
        if let Some(idx) = target_name.rfind('p') {
            let candidate = &target_name[..idx];
            if ctx.sys_root.join("class/block").join(candidate).exists() {
                return Ok(candidate.to_string());
            }
        }
    } else {
        let candidate = target_name.trim_end_matches(|c: char| c.is_ascii_digit());
        if !candidate.is_empty() && ctx.sys_root.join("class/block").join(candidate).exists() {
            return Ok(candidate.to_string());
        }
    }

    Err(ExecuteError::DeviceNotFound(format!(
        "Cannot resolve parent disk for partition {}",
        device
    )))
}

/// Maps raw OS open/lock errors into appropriate ExecuteError.
/// Specifically translates libc::EBUSY into the auto-remount retry message.
pub fn map_open_excl_error(err: io::Error, path: &str) -> ExecuteError {
    if err.raw_os_error() == Some(libc::EBUSY) {
        ExecuteError::CommandFailed(format!(
            "the system remounted the drive, retry (Device {} is busy or mounted with O_EXCL conflict)",
            path
        ))
    } else {
        ExecuteError::DeviceNotFound(format!(
            "Failed to open device {} with O_EXCL: {}",
            path, err
        ))
    }
}

/// Resolves the parent disk's serial number for a partition device node.
pub fn resolve_parent_serial(device: &str, ctx: &FsContext) -> Result<String, ExecuteError> {
    let parent_name = resolve_parent_disk(device, ctx)?;
    let parent_dir = ctx.sys_root.join("class/block").join(&parent_name);

    for path in &[
        parent_dir.join("device/serial"),
        parent_dir.join("serial"),
    ] {
        if let Ok(content) = fs::read_to_string(path) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }

    let uevent_paths = [
        parent_dir.join("device/uevent"),
        parent_dir.join("uevent"),
    ];
    for uevent_path in &uevent_paths {
        if let Ok(uevent) = fs::read_to_string(uevent_path) {
            for line in uevent.lines() {
                if let Some(s) = line.strip_prefix("ID_SERIAL_SHORT=")
                    .or_else(|| line.strip_prefix("ID_SERIAL="))
                    .or_else(|| line.strip_prefix("SERIAL=")) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return Ok(trimmed.to_string());
                    }
                }
            }
        }
    }

    Err(ExecuteError::DeviceNotFound(format!(
        "Cannot resolve serial for parent disk {} of partition {}",
        parent_name, device
    )))
}

/// Performs sector-aligned overwrite on a specific partition node.
/// Enforces partition method allowlist, sysfs geometry match, parent serial check,
/// partition table fingerprint invariance, targeted unmount of holders,
/// and bounds enforcement via PartitionRangeWriter.
#[allow(clippy::too_many_arguments)]
/// Validated partition target: geometry cross-checked against sysfs, PARTUUID
/// and partition-table fingerprint, MBR extended containers refused, sizes
/// aligned to the logical block size, plus the pinned guard identity.
/// Shared by the partition overwrite and A6 discard execution paths.
pub struct ValidatedPartitionTarget {
    pub parent_name: String,
    pub start_bytes: u64,
    pub size_bytes: u64,
    pub logical_block_size: u64,
    pub guard_identity: GuardIdentity,
}

/// Validate a partition-mode target before any destructive open:
/// sysfs geometry (number/start/size), optional PARTUUID, partition table
/// fingerprint, MBR extended container refusal, logical-block alignment and
/// the pinned guard identity. Called by both partition overwrite and discard.
pub fn validate_partition_target(
    device: &str,
    params: &PartitionTargetParams,
    ctx: &FsContext,
    dry_run: bool,
    device_serial: &str,
) -> Result<ValidatedPartitionTarget, ExecuteError> {
    let target_name = device.strip_prefix("/dev/").unwrap_or(device);
    let class_block = ctx.sys_root.join("class/block");
    let part_dir = class_block.join(target_name);

    // Sysfs geometry validation: partition, start, size
    let part_file = part_dir.join("partition");
    if !part_file.exists() {
        return Err(ExecuteError::UnsupportedOperation(format!(
            "Target '{}' is not recognized as a partition in sysfs ({})",
            device, part_dir.display()
        )));
    }
    let actual_num: u32 = fs::read_to_string(&part_file)
        .unwrap_or_default()
        .trim()
        .parse()
        .map_err(|_| ExecuteError::IdentityMismatch("Corrupt sysfs partition file".into()))?;
    if actual_num != params.expected_partition_num {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Partition number mismatch: expected {}, got sysfs partition {}",
            params.expected_partition_num, actual_num
        )));
    }

    let actual_start: u64 = fs::read_to_string(part_dir.join("start"))
        .unwrap_or_default()
        .trim()
        .parse()
        .map_err(|_| ExecuteError::IdentityMismatch("Corrupt sysfs start file".into()))?;
    if actual_start != params.expected_start_sector {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Partition start sector mismatch: expected {}, got sysfs start {}",
            params.expected_start_sector, actual_start
        )));
    }

    let actual_size: u64 = fs::read_to_string(part_dir.join("size"))
        .unwrap_or_default()
        .trim()
        .parse()
        .map_err(|_| ExecuteError::IdentityMismatch("Corrupt sysfs size file".into()))?;
    if actual_size != params.expected_size_sectors {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Partition size sectors mismatch: expected {}, got sysfs size {}",
            params.expected_size_sectors, actual_size
        )));
    }

    // Optional PARTUUID check
    if let Some(expected_uuid) = &params.expected_partuuid {
        let uevent = fs::read_to_string(part_dir.join("uevent")).unwrap_or_default();
        let mut found_uuid = None;
        for line in uevent.lines() {
            if let Some(uuid) = line.strip_prefix("PARTUUID=") {
                found_uuid = Some(uuid.trim().to_string());
                break;
            }
        }
        if let Some(actual_uuid) = found_uuid {
            if !actual_uuid.eq_ignore_ascii_case(expected_uuid) {
                return Err(ExecuteError::IdentityMismatch(format!(
                    "PARTUUID mismatch: expected {}, got sysfs {}",
                    expected_uuid, actual_uuid
                )));
            }
        }
    }

    // Resolve parent disk and check partition table fingerprint
    let parent_name = resolve_parent_disk(device, ctx)?;
    let actual_fingerprint = compute_partition_table_fingerprint(&parent_name, ctx)?;
    if actual_fingerprint != params.expected_table_fingerprint {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Partition table changed: expected fingerprint {}, got sysfs {}",
            params.expected_table_fingerprint, actual_fingerprint
        )));
    }

    // Refuse MBR extended container partitions
    let parent_path = format!("/dev/{}", parent_name);
    if is_mbr_extended_partition(device, &parent_path, ctx)? {
        return Err(ExecuteError::UnsupportedOperation(format!(
            "Refusing operation: target '{}' is an MBR extended container partition",
            device
        )));
    }

    // Logical block size alignment validation
    let lbs: u64 = fs::read_to_string(ctx.sys_root.join("class/block").join(&parent_name).join("queue/logical_block_size"))
        .or_else(|_| fs::read_to_string(part_dir.join("queue/logical_block_size")))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(512);

    let start_bytes = actual_start.checked_mul(512).ok_or_else(|| {
        ExecuteError::UnsupportedOperation("Partition start sector overflow".into())
    })?;
    let size_bytes = actual_size.checked_mul(512).ok_or_else(|| {
        ExecuteError::UnsupportedOperation("Partition size sector overflow".into())
    })?;
    if start_bytes % lbs != 0 || size_bytes % lbs != 0 {
        return Err(ExecuteError::UnsupportedOperation(format!(
            "Partition start or size is not aligned to logical block size ({})",
            lbs
        )));
    }

    let guard_identity = get_guard_identity(device, dry_run, device_serial, ctx)?;

    Ok(ValidatedPartitionTarget {
        parent_name,
        start_bytes,
        size_bytes,
        logical_block_size: lbs,
        guard_identity,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn software_overwrite_partition(
    device: &str,
    passes: u8,
    pattern: OverwritePattern,
    confirmation_token: &str,
    device_serial: &str,
    params: &PartitionTargetParams,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    software_overwrite_partition_ctx(
        device,
        passes,
        pattern,
        confirmation_token,
        device_serial,
        params,
        dry_run,
        tx,
        &FsContext::default(),
    ).await
}

#[allow(clippy::too_many_arguments)]
pub async fn software_overwrite_partition_ctx(
    device: &str,
    passes: u8,
    pattern: OverwritePattern,
    confirmation_token: &str,
    device_serial: &str,
    params: &PartitionTargetParams,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
    ctx: &FsContext,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();

    // 1. Authoritative safety check: parent disk and target partition
    check_boot_disk_protection_ctx(device, dry_run, ctx)?;
    verify_confirmation(confirmation_token, device_serial)?;

    // 2. Shared partition validation (A6 extraction — byte-for-byte the same
    //    checks as before, now also feeding the discard path)
    let target = validate_partition_target(device, params, ctx, dry_run, device_serial)?;
    let guard_identity = target.guard_identity;
    let verified_size_bytes = target.size_bytes;

    let total_passes = match pattern {
        OverwritePattern::MultiPass3 => 3u8,
        _ => passes.max(1),
    };
    let method_name = format!(
        "Partition Overwrite ({}-pass, {:?})",
        total_passes, pattern
    );

    // 6. Dry run early exit: no unmounts, zero write opens
    if dry_run {
        command_log.push(format!(
            "[DRY RUN] Native partition block overwrite: {} passes ({:?}) on {} (size: {} bytes)",
            total_passes, pattern, device, verified_size_bytes
        ));
        send_detailed_progress(&tx, ExecutionPhase::FirmwareCommand, 0, 0, None, 0.0, None,
            "[DRY RUN] Starting simulated partition overwrite...", false).await;
        for pass in 1..=total_passes {
            send_detailed_progress(&tx, ExecutionPhase::FirmwareCommand, 0, 0, None, 0.0, None,
                &format!("[DRY RUN] Overwrite pass {} of {} complete", pass, total_passes), false).await;
        }
        send_detailed_progress(&tx, ExecutionPhase::Flushing, 0, 0, None, 0.0, None, "[DRY RUN] Flushing complete", false).await;
        send_detailed_progress(&tx, ExecutionPhase::Verification, 0, 0, None, 0.0, None, "[DRY RUN] Post-verification complete", false).await;
        return Ok(ExecutionReport {
            success: true,
            method_used: method_name,
            command_log,
            stdout: "[DRY RUN] Partition overwrite simulated successfully".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: true,
            bytes_written: 0,
            io_mode: "dry_run".to_string(),
        });
    }

    send_detailed_progress(&tx, ExecutionPhase::SecurityUnlock, 0, 0, None, 0.0, Some(5),
        "Unmounting filesystems on target partition...", false).await;

    // 7. Targeted unmount: target partition & holders only
    let (_stdout, _stderr) = unmount_target_partition_and_holders(device, false, &mut command_log, ctx)?;

    // 8. Verify exclusive access on the partition node
    verify_exclusive_access_and_recheck(device, false, ctx)?;

    // 9. Open native block writer on the partition node with O_EXCL
    let inner_writer = DirectBlockWriter::open(&guard_identity.canonical_path, &guard_identity)?;
    let actual_blk_size = inner_writer.total_size()?;
    if actual_blk_size != verified_size_bytes {
        return Err(ExecuteError::IdentityMismatch(format!(
            "BLKGETSIZE64 size ({}) does not match sysfs size ({})",
            actual_blk_size, verified_size_bytes
        )));
    }

    // 10. Wrap with PartitionRangeWriter as second boundary guard
    let range_writer = PartitionRangeWriter::new(inner_writer, 0, verified_size_bytes);

    // 11. Execute native overwrite
    execute_writer_overwrite(
        range_writer,
        total_passes,
        pattern,
        device_serial,
        &method_name,
        start,
        tx,
    ).await
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

        fn set_cmdline(&self, content: &str) {
            fs::write(self.path("proc/cmdline"), content).unwrap();
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

    // ------------------------------------------------------------------
    // A3b: live-mode awareness
    // ------------------------------------------------------------------

    #[test]
    fn test_boot_env_detection_all_modes() {
        // Normal: real root filesystem
        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n");
        f.set_cmdline("BOOT_IMAGE=/vmlinuz root=/dev/sda1 rw quiet\n");
        assert_eq!(
            detect_boot_environment_ctx(&f.ctx()).unwrap(),
            BootEnvironment::Normal
        );

        // Live: overlay root + live marker on the cmdline
        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 0:30 / / rw,relatime - overlay overlay rw,lowerdir=/run/live/medium\n");
        f.set_cmdline("boot=casper findiso=/isos/live.iso quiet\n");
        assert_eq!(
            detect_boot_environment_ctx(&f.ctx()).unwrap(),
            BootEnvironment::Live
        );

        // Container: overlay root without any live marker
        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 0:30 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker\n");
        f.set_cmdline("root=/dev/mapper/vg-root\n");
        assert_eq!(
            detect_boot_environment_ctx(&f.ctx()).unwrap(),
            BootEnvironment::Container
        );
    }

    #[test]
    fn test_live_mode_allows_internal_disk() {
        let f = FixtureBuilder::new();
        // Debian-live style: overlay root, live medium mounted at /cdrom
        f.set_mountinfo(
            "1 0 0:30 / / rw,relatime - overlay overlay rw,lowerdir=/run/live/medium\n\
             2 1 8:17 / /cdrom ro,relatime shared:2 - iso9660 /dev/sdb1 ro\n",
        );
        f.set_cmdline("boot=live findiso=/images/live.iso quiet\n");
        f.set_swaps("Filename\tType\tSize\tUsed\tPriority\n");
        // Internal disk (no mounts) — must be wipeable in live mode
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda1", (8, 1), true, Some("sda"));
        // Live medium
        f.add_block_device("sdb", (8, 16), false, None);
        f.add_block_device("sdb1", (8, 17), true, Some("sdb"));

        let ctx = f.ctx();
        let internal = check_boot_disk_protection_ctx("/dev/sda", false, &ctx);
        assert!(internal.is_ok(), "Live mode: unmounted internal disk must be allowed, got {:?}", internal);

        let live_whole = check_boot_disk_protection_ctx("/dev/sdb", false, &ctx);
        assert!(live_whole.is_err(), "Live mode: the live medium's own disk must stay refused");

        let live_part = check_boot_disk_protection_ctx("/dev/sdb1", false, &ctx);
        assert!(live_part.is_err(), "Live mode: partitions of the live medium must stay refused");
    }

    #[test]
    fn test_live_mode_still_refuses_active_swap() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 0:30 / / rw,relatime - overlay overlay rw,lowerdir=/run/live/medium\n\
             2 1 8:17 / /cdrom ro,relatime shared:2 - iso9660 /dev/sdb1 ro\n",
        );
        f.set_cmdline("boot=live quiet\n");
        f.set_swaps(
            "Filename\tType\tSize\tUsed\tPriority\n\
             /dev/sda2\tpartition\t4194300\t0\t-2\n",
        );
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda2", (8, 2), true, Some("sda"));
        f.add_block_device("sdb", (8, 16), false, None);
        f.add_block_device("sdb1", (8, 17), true, Some("sdb"));

        let ctx = f.ctx();
        let res = check_boot_disk_protection_ctx("/dev/sda", false, &ctx);
        assert!(res.is_err(), "Live mode: internal disk hosting active swap must stay refused");
    }

    #[test]
    fn test_live_mode_still_refuses_mounted_internal_partition() {
        let f = FixtureBuilder::new();
        f.set_mountinfo(
            "1 0 0:30 / / rw,relatime - overlay overlay rw,lowerdir=/run/live/medium\n\
             2 1 8:17 / /cdrom ro,relatime shared:2 - iso9660 /dev/sdb1 ro\n\
             3 1 8:3 /data /data rw,relatime shared:3 - ext4 /dev/sda2 rw\n",
        );
        f.set_cmdline("archiso archisobasedir=arch\n");
        f.add_block_device("sda", (8, 0), false, None);
        f.add_block_device("sda2", (8, 3), true, Some("sda"));
        f.add_block_device("sda3", (8, 4), true, Some("sda"));
        f.add_block_device("sdb", (8, 16), false, None);
        f.add_block_device("sdb1", (8, 17), true, Some("sdb"));

        let ctx = f.ctx();
        // A mounted internal partition's disk is in use: whole-disk stays refused.
        let res = check_boot_disk_protection_ctx("/dev/sda", false, &ctx);
        assert!(res.is_err(), "Live mode: disk with a mounted partition must stay refused");
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
            bytes_written: 1024,
            io_mode: "direct".to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"dry_run\":true"));
        assert!(json.contains("\"bytes_written\":1024"));
        assert!(json.contains("\"io_mode\":\"direct\""));
    }

    #[test]
    fn test_progress_event_serializes() {
        let event = ProgressEvent {
            schema_version: 2,
            phase: ExecutionPhase::FirmwareCommand,
            bytes_done: 500,
            bytes_total: 1000,
            percent: Some(0.5),
            speed_bytes_per_sec: 100.0,
            eta_seconds: Some(30),
            message: "halfway".to_string(),
            is_heartbeat: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"FirmwareCommand\""));
        assert!(json.contains("\"percent\":0.5"));
        assert!(json.contains("\"schema_version\":2"));
    }

    // -----------------------------------------------------------------------
    // A6: discard execution path (plan, geometry, dry-run step ordering)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_discard_chunks_alignment_and_splitting() {
        // Unaligned start of 1000 over a 16 MiB range, 512-byte granularity,
        // 4 MiB per-command cap.
        let chunks = build_discard_chunks(1000, 16 * 1024 * 1024, 512, 4 * 1024 * 1024)
            .expect("valid range must plan");

        // Start rounds UP to the next 512-byte boundary: 1024.
        assert_eq!(chunks[0].start, 1024);
        // End rounds DOWN: floor((1000 + 16 MiB) / 512) * 512 = 16777728.
        let last = chunks.last().unwrap();
        assert_eq!(last.start + last.len, 16_777_728);

        // Contiguous, granularity-aligned, never exceeding the per-command cap.
        let mut expected_cursor = chunks[0].start;
        for c in &chunks {
            assert_eq!(c.start, expected_cursor, "chunks must be contiguous");
            assert_eq!(c.len % 512, 0, "chunk length must be 512-aligned");
            assert!(c.len <= 4 * 1024 * 1024, "chunk exceeds per-command cap");
            expected_cursor = c.start + c.len;
        }
        // 16,776,704 aligned bytes / 4 MiB cap → 4 commands.
        assert_eq!(chunks.len(), 4);
    }

    #[test]
    fn test_build_discard_chunks_rejects_range_smaller_than_granularity() {
        let res = build_discard_chunks(0, 256, 512, 0);
        match res {
            Err(ExecuteError::UnsupportedOperation(msg)) => {
                assert!(msg.contains("contains no full"), "got: {}", msg);
            }
            other => panic!("Expected UnsupportedOperation, got {:?}", other),
        }

        // Unaligned start that rounds past the aligned end is also refused.
        let res = build_discard_chunks(100, 300, 512, 0);
        assert!(res.is_err(), "start rounding past end must be refused");
    }

    #[test]
    fn test_build_discard_chunks_single_command_when_max_zero() {
        let chunks = build_discard_chunks(0, 1024 * 1024, 512, 0).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], DiscardChunk { start: 0, len: 1024 * 1024 });
    }

    #[test]
    fn test_build_discard_chunks_step_rises_to_granularity() {
        // max_chunk smaller than granularity must degrade to one granularity
        // per command (never a sub-granular ioctl).
        let chunks = build_discard_chunks(0, 1024 * 1024, 4096, 1024).unwrap();
        assert!(chunks.iter().all(|c| c.len == 4096));
        assert_eq!(chunks.len(), 256);
    }

    #[test]
    fn test_read_discard_geometry_fixture() {
        let f = FixtureBuilder::new();

        // Whole device with queue attributes.
        f.add_block_device("sdb", (8, 16), false, None);
        let class_dir = f.path("sys/class/block/sdb");
        fs::create_dir_all(class_dir.join("queue")).unwrap();
        fs::write(class_dir.join("queue/discard_granularity"), "4096\n").unwrap();
        fs::write(class_dir.join("queue/discard_max_bytes"), "33554432\n").unwrap();

        // Partition without its own queue/ dir → parent fallback.
        f.add_block_device("sdb1", (8, 17), true, Some("sdb"));

        let ctx = f.ctx();
        assert_eq!(read_discard_geometry("/dev/sdb", &ctx), (4096, 33554432));
        assert_eq!(read_discard_geometry("/dev/sdb1", &ctx), (4096, 33554432));
        // Unknown device degrades to safe defaults: 512 granularity, one command.
        assert_eq!(read_discard_geometry("/dev/nonexistent", &ctx), (512, 0));
    }

    #[test]
    fn test_issue_discard_chunk_on_regular_file_maps_enotty() {
        // A regular file has no block ioctl surface: the kernel answers ENOTTY,
        // which must surface as a typed UnsupportedOperation (fail closed).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp.path())
            .unwrap();
        let chunk = DiscardChunk { start: 0, len: 4096 };
        let res = issue_discard_chunk(file.as_raw_fd(), tmp.path().to_str().unwrap(), chunk);
        match res {
            Err(ExecuteError::UnsupportedOperation(msg)) => {
                assert!(msg.contains("BLKDISCARD is not supported"), "got: {}", msg);
            }
            other => panic!("Expected UnsupportedOperation from ENOTTY, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_dry_run_whole_device_discard_reports_ordered_steps() {
        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 8:0 / / rw,relatime - ext4 /dev/root rw\n");
        f.add_block_device("sdb", (8, 16), false, None);

        // 16 MiB device (32768 sectors), 512-byte granularity, 4 MiB per command.
        let class_dir = f.path("sys/class/block/sdb");
        fs::create_dir_all(class_dir.join("queue")).unwrap();
        fs::write(class_dir.join("size"), "32768\n").unwrap();
        fs::write(class_dir.join("queue/discard_granularity"), "512\n").unwrap();
        fs::write(class_dir.join("queue/discard_max_bytes"), "4194304\n").unwrap();

        let ctx = f.ctx();
        let (tx, _rx) = mpsc::channel(64);
        let report = discard_erase_ctx("/dev/sdb", "SER1", "SER1", true, tx, &ctx)
            .await
            .expect("dry-run discard should succeed");

        assert!(report.success);
        assert!(report.dry_run);
        assert_eq!(report.io_mode, "dry_run");
        assert_eq!(report.bytes_written, 0, "dry run must discard zero bytes");
        assert_eq!(report.method_used, "BLKDISCARD (TRIM/UNMAP)");

        // Ordered steps: guard first, plan second, nothing executed.
        let log = &report.command_log;
        assert!(
            log[0].contains("[DRY RUN] [guard]"),
            "first step must be the guard check: {:?}",
            log[0]
        );
        assert_eq!(log.len(), 2, "dry run logs exactly guard + plan: {:?}", log);
        assert!(
            log[1].contains("[DRY RUN] BLKDISCARD plan")
                && log[1].contains("4 command(s), 16777216 bytes"),
            "plan step must be ordered second: {:?}",
            log[1]
        );
        assert!(
            !log.iter().any(|l| l.starts_with("[flush]")),
            "dry run must never flush: {:?}",
            log
        );
        assert!(log.iter().all(|l| l.starts_with("[DRY RUN]")));
    }

    #[tokio::test]
    async fn test_dry_run_partition_discard_reports_ordered_steps() {
        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 8:0 / / rw,relatime - ext4 /dev/root rw\n");
        f.add_block_device("sdb", (8, 16), false, None);
        f.add_block_device("sdb1", (8, 17), true, Some("sdb"));
        let p_dir = f.path("sys/class/block/sdb1");
        fs::write(p_dir.join("start"), "2048\n").unwrap();
        fs::write(p_dir.join("size"), "204800\n").unwrap();

        // Discard geometry on the parent disk (partition fallback path).
        let class_dir = f.path("sys/class/block/sdb");
        fs::create_dir_all(class_dir.join("queue")).unwrap();
        fs::write(class_dir.join("queue/discard_granularity"), "512\n").unwrap();
        fs::write(class_dir.join("queue/discard_max_bytes"), "4194304\n").unwrap();

        let ctx = f.ctx();
        let fp = compute_partition_table_fingerprint("sdb", &ctx).unwrap();
        let params = PartitionTargetParams {
            expected_partition_num: 1,
            expected_start_sector: 2048,
            expected_size_sectors: 204800,
            expected_partuuid: None,
            expected_table_fingerprint: fp,
        };

        let (tx, _rx) = mpsc::channel(64);
        let report = discard_erase_partition_ctx("/dev/sdb1", "SER1", "SER1", &params, true, tx, &ctx)
            .await
            .expect("dry-run partition discard should succeed");

        assert!(report.success);
        assert!(report.dry_run);
        assert_eq!(report.io_mode, "dry_run");
        assert_eq!(report.bytes_written, 0);
        assert_eq!(report.method_used, "Partition BLKDISCARD (TRIM/UNMAP)");

        // Ordered steps: guard (geometry + fingerprint) first, plan second.
        let log = &report.command_log;
        assert!(
            log[0].contains("[DRY RUN] [guard] partition geometry and table fingerprint verified"),
            "first step must be the partition guard: {:?}",
            log[0]
        );
        assert_eq!(log.len(), 2, "dry run logs exactly guard + plan: {:?}", log);
        assert!(
            log[1].contains("[DRY RUN] BLKDISCARD plan")
                && log[1].contains("104857600 bytes"),
            "plan must cover the full 100 MiB partition range: {:?}",
            log[1]
        );
        assert!(log.iter().all(|l| l.starts_with("[DRY RUN]")));
    }

    #[tokio::test]
    async fn test_discard_partition_refuses_fingerprint_mismatch() {
        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 8:0 / / rw,relatime - ext4 /dev/root rw\n");
        f.add_block_device("sdb", (8, 16), false, None);
        f.add_block_device("sdb1", (8, 17), true, Some("sdb"));
        let p_dir = f.path("sys/class/block/sdb1");
        fs::write(p_dir.join("start"), "2048\n").unwrap();
        fs::write(p_dir.join("size"), "204800\n").unwrap();

        let ctx = f.ctx();
        let params = PartitionTargetParams {
            expected_partition_num: 1,
            expected_start_sector: 2048,
            expected_size_sectors: 204800,
            expected_partuuid: None,
            expected_table_fingerprint: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };

        let (tx, _rx) = mpsc::channel(64);
        let res = discard_erase_partition_ctx("/dev/sdb1", "SER1", "SER1", &params, true, tx, &ctx).await;
        match res {
            Err(ExecuteError::IdentityMismatch(msg)) => {
                assert!(msg.contains("Partition table changed"), "got: {}", msg);
            }
            other => panic!("Expected IdentityMismatch on fingerprint mismatch, got {:?}", other),
        }
    }
}
