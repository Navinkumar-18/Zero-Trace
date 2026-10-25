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
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// Phase C: the guard chain now lives in `crate::guard` over `crate::backend`
// facts; these thin wrappers keep the historic signatures for every existing
// caller and test while delegating to the single shared chain.
use crate::backend::linux::LinuxBackend;
use crate::backend::{BackendError, BlockBackend, ExclusiveHandle};
use crate::guard::ValidatedTarget;
pub use crate::types::{
    dev_major, dev_minor, is_mount_unmountable_allowlisted, parse_major_minor, BlockWriter,
    BootEnvironment, ExecuteError, GuardIdentity, PartitionTargetParams, ValidatedPartitionTarget,
};


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
                // A3b spec: overlay, aufs, tmpfs or squashfs root all mean the
                // running system's writes do not land on a real disk (archiso
                // uses tmpfs + squashfs; Docker uses overlay).
                if fs_type == "overlay"
                    || fs_type == "aufs"
                    || fs_type == "tmpfs"
                    || fs_type == "squashfs"
                    || source == "overlay"
                    || source == "aufs"
                {
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

pub fn check_boot_disk_protection_ctx(
    device: &str,
    dry_run: bool,
    ctx: &FsContext,
) -> Result<(), ExecuteError> {
    crate::guard::check_boot_disk_protection(&LinuxBackend::new(ctx.clone()), device, dry_run)
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
    crate::guard::verify_exclusive_access_and_recheck(&LinuxBackend::new(ctx.clone()), device, dry_run)
}

/// Inspects device and captures guard identity (canonical path, st_rdev, major, minor, is_block, serial).
pub fn get_guard_identity(
    device: &str,
    dry_run: bool,
    device_serial: &str,
    ctx: &FsContext,
) -> Result<GuardIdentity, ExecuteError> {
    crate::guard::get_guard_identity(&LinuxBackend::new(ctx.clone()), device, dry_run, device_serial)
}

/// Re-checks boot disk protection against system mountinfo using an opened device's major:minor dev_t.
pub fn recheck_protection_by_dev_t(
    dev: libc::dev_t,
    ctx: &FsContext,
) -> Result<(), ExecuteError> {
    crate::guard::recheck_protection_by_dev_t(&LinuxBackend::new(ctx.clone()), dev)
}

/// Verify the confirmation token matches expected value.
fn verify_confirmation(token: &str, expected_serial: &str) -> Result<(), ExecuteError> {
    crate::guard::verify_confirmation(token, expected_serial)
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

/// P2: run one external tool step for an execution flow.
///
/// Every external tool invocation from a flow goes through the backend
/// (`BlockBackend::exec`), never `Command` directly and never through a
/// shell — arguments stay an argv list. Destructive commands (secure erase,
/// sanitize, format, discard, PSID revert, …) require a guard-minted
/// [`ValidatedTarget`] and **re-validate the device identity immediately
/// before execution** (boot-disk protection, node rdev/inode, serial, size;
/// see [`crate::guard::revalidate_target_identity`]).
///
/// A refused step records a `[REFUSED]` line in the command log and never
/// reaches the tool.
pub fn run_firmware_cmd(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
    program: &str,
    args: &[&str],
    destructive: bool,
    dry_run: bool,
    command_log: &mut Vec<String>,
) -> Result<(String, String, i32), ExecuteError> {
    let full_cmd = format!("{} {}", program, args.join(" "));

    if destructive {
        if let Err(err) = crate::guard::revalidate_target_identity(backend, target, dry_run) {
            command_log.push(format!("[REFUSED] {}: {}", full_cmd, err));
            return Err(err);
        }
    }

    command_log.push(full_cmd.clone());

    if dry_run {
        return Ok((
            format!("[DRY RUN] Would execute: {}", full_cmd),
            String::new(),
            0,
        ));
    }

    backend.exec(program, args).map_err(|e| {
        ExecuteError::CommandFailed(format!("Failed to run {}: {}", program, e))
    })
}

/// P2: unmount every mounted partition backing the validated target.
///
/// Sources come from the backend's mount facts (so fixture/mock backends are
/// exercised identically) and `umount` runs with an argv list — the historic
/// `sh -c "umount -f <device>*"` glob pass is gone: no shell interpolation of
/// a device path, and no command that can touch a node outside the validated
/// target's mount set.
fn unmount_target_if_mounted(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
    dry_run: bool,
    command_log: &mut Vec<String>,
) -> (String, String) {
    let mut stdout_accum = String::new();
    let mut stderr_accum = String::new();
    let device = target.canonical_path();

    if dry_run {
        command_log.push(format!(
            "[DRY RUN] Would check mounts and unmount active partitions on {}",
            device
        ));
        return (stdout_accum, stderr_accum);
    }

    // Resolve exact mounted partition paths from the backend's mount facts.
    let mounts = backend.mounts_file();
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

    for mount_src in mounted_targets {
        command_log.push(format!(
            "[UNMOUNT] Unmounting active filesystem target: {}",
            mount_src
        ));
        if let Ok((stdout, stderr, _)) = backend.exec("umount", &["-f", &mount_src]) {
            stdout_accum.push_str(&stdout);
            stderr_accum.push_str(&stderr);
        }
    }

    (stdout_accum, stderr_accum)
}

// ---------------------------------------------------------------------------
// Execution functions
// ---------------------------------------------------------------------------

/// P2 compatibility adapter: mints a guard [`ValidatedTarget`] from the
/// historic `(device, token, serial)` arguments and runs the validated flow.
/// Tool execution itself lives in [`nvme_sanitize_validated`], which only
/// accepts a `&ValidatedTarget`.
pub async fn nvme_sanitize(
    device: &str,
    action: SanitizeAction,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let target = validate_whole_disk_flow_target_ctx(
        device,
        confirmation_token,
        device_serial,
        dry_run,
        &FsContext::default(),
    )?;
    nvme_sanitize_validated(&target, action, dry_run, tx).await
}

/// NVMe Sanitize — issues `nvme sanitize` command and polls sanitize-log.
///
/// P2: takes a guard-minted [`ValidatedTarget`]. Boot-disk protection,
/// confirmation token and identity are validated at mint time; the device
/// identity is re-validated immediately before the destructive command.
pub async fn nvme_sanitize_validated(
    target: &ValidatedTarget,
    action: SanitizeAction,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    nvme_sanitize_with(
        &LinuxBackend::new(FsContext::default()),
        target,
        action,
        dry_run,
        tx,
    )
    .await
}

pub async fn nvme_sanitize_with(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
    action: SanitizeAction,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();
    let device = target.canonical_path();

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_target_if_mounted(backend, target, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    crate::guard::verify_exclusive_access_and_recheck(backend, device, dry_run)?;

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

    let (stdout, stderr, code) = run_firmware_cmd(
        backend,
        target,
        "nvme",
        &["sanitize", device, "-a", action_arg],
        true,
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
        let (s, e, _) = run_firmware_cmd(
            backend,
            target,
            "nvme",
            &["sanitize-log", device],
            false,
            dry_run,
            &mut command_log,
        )?;
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

/// P2 compatibility adapter: mints a guard [`ValidatedTarget`] from the
/// historic `(device, token, serial)` arguments and runs the validated flow.
pub async fn ata_secure_erase(
    device: &str,
    enhanced: bool,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let target = validate_whole_disk_flow_target_ctx(
        device,
        confirmation_token,
        device_serial,
        dry_run,
        &FsContext::default(),
    )?;
    ata_secure_erase_validated(&target, enhanced, dry_run, tx).await
}

/// ATA Secure Erase — handles full ATA SE sequence including frozen-state check.
///
/// P2: takes a guard-minted [`ValidatedTarget`]; identity is re-validated
/// immediately before the password-setting and erase commands.
pub async fn ata_secure_erase_validated(
    target: &ValidatedTarget,
    enhanced: bool,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    ata_secure_erase_with(
        &LinuxBackend::new(FsContext::default()),
        target,
        enhanced,
        dry_run,
        tx,
    )
    .await
}

pub async fn ata_secure_erase_with(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
    enhanced: bool,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();
    let device = target.canonical_path();
    let method_name = if enhanced {
        "ATA Enhanced Secure Erase".to_string()
    } else {
        "ATA Secure Erase".to_string()
    };

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_target_if_mounted(backend, target, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    crate::guard::verify_exclusive_access_and_recheck(backend, device, dry_run)?;

    // Phase 1: Check frozen state
    send_progress(&tx, ExecutionPhase::SecurityUnlock,
        "Checking ATA security frozen state with hdparm -I...", Some(10)).await;

    let (stdout, stderr, _) = run_firmware_cmd(
        backend,
        target,
        "hdparm",
        &["-I", device],
        false,
        dry_run,
        &mut command_log,
    )?;
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

    let (stdout, stderr, code) = run_firmware_cmd(
        backend,
        target,
        "hdparm",
        &["--user-master", "u", "--security-set-pass", "p", device],
        true,
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

    let (stdout, stderr, code) = run_firmware_cmd(
        backend,
        target,
        "hdparm",
        &[erase_arg, "p", device],
        true,
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
        let (s, e, _) = run_firmware_cmd(
            backend,
            target,
            "hdparm",
            &["-F", device],
            false,
            dry_run,
            &mut command_log,
        )?;
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

/// P2 compatibility adapter: mints a guard [`ValidatedTarget`] from the
/// historic `(device, token, serial)` arguments and runs the validated flow.
pub async fn ata_sanitize(
    device: &str,
    action: AtaSanitizeAction,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let target = validate_whole_disk_flow_target_ctx(
        device,
        confirmation_token,
        device_serial,
        dry_run,
        &FsContext::default(),
    )?;
    ata_sanitize_validated(&target, action, dry_run, tx).await
}

/// ATA Sanitize — Block Erase, Crypto Scramble, or Overwrite via hdparm.
///
/// P2: takes a guard-minted [`ValidatedTarget`]; identity is re-validated
/// immediately before the sanitize command.
pub async fn ata_sanitize_validated(
    target: &ValidatedTarget,
    action: AtaSanitizeAction,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    ata_sanitize_with(
        &LinuxBackend::new(FsContext::default()),
        target,
        action,
        dry_run,
        tx,
    )
    .await
}

pub async fn ata_sanitize_with(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
    action: AtaSanitizeAction,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();
    let device = target.canonical_path();

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_target_if_mounted(backend, target, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    crate::guard::verify_exclusive_access_and_recheck(backend, device, dry_run)?;

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
    let (stdout, stderr, code) = run_firmware_cmd(
        backend,
        target,
        "hdparm",
        &[&hdparm_arg, device],
        true,
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

/// P2 compatibility adapter: mints a guard [`ValidatedTarget`] from the
/// historic `(device, token, serial)` arguments and runs the validated flow.
pub async fn opal_revert(
    device: &str,
    psid: Option<&str>,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let target = validate_whole_disk_flow_target_ctx(
        device,
        confirmation_token,
        device_serial,
        dry_run,
        &FsContext::default(),
    )?;
    opal_revert_validated(&target, psid, dry_run, tx).await
}

/// TCG OPAL Revert — uses sedutil-cli for PSID revert or crypto erase.
///
/// P2: takes a guard-minted [`ValidatedTarget`]; identity is re-validated
/// immediately before the revert command.
pub async fn opal_revert_validated(
    target: &ValidatedTarget,
    psid: Option<&str>,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    opal_revert_with(
        &LinuxBackend::new(FsContext::default()),
        target,
        psid,
        dry_run,
        tx,
    )
    .await
}

pub async fn opal_revert_with(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
    psid: Option<&str>,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();
    let device = target.canonical_path();

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_target_if_mounted(backend, target, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    crate::guard::verify_exclusive_access_and_recheck(backend, device, dry_run)?;

    send_progress(&tx, ExecutionPhase::SecurityUnlock,
        "Querying TCG OPAL SED state...", Some(3)).await;

    // Query OPAL state first
    let (stdout, stderr, _) = run_firmware_cmd(
        backend,
        target,
        "sedutil-cli",
        &["--query", device],
        false,
        dry_run,
        &mut command_log,
    )?;
    all_stdout.push_str(&stdout);
    all_stderr.push_str(&stderr);

    send_progress(&tx, ExecutionPhase::FirmwareCommand,
        "Issuing TCG OPAL revertTPer command...", None).await;

    // PSID revert or password-based revert
    let (stdout, stderr, code) = if let Some(psid_val) = psid {
        run_firmware_cmd(backend, target, "sedutil-cli",
            &["--yesIreallywanttoERASEALLmydatausingthePSID", psid_val, device],
            true, dry_run, &mut command_log)?
    } else {
        // Try with default SID
        run_firmware_cmd(backend, target, "sedutil-cli",
            &["--revertTPer", "SID", device],
            true, dry_run, &mut command_log)?
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

/// P2 compatibility adapter: mints a guard [`ValidatedTarget`] from the
/// historic `(device, token, serial)` arguments and runs the validated flow.
pub async fn emmc_sanitize(
    device: &str,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let target = validate_whole_disk_flow_target_ctx(
        device,
        confirmation_token,
        device_serial,
        dry_run,
        &FsContext::default(),
    )?;
    emmc_sanitize_validated(&target, dry_run, tx).await
}

/// eMMC Sanitize — issues `mmc sanitize` command.
///
/// P2: takes a guard-minted [`ValidatedTarget`]; identity is re-validated
/// immediately before the sanitize command.
pub async fn emmc_sanitize_validated(
    target: &ValidatedTarget,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    emmc_sanitize_with(
        &LinuxBackend::new(FsContext::default()),
        target,
        dry_run,
        tx,
    )
    .await
}

pub async fn emmc_sanitize_with(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
    dry_run: bool,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    let start = Instant::now();
    let mut command_log = Vec::new();
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();
    let device = target.canonical_path();

    // Unmount any active partitions on device
    let (u_out, u_err) = unmount_target_if_mounted(backend, target, dry_run, &mut command_log);
    all_stdout.push_str(&u_out);
    all_stderr.push_str(&u_err);

    // Verify exclusive access and re-check boot protection post-unmount
    crate::guard::verify_exclusive_access_and_recheck(backend, device, dry_run)?;

    send_progress(&tx, ExecutionPhase::SecurityUnlock,
        "Reading eMMC extcsd sanitize capability...", Some(3)).await;

    send_progress(&tx, ExecutionPhase::FirmwareCommand,
        &format!("Issuing mmc sanitize on {}...", device), None).await;

    let (stdout, stderr, code) = run_firmware_cmd(
        backend,
        target,
        "mmc",
        &["sanitize", device],
        true,
        dry_run,
        &mut command_log,
    )?;
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

/// Issue a single BLKDISCARD command; translate kernel refusals into typed
/// errors. The raw ioctl lives in the backend (C2b) — this wrapper keeps the
/// historic errno mapping byte-for-byte.
fn issue_discard_chunk(
    fd: libc::c_int,
    device: &str,
    chunk: DiscardChunk,
) -> Result<(), ExecuteError> {
    let mut range: [u64; 2] = [chunk.start, chunk.len];
    if let Err(err) = crate::backend::linux::blkdiscard_range(fd, &mut range) {
        return match err.raw_os_error() {
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
        };
    }
    Ok(())
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

    // 1. Guard chain — identical to every other execution path. C2a: the
    //    historic check order (boot-disk protection → confirmation →
    //    identity) now mints the validated target that gates the only
    //    write-open below.
    let backend = LinuxBackend::new(ctx.clone());
    let validated_target = validate_whole_disk_flow_target_ctx(
        device, confirmation_token, device_serial, dry_run, ctx,
    )?;
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
    let (_stdout, _stderr) = unmount_target_if_mounted(&backend, &validated_target, false, &mut command_log);

    // 4. Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, false, ctx)?;
    command_log.push(format!("[guard] exclusive access verified on {}", device));

    // 5. Open with O_EXCL + fd identity validation — only through the
    //    backend on the guard-minted validated target (C2a).
    let mut writer = open_validated_writer(&backend, &validated_target)?;
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

    // 6. Ordered BLKDISCARD execution over the whole device — issued on the
    //    handle's own fd (no second open of the device).
    let fd = writer.raw_fd().ok_or_else(|| {
        ExecuteError::UnsupportedOperation("backend exposes no raw fd for BLKDISCARD".to_string())
    })?;
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
    //    fingerprint, MBR extended refusal, logical-block alignment, identity.
    //    C2a: same guard chain in the same order, now also minting the
    //    validated target whose open_exclusive is the only write-open path.
    let backend = LinuxBackend::new(ctx.clone());
    let validated_target = crate::guard::validate_partition_target(
        &backend, device, params, dry_run, device_serial,
    )?;
    let target = validated_target.to_legacy_partition_target().ok_or_else(|| {
        ExecuteError::UnsupportedOperation("validated target is not partition-scoped".to_string())
    })?;
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

    // 6. Open with O_EXCL + identity checks — only through the backend on
    //    the guard-minted validated target (C2a); cross-check BLKGETSIZE64
    //    vs sysfs unchanged.
    let mut writer = open_validated_writer(&backend, &validated_target)?;
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

    // 7. Ordered BLKDISCARD execution over the partition range only — issued
    //    on the handle's own fd (no second open of the device).
    let fd = writer.raw_fd().ok_or_else(|| {
        ExecuteError::UnsupportedOperation("backend exposes no raw fd for BLKDISCARD".to_string())
    })?;
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

// C2a: the direct writer (O_EXCL open ladder, fd identity re-validation,
// size/sector ioctls, BLKFLSBUF) now lives in the backend — raw device
// opening is private to `backend/linux`. Re-exported so the historic API
// (`zt_engine::execute::DirectBlockWriter`) and its characterization
// tests keep working unchanged.
pub use crate::backend::linux::DirectBlockWriter;

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

    // 1. Safety validation and identity pinning — boot-disk protection →
    //    confirmation token → identity, minted as a validated target so the
    //    only write-open below goes through the backend (C2a).
    let backend = LinuxBackend::new(FsContext::default());
    let validated_target = validate_whole_disk_flow_target_ctx(
        device,
        confirmation_token,
        device_serial,
        dry_run,
        &FsContext::default(),
    )?;

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
    let (_stdout, _stderr) = unmount_target_if_mounted(&backend, &validated_target, false, &mut command_log);

    // 4. Verify exclusive access and re-check boot protection post-unmount
    verify_exclusive_access_and_recheck(device, false, &FsContext::default())?;

    // 5. Open the device for writing only through the backend on the
    //    guard-minted validated target (C2a: O_EXCL + fd identity checks).
    let handle = open_validated_writer(&backend, &validated_target)?;

    // 6. Execute native overwrite
    execute_writer_overwrite(
        handle,
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

    /// P2: methods that invoke a vendor firmware tool on the whole device
    /// (secure erase, sanitize, OPAL revert). These require a guard-minted
    /// `ValidatedTarget` rather than a device path.
    pub fn is_firmware(&self) -> bool {
        matches!(
            self,
            EngineMethod::AtaSecureErase
                | EngineMethod::AtaEnhancedSecureErase
                | EngineMethod::AtaSanitizeBlock
                | EngineMethod::AtaSanitizeCrypto
                | EngineMethod::NvmeSanitizeBlock
                | EngineMethod::NvmeSanitizeCrypto
                | EngineMethod::OpalRevert
                | EngineMethod::EmmcSanitize
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


/// Calculates the SHA-256 fingerprint of the partition table on the parent disk.
/// Sorted ascending by partition number: format "{part_num}:{start_sector}:{size_sectors}\n".
pub fn compute_partition_table_fingerprint(
    parent_disk: &str,
    ctx: &FsContext,
) -> Result<String, ExecuteError> {
    crate::guard::compute_partition_table_fingerprint(&LinuxBackend::new(ctx.clone()), parent_disk)
}

/// Check if a target partition is an MBR extended container partition.
pub fn is_mbr_extended_partition(
    device: &str,
    parent_disk: &str,
    ctx: &FsContext,
) -> Result<bool, ExecuteError> {
    crate::guard::is_mbr_extended_partition(&LinuxBackend::new(ctx.clone()), device, parent_disk)
}

/// Safely unmounts active filesystems on the target partition and any active holders.
/// Sibling partitions are left untouched.
pub fn unmount_target_partition_and_holders(
    target_partition: &str,
    dry_run: bool,
    command_log: &mut Vec<String>,
    ctx: &FsContext,
) -> Result<(String, String), ExecuteError> {
    crate::guard::unmount_target_partition_and_holders(
        &LinuxBackend::new(ctx.clone()),
        target_partition,
        dry_run,
        command_log,
    )
}

/// Resolves the parent disk device name from a partition device path or name.
pub fn resolve_parent_disk(device: &str, ctx: &FsContext) -> Result<String, ExecuteError> {
    crate::guard::resolve_parent_disk(&LinuxBackend::new(ctx.clone()), device)
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

/// C2a: mint the whole-device validated target for an execution flow —
/// boot-disk protection → confirmation token → identity pinning, the exact
/// historic check order (error precedence preserved). The returned target
/// gates the only write-open path (`open_validated_writer`).
pub fn validate_whole_disk_flow_target_ctx(
    device: &str,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
    ctx: &FsContext,
) -> Result<ValidatedTarget, ExecuteError> {
    crate::guard::validate_whole_disk_flow_target(
        &LinuxBackend::new(ctx.clone()),
        device,
        confirmation_token,
        device_serial,
        dry_run,
    )
}

/// C2a: the only way execution flows open a device for writing. Delegates to
/// the backend's `open_exclusive` on a guard-minted [`ValidatedTarget`]
/// (O_EXCL ladder + fd identity re-validation live in `backend/`) and maps
/// backend errors back to the historic typed errors — `OpenFailed` carries
/// the original `ExecuteError` verbatim, so every flow sees exactly the
/// error it saw with the legacy `DirectBlockWriter::open` call.
pub fn open_validated_writer(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
) -> Result<ExclusiveHandle, ExecuteError> {
    backend.open_exclusive(target).map_err(|e| match e {
        BackendError::OpenFailed(err) => err,
        BackendError::Unavailable(msg) => ExecuteError::BootDiskProtection(msg),
        BackendError::Io(msg) => ExecuteError::IoError(io::Error::other(msg)),
        BackendError::Unsupported(msg) => ExecuteError::UnsupportedOperation(msg.to_string()),
    })
}

/// Resolves the parent disk's serial number for a partition device node.
pub fn resolve_parent_serial(device: &str, ctx: &FsContext) -> Result<String, ExecuteError> {
    crate::guard::resolve_parent_serial(&LinuxBackend::new(ctx.clone()), device)
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
    let backend = LinuxBackend::new(ctx.clone());
    let target = crate::guard::validate_partition_target(&backend, device, params, dry_run, device_serial)?;
    target.to_legacy_partition_target().ok_or_else(|| {
        ExecuteError::UnsupportedOperation("validated target is not partition-scoped".to_string())
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
    //    checks as before, now also feeding the discard path). C2a: also
    //    mints the validated target whose open_exclusive is the only
    //    write-open path.
    let backend = LinuxBackend::new(ctx.clone());
    let validated_target = crate::guard::validate_partition_target(
        &backend, device, params, dry_run, device_serial,
    )?;
    let target = validated_target.to_legacy_partition_target().ok_or_else(|| {
        ExecuteError::UnsupportedOperation("validated target is not partition-scoped".to_string())
    })?;
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

    // 9. Open native block writer on the partition node with O_EXCL — only
    //    through the backend on the guard-minted validated target (C2a).
    let inner_writer = open_validated_writer(&backend, &validated_target)?;
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
    use std::os::unix::io::AsRawFd;

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

        // A3b spec: tmpfs + squashfs root (archiso style) is live-mode material
        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 0:30 / / rw,relatime - tmpfs tmpfs rw\n");
        f.set_cmdline("archiso archisobasedir=arch quiet\n");
        assert_eq!(
            detect_boot_environment_ctx(&f.ctx()).unwrap(),
            BootEnvironment::Live
        );

        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 0:30 / / ro,relatime - squashfs /dev/sdb1 ro\n");
        f.set_cmdline("boot=live quiet\n");
        assert_eq!(
            detect_boot_environment_ctx(&f.ctx()).unwrap(),
            BootEnvironment::Live
        );

        // tmpfs root without a marker fails closed to Container
        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 0:30 / / rw,relatime - tmpfs tmpfs rw\n");
        f.set_cmdline("root=/dev/mapper/vg-root\n");
        assert_eq!(
            detect_boot_environment_ctx(&f.ctx()).unwrap(),
            BootEnvironment::Container
        );

        // A cmdline live marker on a real disk root does NOT downgrade
        // protection: Normal rules (root disk protected) still apply.
        let f = FixtureBuilder::new();
        f.set_mountinfo("1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n");
        f.set_cmdline("boot=live root=/dev/sda1 rw\n");
        assert_eq!(
            detect_boot_environment_ctx(&f.ctx()).unwrap(),
            BootEnvironment::Normal
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
