//! C2: the SHARED guard chain.
//!
//! Every safety decision the engine makes before a destructive write lives
//! here, in platform-neutral code operating **only on `BlockBackend`
//! facts**:
//!
//! * boot-disk / protected-mount / active-swap protection
//! * live / normal / container boot-environment rules (A3b)
//! * typed confirmation-token verification (A5)
//! * partition geometry, PARTUUID and partition-table fingerprint checks
//! * MBR extended-container refusal, logical-block alignment
//! * holder/slave graph traversal and targeted unmounting
//!
//! The chain mints [`ValidatedTarget`] — the ONLY way to obtain an
//! `ExclusiveHandle` from a backend, so a backend can never write without
//! passing through this chain (compile-time enforced; see the
//! `compile_fail` proof on [`ValidatedTarget`]).
//!
//! The bodies were moved verbatim from `execute.rs` (which keeps thin
//! `FsContext` wrappers with identical signatures); error strings and
//! decision order are unchanged — the C0 goldens and the full test suite
//! pin that.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::backend::{BackendError, BlockBackend, Relation};
use crate::types::{
    dev_major, dev_minor, is_mount_unmountable_allowlisted, parse_major_minor, BootEnvironment,
    ExecuteError, GuardIdentity, PartitionTargetParams, ValidatedPartitionTarget,
};

// ---------------------------------------------------------------------------
// ValidatedTarget (C2): the compile-time write gate
// ---------------------------------------------------------------------------

/// Scope of a validated target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetScope {
    /// Whole-disk wipe: the entire device including its partition table.
    WholeDisk,
    /// Partition-scoped wipe: only this range; the partition table and
    /// sibling partitions are out of bounds for the handle.
    Partition {
        parent_name: String,
        partition_number: u32,
        start_bytes: u64,
        size_bytes: u64,
        logical_block_size: u64,
    },
}

impl TargetScope {
    /// Byte range `start..end` of a partition scope on the parent device
    /// (None = whole disk).
    pub fn partition_range(&self) -> Option<(u64, u64)> {
        match self {
            TargetScope::WholeDisk => None,
            TargetScope::Partition {
                start_bytes,
                size_bytes,
                ..
            } => Some((*start_bytes, start_bytes.saturating_add(*size_bytes))),
        }
    }
}

/// A target that has passed the full guard chain: confirmation token, boot
/// disk protection, boot-environment rules, geometry/fingerprint checks and
/// the pinned guard identity.
///
/// **Only this module can construct one** (private fields + private sealed
/// constructor). `BlockBackend::open_exclusive` accepts only this type, so
/// code outside the guard chain cannot open a write handle — bypassing the
/// guard fails at compile time:
///
/// ```compile_fail
/// // C2 proof: no path to a write handle without the guard chain.
/// use zt_engine::backend::BlockBackend;
/// use zt_engine::guard::ValidatedTarget;
///
/// fn smuggle_target<B: BlockBackend>(backend: &B) {
///     let forged = ValidatedTarget {
///         canonical_path: "/dev/sda".to_string(), // private field
///         guard_identity: todo!(),
///         scope: todo!(),
///     };
///     let _handle = backend.open_exclusive(&forged); // never reachable
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ValidatedTarget {
    canonical_path: String,
    guard_identity: GuardIdentity,
    scope: TargetScope,
}

impl ValidatedTarget {
    /// Sealed constructor — private to this module (the guard chain).
    fn sealed(canonical_path: String, guard_identity: GuardIdentity, scope: TargetScope) -> Self {
        Self { canonical_path, guard_identity, scope }
    }

    pub fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    pub fn guard_identity(&self) -> &GuardIdentity {
        &self.guard_identity
    }

    pub fn scope(&self) -> &TargetScope {
        &self.scope
    }

    pub fn device_serial(&self) -> &str {
        &self.guard_identity.device_serial
    }
}

// ---------------------------------------------------------------------------
// Mount/swap protection state (facts + shared policy result)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct MountProtectionState {
    protected_devs: HashMap<(u32, u32), String>,
    protected_names: HashSet<String>,
    has_root_mount: bool,
}

/// Build the protection state from backend facts (mountinfo/swaps content,
/// canonicalization, sysfs numbers, btrfs membership). Policy — what counts
/// as protected and every fail-closed rule — lives here, shared.
///
/// `boot_env` matters for A3b: in `Live` mode the overlay root itself has no
/// backing block device and must not trip the anonymous-device fail-closed
/// check; the live medium's own mounts (e.g. /run/live/medium, /cdrom) are
/// still recorded as protected via the normal non-allowlisted-mount path.
/// C2c: scan-read errors are **fail-closed** — an exists-but-unreadable sysfs
/// or proc read blocks the wipe (typed `BootDiskProtection`) instead of
/// being skipped as if the state were absent. Absent state (`Ok(None)`,
/// absent dirs) keeps its historic permissive semantics.
fn scan_read_err(e: BackendError) -> ExecuteError {
    match e {
        BackendError::Unavailable(msg) => ExecuteError::BootDiskProtection(msg),
        other => ExecuteError::BootDiskProtection(other.to_string()),
    }
}

/// Resolved mount/swap source: `(name, sysfs major:minor when known)`.
/// `Ok(None)` = the source does not canonicalize (historic skip: absence).
type ResolvedSource = Option<(String, Option<(u32, u32)>)>;

fn scan_mount_and_swap_protection(
    backend: &dyn BlockBackend,
    dry_run: bool,
    boot_env: BootEnvironment,
) -> Result<MountProtectionState, ExecuteError> {
    // 2. Mountinfo content (backend resolves self/mountinfo → mountinfo →
    //    mounts and fail-closes when none exist; C2c: read *errors* also
    //    fail closed here).
    let state = backend.read_mount_state().map_err(scan_read_err)?;
    let mountinfo_content = state.mountinfo;

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

    // Resolve a /dev mount/swap source: canonicalize → name (recorded even
    // when the sysfs dev number is absent — historic inline order), with the
    // parsed (major, minor) when available. C2c: an exists-but-unreadable
    // sysfs dev file fails closed; a source that does not canonicalize keeps
    // its historic skip (absence, not an error).
    let resolve_source = |source: &str| -> Result<ResolvedSource, ExecuteError> {
        let Some(canon) = backend.canonicalize_path(source, dry_run).ok() else {
            return Ok(None);
        };
        let name = canon.rsplit('/').next().unwrap_or(&canon).to_string();
        let dev_attr = backend.sysfs_class_attr(&name, "dev").map_err(scan_read_err)?;
        let mm = dev_attr.and_then(|c| parse_major_minor(&c));
        Ok(Some((name, mm)))
    };

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
                    for d_name in backend.btrfs_member_devices().map_err(scan_read_err)? {
                        protected_names.insert(d_name.clone());
                        let dev_attr = backend
                            .sysfs_class_attr(&d_name, "dev")
                            .map_err(scan_read_err)?;
                        if let Some(dev_mm) = dev_attr.and_then(|c| parse_major_minor(&c)) {
                            protected_devs.insert(
                                dev_mm,
                                format!("btrfs device '{}' for protected mount '{}'", d_name, mount_point),
                            );
                            btrfs_resolved = true;
                        }
                    }
                    if mount_source.starts_with("/dev/") {
                        let src_name = mount_source.rsplit('/').next().unwrap_or(mount_source);
                        protected_names.insert(src_name.to_string());
                        let src_attr = backend
                            .sysfs_class_attr(src_name, "dev")
                            .map_err(scan_read_err)?;
                        if let Some(dev_mm) = src_attr.and_then(|c| parse_major_minor(&c)) {
                            protected_devs.insert(
                                dev_mm,
                                format!("btrfs source '{}' for protected mount '{}'", src_name, mount_point),
                            );
                            btrfs_resolved = true;
                        }
                    }

                    if !btrfs_resolved {
                        return Err(ExecuteError::BootDiskProtection(format!(
                            "Btrfs protected mount '{}' has unresolvable backing device(s): refusing destructive operation (fail closed)",
                            mount_point
                        )));
                    }
                } else if mount_source.starts_with("/dev/") {
                    if let Some((src_name, src_mm)) = resolve_source(mount_source)? {
                        protected_names.insert(src_name);
                        if let Some(mm) = src_mm {
                            protected_devs.insert(
                                mm,
                                format!("mount source '{}' for protected mount '{}'", mount_source, mount_point),
                            );
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
                if let Some((src_name, src_mm)) = resolve_source(mount_source)? {
                    protected_names.insert(src_name);
                    if let Some(mm) = src_mm {
                        protected_devs.insert(
                            mm,
                            format!("mount source '{}' for protected mount '{}'", mount_source, mount_point),
                        );
                    }
                }
            }
        }
    }

    // 3. Swaps content
    for line in state.swaps.lines().skip(1) {
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
            if let Some((swap_name, mm)) = resolve_source(swap_target)? {
                protected_names.insert(swap_name);
                if let Some(mm) = mm {
                    protected_devs.insert(mm, format!("active swap partition '{}'", swap_target));
                }
            }
        } else if swap_type == "file" {
            let mut swap_resolved = false;
            if let Some(dev) = backend.stat_backing_device(swap_target) {
                let mm = dev;
                protected_devs.insert(mm, format!("backing device for active swap file '{}'", swap_target));
                swap_resolved = true;
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

    Ok(MountProtectionState {
        protected_devs,
        protected_names,
        has_root_mount,
    })
}

// ---------------------------------------------------------------------------
// Boot-disk protection (C2 core)
// ---------------------------------------------------------------------------

/// The shared boot-disk protection chain. Facts come from the backend; every
/// decision (protection set, family traversal, fail-closed rules) is here.
pub fn check_boot_disk_protection(
    backend: &dyn BlockBackend,
    device: &str,
    dry_run: bool,
) -> Result<(), ExecuteError> {
    // 1. Canonicalize the target path
    let canonical = backend.canonicalize_path(device, dry_run)?;
    let target_name = canonical
        .rsplit('/')
        .next()
        .unwrap_or(&canonical)
        .to_string();

    // A3b: classify the boot environment before applying mount rules.
    let boot_env = backend.boot_environment()?;
    if boot_env == BootEnvironment::Container {
        return Err(ExecuteError::BootDiskProtection(
            "Container or overlayfs root environment detected: refusing destructive operation (fail closed)".to_string(),
        ));
    }

    let state = scan_mount_and_swap_protection(backend, dry_run, boot_env)?;
    if !state.has_root_mount {
        return Err(ExecuteError::BootDiskProtection(
            "Invalid mount environment: no root '/' mount point found in mountinfo".to_string(),
        ));
    }
    let protected_devs = state.protected_devs;
    let protected_names = state.protected_names;

    // 4. Resolve target in sysfs
    if !backend.sysfs_block_exists(&target_name) {
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
                Path::new(&backend.sysfs_root_display())
                    .join("class/block")
                    .join(&target_name)
                    .display()
            )));
        }
    }

    // 5. Gather physical/partition family of target
    let mut family_devices: HashSet<String> = HashSet::new();
    family_devices.insert(target_name.clone());

    let is_partition = backend.sysfs_is_partition(&target_name);

    if is_partition {
        let mut parent_disk_opt: Option<String> = None;
        if let Some(p_str) = backend.sysfs_parent_link(&target_name) {
            if p_str != "block" && backend.sysfs_block_exists(&p_str) {
                parent_disk_opt = Some(p_str);
            }
        }
        if parent_disk_opt.is_none() {
            if target_name.starts_with("nvme") || target_name.starts_with("mmcblk") {
                if let Some(idx) = target_name.rfind('p') {
                    let candidate = &target_name[..idx];
                    if backend.sysfs_block_exists(candidate) {
                        parent_disk_opt = Some(candidate.to_string());
                    }
                }
            } else {
                let candidate = target_name.trim_end_matches(|c: char| c.is_ascii_digit());
                if !candidate.is_empty() && backend.sysfs_block_exists(candidate) {
                    parent_disk_opt = Some(candidate.to_string());
                }
            }
        }

        if let Some(parent_disk) = parent_disk_opt {
            family_devices.insert(parent_disk.clone());
            for dev in backend.sysfs_block_names() {
                if backend.sysfs_is_partition(&dev)
                    && dev.starts_with(&parent_disk)
                    && (dev[parent_disk.len()..].starts_with('p')
                        || dev[parent_disk.len()..].chars().next().is_some_and(|c| c.is_ascii_digit()))
                {
                    family_devices.insert(dev);
                }
            }
        }
    } else {
        for dev in backend.sysfs_block_names() {
            if backend.sysfs_is_partition(&dev)
                && dev.starts_with(&target_name)
                && (dev[target_name.len()..].starts_with('p')
                    || dev[target_name.len()..].chars().next().is_some_and(|c| c.is_ascii_digit()))
            {
                family_devices.insert(dev);
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

        // C2c: an unreadable holders/slaves dir fails closed — the wipe is
        // blocked rather than the relation being skipped as empty.
        for name in backend
            .sysfs_related_names(&curr, Relation::Holders)
            .map_err(scan_read_err)?
        {
            if !visited.contains(&name) {
                queue.push_back(name);
            }
        }
        for name in backend
            .sysfs_related_names(&curr, Relation::Slaves)
            .map_err(scan_read_err)?
        {
            if !visited.contains(&name) {
                queue.push_back(name);
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

        // Fail closed when the sysfs dev file exists but cannot be read —
        // same refusal as the historic inline read (exact message).
        let dev_attr = backend.sysfs_class_attr(dev, "dev").map_err(|e| match e {
            BackendError::Io(msg) => ExecuteError::BootDiskProtection(format!(
                "Cannot read sysfs dev file for {}: {}", dev, msg
            )),
            other => ExecuteError::BootDiskProtection(other.to_string()),
        })?;
        if let Some(content) = dev_attr {
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

/// O_EXCL probe + immediate re-check (the pre-command revalidation).
pub fn verify_exclusive_access_and_recheck(
    backend: &dyn BlockBackend,
    device: &str,
    dry_run: bool,
) -> Result<(), ExecuteError> {
    if dry_run {
        return check_boot_disk_protection(backend, device, true);
    }

    let canonical = backend.canonicalize_path(device, false)?;
    backend.probe_exclusive_open(&canonical, device)?;

    check_boot_disk_protection(backend, device, false)
}

/// Guard identity of a device (canonical path, rdev, ino, ...).
pub fn get_guard_identity(
    backend: &dyn BlockBackend,
    device: &str,
    dry_run: bool,
    device_serial: &str,
) -> Result<GuardIdentity, ExecuteError> {
    let canonical = backend.canonicalize_path(device, dry_run)?;
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

    let stat = backend.stat_path(&canonical).map_err(|e| {
        // Historic message embeds the raw io::Error display.
        let detail = match &e {
            BackendError::Io(msg) => msg.clone(),
            other => other.to_string(),
        };
        ExecuteError::DeviceNotFound(format!("Cannot stat {}: {}", canonical, detail))
    })?;
    if !stat.is_block && !stat.is_regular {
        return Err(ExecuteError::UnsupportedOperation(format!(
            "Device {} is neither a block device nor a regular file",
            device
        )));
    }

    Ok(GuardIdentity {
        canonical_path: canonical,
        st_rdev: stat.rdev as libc::dev_t,
        major: dev_major(stat.rdev),
        minor: dev_minor(stat.rdev),
        is_block: stat.is_block,
        device_serial: device_serial.to_string(),
        st_ino: stat.ino,
    })
}

/// Re-checks boot disk protection against `self/mountinfo` using an opened
/// device's major:minor dev_t. Only self/mountinfo counts here (no
/// fallback chain) — matches the historic pre-write recheck exactly.
pub fn recheck_protection_by_dev_t(
    backend: &dyn BlockBackend,
    dev: u64,
) -> Result<(), ExecuteError> {
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    let Some(content) = backend.mountinfo_self().map_err(|e| match e {
        BackendError::Unavailable(msg) => ExecuteError::BootDiskProtection(msg),
        other => ExecuteError::BootDiskProtection(other.to_string()),
    })? else {
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

/// Verify the confirmation token matches expected value (A5 typed gate).
pub fn verify_confirmation(token: &str, expected_serial: &str) -> Result<(), ExecuteError> {
    if token.trim() != expected_serial.trim() {
        return Err(ExecuteError::ConfirmationMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Partition-scoped facts & validation (C2)
// ---------------------------------------------------------------------------

/// Calculates the SHA-256 fingerprint of the partition table on the parent
/// disk from sysfs facts. Sorted ascending by partition number:
/// format "{part_num}:{start_sector}:{size_sectors}\n".
pub fn compute_partition_table_fingerprint(
    backend: &dyn BlockBackend,
    parent_disk: &str,
) -> Result<String, ExecuteError> {
    let parent_name = parent_disk.strip_prefix("/dev/").unwrap_or(parent_disk);
    let mut parts: Vec<(u32, u64, u64)> = Vec::new();

    for name in backend.sysfs_block_names() {
        if name.starts_with(parent_name)
            && (name[parent_name.len()..].starts_with('p')
                || name[parent_name.len()..].chars().next().is_some_and(|c| c.is_ascii_digit()))
        {
            // `partition` present (Ok(Some)|Err) gates on existence like the
            // historic `part_file.exists()`; read failures degrade to ""
            // (entry skipped / parse error) exactly like `unwrap_or_default`.
            let part_attr = backend.sysfs_class_attr(&name, "partition");
            if !matches!(part_attr, Ok(None)) {
                let num_str = part_attr.unwrap_or_default().unwrap_or_default();
                if let Ok(num) = num_str.trim().parse::<u32>() {
                    let start_str = backend
                        .sysfs_class_attr(&name, "start")
                        .unwrap_or_default()
                        .unwrap_or_default();
                    let size_str = backend
                        .sysfs_class_attr(&name, "size")
                        .unwrap_or_default()
                        .unwrap_or_default();
                    let start = start_str.trim().parse::<u64>().unwrap_or(0);
                    let size = size_str.trim().parse::<u64>().unwrap_or(0);
                    parts.push((num, start, size));
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
    backend: &dyn BlockBackend,
    device: &str,
    parent_disk: &str,
) -> Result<bool, ExecuteError> {
    let part_name = device.strip_prefix("/dev/").unwrap_or(device);

    if !matches!(backend.sysfs_class_attr(part_name, "subpartition"), Ok(None)) {
        return Ok(true);
    }

    let parent_canonical = backend.canonicalize_path(parent_disk, false).unwrap_or_else(|_| parent_disk.to_string());
    let parent_path = backend.device_file_path(parent_disk, &parent_canonical);

    if let Ok(mbr) = backend.read_raw(&parent_path.to_string_lossy(), 0, 512) {
        if mbr.len() == 512 && mbr[510] == 0x55 && mbr[511] == 0xAA {
            let start_str = backend
                .sysfs_class_attr(part_name, "start")
                .unwrap_or_default()
                .unwrap_or_default();
            let target_start = start_str.trim().parse::<u32>().unwrap_or(0);
            let part_num_str = backend
                .sysfs_class_attr(part_name, "partition")
                .unwrap_or_default()
                .unwrap_or_default();
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

/// Safely unmounts active filesystems on the target partition and any active
/// holders. Sibling partitions are left untouched.
pub fn unmount_target_partition_and_holders(
    backend: &dyn BlockBackend,
    target_partition: &str,
    dry_run: bool,
    command_log: &mut Vec<String>,
) -> Result<(String, String), ExecuteError> {
    let mut stdout_accum = String::new();
    let mut stderr_accum = String::new();

    if dry_run {
        command_log.push(format!("[DRY RUN] Would check mounts and unmount partition {} and its holders", target_partition));
        return Ok((stdout_accum, stderr_accum));
    }

    let target_name = target_partition.strip_prefix("/dev/").unwrap_or(target_partition);
    let target_canonical = backend.canonicalize_path(target_partition, dry_run)?;

    // 1. Resolve holders
    // C2c: unreadable holders dir fails closed instead of unmounting "nothing".
    let holders = backend
        .sysfs_related_names(target_name, Relation::Holders)
        .map_err(scan_read_err)?;

    // Direct `<proc>/mounts` read (missing/unreadable → empty), matching the
    // historic direct read — independent of the mountinfo fallback chain.
    let mounts_content = backend.mounts_file();

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
            let (stdout, stderr, code) = run_logged_cmd(backend, "umount", &["-f", &holder_dev], command_log)?;
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
        let (stdout, stderr, code) = run_logged_cmd(backend, "umount", &["-f", target_partition], command_log)?;
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

/// Executes a command through the backend, preserving the historic
/// command-log strings exactly (shared for all backends).
fn run_logged_cmd(
    backend: &dyn BlockBackend,
    program: &str,
    args: &[&str],
    command_log: &mut Vec<String>,
) -> Result<(String, String, i32), ExecuteError> {
    let full_cmd = format!("{} {}", program, args.join(" "));
    command_log.push(full_cmd.clone());
    backend.exec(program, args).map_err(|e| {
        // Historic message embeds the raw io::Error display.
        let detail = match &e {
            BackendError::Io(msg) => msg.clone(),
            other => other.to_string(),
        };
        ExecuteError::CommandFailed(format!("Failed to run {}: {}", program, detail))
    })
}

/// Resolves the parent disk device name from a partition device path/name.
pub fn resolve_parent_disk(
    backend: &dyn BlockBackend,
    device: &str,
) -> Result<String, ExecuteError> {
    let target_name = device.strip_prefix("/dev/").unwrap_or(device);

    if let Some(p_str) = backend.sysfs_parent_link(target_name) {
        if p_str != "block" && backend.sysfs_block_exists(&p_str) {
            return Ok(p_str);
        }
    }

    if target_name.starts_with("nvme") || target_name.starts_with("mmcblk") {
        if let Some(idx) = target_name.rfind('p') {
            let candidate = &target_name[..idx];
            if backend.sysfs_block_exists(candidate) {
                return Ok(candidate.to_string());
            }
        }
    } else {
        let candidate = target_name.trim_end_matches(|c: char| c.is_ascii_digit());
        if !candidate.is_empty() && backend.sysfs_block_exists(candidate) {
            return Ok(candidate.to_string());
        }
    }

    Err(ExecuteError::DeviceNotFound(format!(
        "Cannot resolve parent disk for partition {}",
        device
    )))
}

/// Resolves the parent disk's serial number from device facts.
pub fn resolve_parent_serial(
    backend: &dyn BlockBackend,
    device: &str,
) -> Result<String, ExecuteError> {
    let parent_name = resolve_parent_disk(backend, device)?;

    for attr in &["device/serial", "serial"] {
        if let Ok(Some(content)) = backend.sysfs_class_attr(&parent_name, attr) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }

    for attr in &["device/uevent", "uevent"] {
        if let Ok(Some(uevent)) = backend.sysfs_class_attr(&parent_name, attr) {
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

/// Validate a partition-mode target before any destructive open — the full
/// C2 chain over backend facts. Mints the [`ValidatedTarget`] whose scope
/// bounds every subsequent write.
pub fn validate_partition_target(
    backend: &dyn BlockBackend,
    device: &str,
    params: &PartitionTargetParams,
    dry_run: bool,
    device_serial: &str,
) -> Result<ValidatedTarget, ExecuteError> {
    let target_name = device.strip_prefix("/dev/").unwrap_or(device);

    // Sysfs geometry validation: partition, start, size
    if matches!(backend.sysfs_class_attr(target_name, "partition"), Ok(None)) {
        return Err(ExecuteError::UnsupportedOperation(format!(
            "Target '{}' is not recognized as a partition in sysfs ({})",
            device,
            Path::new(&backend.sysfs_root_display())
                .join("class/block")
                .join(target_name)
                .display()
        )));
    }
    let actual_num: u32 = backend
        .sysfs_class_attr(target_name, "partition")
        .unwrap_or_default()
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

    let actual_start: u64 = backend
        .sysfs_class_attr(target_name, "start")
        .unwrap_or_default()
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

    let actual_size: u64 = backend
        .sysfs_class_attr(target_name, "size")
        .unwrap_or_default()
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
        let uevent = backend
            .sysfs_class_attr(target_name, "uevent")
            .unwrap_or_default()
            .unwrap_or_default();
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
    let parent_name = resolve_parent_disk(backend, device)?;
    let actual_fingerprint = compute_partition_table_fingerprint(backend, &parent_name)?;
    if actual_fingerprint != params.expected_table_fingerprint {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Partition table changed: expected fingerprint {}, got sysfs {}",
            params.expected_table_fingerprint, actual_fingerprint
        )));
    }

    // Refuse MBR extended container partitions
    let parent_path = format!("/dev/{}", parent_name);
    if is_mbr_extended_partition(backend, device, &parent_path)? {
        return Err(ExecuteError::UnsupportedOperation(format!(
            "Refusing operation: target '{}' is an MBR extended container partition",
            device
        )));
    }

    // Logical block size alignment validation — fallback chain mirrors
    // `read_to_string(parent).or_else(read_to_string(part))`: only a read
    // *failure*/absence falls back; an unparseable present value yields 512.
    let lbs: u64 = match backend.sysfs_class_attr(&parent_name, "queue/logical_block_size") {
        Ok(Some(s)) => s.trim().parse::<u64>().unwrap_or(512),
        _ => match backend.sysfs_class_attr(target_name, "queue/logical_block_size") {
            Ok(Some(s)) => s.trim().parse::<u64>().unwrap_or(512),
            _ => 512,
        },
    };

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

    let guard_identity = get_guard_identity(backend, device, dry_run, device_serial)?;

    Ok(ValidatedTarget::sealed(
        guard_identity.canonical_path.clone(),
        guard_identity,
        TargetScope::Partition {
            parent_name,
            partition_number: actual_num,
            start_bytes,
            size_bytes,
            logical_block_size: lbs,
        },
    ))
}

/// Whole-disk validation entry: typed confirmation + boot-disk protection +
/// identity pinning. Used by the shared conformance suite to prove a backend
/// can never be written to without confirmation.
pub fn validate_whole_disk_target(
    backend: &dyn BlockBackend,
    device: &str,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
) -> Result<ValidatedTarget, ExecuteError> {
    verify_confirmation(confirmation_token, device_serial)?;
    check_boot_disk_protection(backend, device, dry_run)?;
    let guard_identity = get_guard_identity(backend, device, dry_run, device_serial)?;
    Ok(ValidatedTarget::sealed(
        guard_identity.canonical_path.clone(),
        guard_identity,
        TargetScope::WholeDisk,
    ))
}

/// C2a: whole-device target mint in the **historic flow order** — boot-disk
/// protection → confirmation token → identity pinning — the exact check
/// sequence the execution flows (`software_overwrite`, `discard_erase`)
/// performed inline before opening a writer. The returned target gates the
/// only way those flows open a device (`open_exclusive`); error precedence
/// is preserved so no existing test behavior changes.
pub fn validate_whole_disk_flow_target(
    backend: &dyn BlockBackend,
    device: &str,
    confirmation_token: &str,
    device_serial: &str,
    dry_run: bool,
) -> Result<ValidatedTarget, ExecuteError> {
    check_boot_disk_protection(backend, device, dry_run)?;
    verify_confirmation(confirmation_token, device_serial)?;
    let guard_identity = get_guard_identity(backend, device, dry_run, device_serial)?;
    Ok(ValidatedTarget::sealed(
        guard_identity.canonical_path.clone(),
        guard_identity,
        TargetScope::WholeDisk,
    ))
}

// ---------------------------------------------------------------------------
// Legacy adapter: the historic `ValidatedPartitionTarget` view (kept for API
// compatibility; the sealed ValidatedTarget above is the write gate).
// ---------------------------------------------------------------------------

impl ValidatedTarget {
    /// Project onto the legacy struct used by existing execution paths.
    pub fn to_legacy_partition_target(&self) -> Option<ValidatedPartitionTarget> {
        match &self.scope {
            TargetScope::WholeDisk => None,
            TargetScope::Partition {
                parent_name,
                start_bytes,
                size_bytes,
                logical_block_size,
                ..
            } => Some(ValidatedPartitionTarget {
                parent_name: parent_name.clone(),
                start_bytes: *start_bytes,
                size_bytes: *size_bytes,
                logical_block_size: *logical_block_size,
                guard_identity: self.guard_identity.clone(),
            }),
        }
    }
}
