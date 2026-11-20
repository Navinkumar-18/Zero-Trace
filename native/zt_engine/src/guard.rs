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

use crate::backend::windows_parse::{
    compute_windows_partition_fingerprint, layout_is_dynamic, volume_guid_eq, ParsedDriveLayout,
    PartitionStyle,
};
use crate::backend::{
    BackendError, BitLockerLockState, BlockBackend, DiskSetFact, ElevationFact, Relation,
    VolumeFact, VolumeGuidSetFact, WindowsBootFacts, WindowsVolumeFacts,
};
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
    /// Volume-scoped Windows wipe: the handle is the volume itself, so its
    /// byte range is volume-relative `[0, size_bytes)`. The parent-disk
    /// coordinates are pinned on [`WindowsVolumeIdentity`] instead.
    Volume {
        disk_number: u32,
        partition_number: u32,
        /// Always `0`: writes are volume-relative.
        start_bytes: u64,
        size_bytes: u64,
        /// `\\?\Volume{...}\` of the target.
        volume_guid: String,
        /// Drive letter used in the typed confirmation token.
        drive_letter: char,
        logical_block_size: u64,
    },
}

impl TargetScope {
    /// Byte range `start..end` of a partition scope on the parent device
    /// (None = whole disk or volume-relative scope).
    pub fn partition_range(&self) -> Option<(u64, u64)> {
        match self {
            TargetScope::WholeDisk | TargetScope::Volume { .. } => None,
            TargetScope::Partition {
                start_bytes,
                size_bytes,
                ..
            } => Some((*start_bytes, start_bytes.saturating_add(*size_bytes))),
        }
    }

    /// Bounds enforced by [`crate::backend::ExclusiveHandle::write_at`]:
    /// `(low, high, scope label)`. `None` = whole disk (no extra bound).
    pub(crate) fn write_bounds(&self) -> Option<(u64, u64, &'static str)> {
        match self {
            TargetScope::WholeDisk => None,
            TargetScope::Partition {
                start_bytes,
                size_bytes,
                ..
            } => Some((
                *start_bytes,
                start_bytes.saturating_add(*size_bytes),
                "partition",
            )),
            TargetScope::Volume {
                start_bytes,
                size_bytes,
                ..
            } => Some((
                *start_bytes,
                start_bytes.saturating_add(*size_bytes),
                "volume",
            )),
        }
    }
}

/// Warnings that the UI must surface for a validated Windows volume target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct WindowsVolumeWarnings {
    /// The volume is BitLocker-protected and currently unlocked. On-disk data
    /// is ciphertext; verification reads the decrypted view through Windows.
    pub bitlocker_unlocked: bool,
    /// The volume shares a physical disk with the Windows system volume.
    /// Validation additionally required the caller's same-disk confirmation.
    pub same_disk_as_system: bool,
}

/// Identity pinned at Windows volume validation time (Step 1.3) and
/// re-checked immediately before the lock in Step 1.4.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WindowsVolumeIdentity {
    pub disk_number: u32,
    pub partition_number: u32,
    /// Absolute offset of the partition on the parent disk.
    pub partition_start_bytes: u64,
    /// Volume logical size; also the write bound `[0, size_bytes)`.
    pub size_bytes: u64,
    /// `\\?\Volume{...}\` form.
    pub volume_guid: String,
    /// Windows partition-table fingerprint (`compute_windows_partition_fingerprint`).
    pub partition_table_fingerprint: String,
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
    /// P2: device size pinned at mint time and re-checked immediately before
    /// every destructive firmware command. `0` = geometry unavailable at
    /// mint time (fixture backends), comparison skipped.
    pinned_size_bytes: u64,
    /// Step 1.3: Windows volume identity pinned by
    /// [`validate_windows_volume_target`]. `None` for Linux scopes.
    windows_volume: Option<WindowsVolumeIdentity>,
    /// Step 1.3: warnings the UI must surface for a Windows volume target.
    windows_warnings: WindowsVolumeWarnings,
}

impl ValidatedTarget {
    /// Sealed constructor — private to this module (the guard chain).
    fn sealed(
        canonical_path: String,
        guard_identity: GuardIdentity,
        scope: TargetScope,
        pinned_size_bytes: u64,
    ) -> Self {
        Self {
            canonical_path,
            guard_identity,
            scope,
            pinned_size_bytes,
            windows_volume: None,
            windows_warnings: WindowsVolumeWarnings::default(),
        }
    }

    /// Sealed Windows-volume constructor (Step 1.3).
    fn sealed_windows_volume(
        canonical_path: String,
        guard_identity: GuardIdentity,
        scope: TargetScope,
        identity: WindowsVolumeIdentity,
        warnings: WindowsVolumeWarnings,
    ) -> Self {
        Self {
            canonical_path,
            guard_identity,
            scope,
            pinned_size_bytes: identity.size_bytes,
            windows_volume: Some(identity),
            windows_warnings: warnings,
        }
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

    /// Step 1.3: pinned Windows volume identity, when this is a volume target.
    pub fn windows_volume_identity(&self) -> Option<&WindowsVolumeIdentity> {
        self.windows_volume.as_ref()
    }

    /// Step 1.3: warnings the UI must display (both false for Linux scopes).
    pub fn windows_warnings(&self) -> WindowsVolumeWarnings {
        self.windows_warnings
    }

    pub fn device_serial(&self) -> &str {
        &self.guard_identity.device_serial
    }

    /// P2: size pinned at validation time (0 = unknown).
    pub fn pinned_size_bytes(&self) -> u64 {
        self.pinned_size_bytes
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
        "tmpfs",
        "devtmpfs",
        "proc",
        "sysfs",
        "cgroup",
        "cgroup2",
        "ramfs",
        "devpts",
        "pstore",
        "securityfs",
        "tracefs",
        "debugfs",
        "mqueue",
        "hugetlbfs",
        "autofs",
        "fusectl",
        "configfs",
        "efivarfs",
        "bpf",
        "squashfs",
        "nsfs",
        "pipefs",
        "sockfs",
        "rpc_pipefs",
    ]
    .into_iter()
    .collect();

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
        let dev_attr = backend
            .sysfs_class_attr(&name, "dev")
            .map_err(scan_read_err)?;
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
            return Err(ExecuteError::BootDiskProtection(format!(
                "Corrupt mountinfo line: {}",
                line
            )));
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
                                format!(
                                    "btrfs device '{}' for protected mount '{}'",
                                    d_name, mount_point
                                ),
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
                                format!(
                                    "btrfs source '{}' for protected mount '{}'",
                                    src_name, mount_point
                                ),
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
                                format!(
                                    "mount source '{}' for protected mount '{}'",
                                    mount_source, mount_point
                                ),
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
                            format!(
                                "mount source '{}' for protected mount '{}'",
                                mount_source, mount_point
                            ),
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
                protected_devs.insert(
                    mm,
                    format!("backing device for active swap file '{}'", swap_target),
                );
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
                    protected_devs.insert(
                        mm,
                        format!(
                            "backing mount '{}' for active swap file '{}'",
                            best_prefix, swap_target
                        ),
                    );
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
                        || dev[parent_disk.len()..]
                            .chars()
                            .next()
                            .is_some_and(|c| c.is_ascii_digit()))
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
                    || dev[target_name.len()..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_digit()))
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
                "Cannot read sysfs dev file for {}: {}",
                dev, msg
            )),
            other => ExecuteError::BootDiskProtection(other.to_string()),
        })?;
        if let Some(content) = dev_attr {
            let mm = parse_major_minor(&content).ok_or_else(|| {
                ExecuteError::BootDiskProtection(format!(
                    "Corrupt dev file for device {}: '{}'",
                    dev,
                    content.trim()
                ))
            })?;

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

// ---------------------------------------------------------------------------
// D-a piece 2: Windows boot/system disk refusal (shared policy)
// ---------------------------------------------------------------------------

/// Parses a Windows physical-drive path (`\\.\PhysicalDriveN` or
/// `PhysicalDriveN`) into its disk number.
pub fn windows_disk_number(device: &str) -> Option<u32> {
    let name = device.trim();
    let name = name.strip_prefix(r"\\.\").unwrap_or(name);
    let name = name.strip_prefix(r"\??\").unwrap_or(name);
    let digits = name.strip_prefix("PhysicalDrive")?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Pure per-disk refusal reason from Windows boot facts. `None` = this disk is
/// not named by any evidence. An unreadable fact refuses **every** disk
/// (fail closed), never only the disks that happen to be known.
pub fn windows_boot_facts_disk_refusal(facts: &WindowsBootFacts, disk: u32) -> Option<String> {
    let fields = [
        ("system disk", &facts.system_disks),
        ("boot volume", &facts.boot_disks),
        ("page-file", &facts.pagefile_disks),
        ("hibernation file", &facts.hibernation_disks),
        ("crash-dump", &facts.crashdump_disks),
        ("Zero Trace application", &facts.app_disks),
    ];
    for (label, fact) in fields {
        if let Some(reason) = fact.reason() {
            return Some(format!(
                "Cannot read the Windows {} fact ({}): refusing destructive operation (fail closed)",
                label, reason
            ));
        }
    }

    let evidence: &[(&DiskSetFact, &str)] = &[
        (
            &facts.system_disks,
            "Windows is running from this disk. Use the Zero Trace live USB",
        ),
        (
            &facts.boot_disks,
            "This disk holds the Windows boot volume. Use the Zero Trace live USB",
        ),
        (
            &facts.pagefile_disks,
            "This disk holds an active Windows page file. Disable or move the page file before wiping",
        ),
        (
            &facts.hibernation_disks,
            "This disk holds the Windows hibernation file. Disable hibernation before wiping",
        ),
        (
            &facts.crashdump_disks,
            "This disk holds the Windows crash-dump target. Change the dump target before wiping",
        ),
        (
            &facts.app_disks,
            "This disk holds the running Zero Trace application. Start Zero Trace from removable media instead",
        ),
    ];
    for (fact, message) in evidence {
        if fact.disks().is_some_and(|disks| disks.contains(&disk)) {
            return Some(format!(
                "{} (disk {}): refusing destructive operation",
                message, disk
            ));
        }
    }
    None
}

/// Pure elevation refusal (unreadable token fact or an unelevated process).
pub fn windows_elevation_refusal(facts: &WindowsBootFacts) -> Option<String> {
    match &facts.elevated {
        ElevationFact::Known(true) => None,
        ElevationFact::Known(false) => Some(
            "Zero Trace is not running elevated: refusing destructive operation".to_string(),
        ),
        ElevationFact::Unreadable(reason) => Some(format!(
            "Cannot read the Windows elevation fact ({}): refusing destructive operation (fail closed)",
            reason
        )),
    }
}

/// Pure Windows disk decision: unknown/unreadable evidence and an unelevated
/// process both refuse. Used by the backend-independent conformance suite and
/// by the `windows-facts` output.
pub fn check_windows_boot_facts_for_disk(
    facts: &WindowsBootFacts,
    disk: u32,
) -> Result<(), ExecuteError> {
    if let Some(reason) = windows_boot_facts_disk_refusal(facts, disk) {
        return Err(ExecuteError::BootDiskProtection(reason));
    }
    if let Some(reason) = windows_elevation_refusal(facts) {
        return Err(ExecuteError::BootDiskProtection(reason));
    }
    Ok(())
}

/// Shared Windows boot-disk protection over backend facts. `Ok(())` on
/// non-Windows backends (which report no Windows boot facts); on Windows a
/// failed fact read or a non-physical-drive path is a refusal, never a pass.
pub fn check_windows_boot_disk_protection(
    backend: &dyn BlockBackend,
    device: &str,
) -> Result<(), ExecuteError> {
    let Some(facts) = backend.windows_boot_facts().map_err(scan_read_err)? else {
        return Ok(());
    };
    let disk = windows_disk_number(device).ok_or_else(|| {
        ExecuteError::UnsupportedOperation(format!("Not a Windows physical-drive path: {}", device))
    })?;
    check_windows_boot_facts_for_disk(&facts, disk)
}

// ---------------------------------------------------------------------------
// Step 1.3: Windows volume-scope guard
// ---------------------------------------------------------------------------

/// Prefix of the extra confirmation token required when the target volume
/// shares a physical disk with the Windows system volume.
pub const WINDOWS_SAME_DISK_PREFIX: &str = "SAME DISK ";

/// Placeholder label field for a volume with no label.
pub const WINDOWS_NO_LABEL: &str = "NO_LABEL";

/// Caller inputs for [`validate_windows_volume_target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsVolumeTargetParams {
    /// `\\?\Volume{...}\` (or any form compared by `volume_guid_eq`).
    pub volume_guid: String,
    /// Required token: `<letter>: <label> <size>`, e.g. `E: BACKUP 29.8GB`.
    pub confirmation_token: String,
    /// Required only when the volume is on the system volume's physical
    /// disk: `SAME DISK <letter>: <label> <size>`.
    pub same_disk_confirmation: Option<String>,
}

/// Formats a byte count for the typed confirmation token: the largest
/// decimal (SI, 1000-based) unit with at least 1.0, one rounded decimal and
/// no space, e.g. `29.8GB`, `500.1GB`, `1.0TB`. Rounding is half-up on
/// integer arithmetic so the Dart dialog can reproduce it exactly.
pub fn format_windows_volume_size(bytes: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1_000_000_000_000, "TB"),
        (1_000_000_000, "GB"),
        (1_000_000, "MB"),
        (1_000, "KB"),
    ];

    if bytes < 1_000 {
        return format!("{}B", bytes);
    }

    let mut index = UNITS
        .iter()
        .position(|(unit, _)| bytes >= *unit)
        .unwrap_or(UNITS.len() - 1);

    loop {
        let (unit, suffix) = UNITS[index];
        let tenths = ((bytes as u128) * 10 + (unit as u128) / 2) / (unit as u128);
        // 999.95+ rounded to 1000.0 — promote to the next larger unit so the
        // token never says "1000.0GB".
        if tenths >= 10_000 && index > 0 {
            index -= 1;
            continue;
        }
        return format!("{}.{}{}", tenths / 10, tenths % 10, suffix);
    }
}

/// Canonical required confirmation token from volume facts:
/// `"<letter>: <label> <size>"`.
///
/// * letter: uppercase drive letter, colon attached;
/// * label: reported label trimmed; the literal `NO_LABEL` when absent/empty;
/// * size: [`format_windows_volume_size`] of `total_bytes`, no space before
///   the unit.
pub fn windows_volume_confirmation_token(
    facts: &WindowsVolumeFacts,
) -> Result<String, ExecuteError> {
    let (letter, label, size) = windows_volume_token_parts(facts)?;
    Ok(format!("{}: {} {}", letter, label, size))
}

/// Canonical same-disk token: `SAME DISK <required token>`.
pub fn windows_volume_same_disk_token(facts: &WindowsVolumeFacts) -> Result<String, ExecuteError> {
    Ok(format!(
        "{}{}",
        WINDOWS_SAME_DISK_PREFIX,
        windows_volume_confirmation_token(facts)?
    ))
}

fn windows_volume_token_parts(
    facts: &WindowsVolumeFacts,
) -> Result<(char, String, String), ExecuteError> {
    let letter = facts.primary_drive_letter().ok_or_else(|| {
        ExecuteError::WindowsVolumeNoDriveLetter(format!(
            "Volume '{}' has no drive letter mount point",
            facts.volume_guid_path
        ))
    })?;

    let label = match &facts.label {
        VolumeFact::Known(Some(label)) => {
            let trimmed = label.trim();
            if trimmed.is_empty() {
                WINDOWS_NO_LABEL.to_string()
            } else {
                trimmed.to_string()
            }
        }
        VolumeFact::Known(None) => WINDOWS_NO_LABEL.to_string(),
        VolumeFact::Unreadable(reason) => {
            return Err(ExecuteError::WindowsVolumeFactsUnreadable(format!(
                "Cannot read the volume label for '{}': {}",
                facts.volume_guid_path, reason
            )))
        }
    };

    let size = match &facts.total_bytes {
        VolumeFact::Known(bytes) => format_windows_volume_size(*bytes),
        VolumeFact::Unreadable(reason) => {
            return Err(ExecuteError::WindowsVolumeGeometry(format!(
                "Cannot read the volume size for '{}': {}",
                facts.volume_guid_path, reason
            )))
        }
    };

    Ok((letter, label, size))
}

/// Parses `"<letter>: <label> <size>"`. Label may contain spaces; the size
/// is the last whitespace-delimited token. `None` = malformed.
fn split_windows_volume_token(token: &str) -> Option<(char, String, String)> {
    let token = token.trim();
    let (head, rest) = token.split_once(|c: char| c.is_whitespace())?;

    let mut head_chars = head.chars();
    let letter = head_chars.next()?.to_ascii_uppercase();
    if !letter.is_ascii_alphabetic() || head_chars.next()? != ':' {
        return None;
    }
    if head_chars.next().is_some() {
        return None;
    }

    let rest = rest.trim();
    let split_at = rest.rfind(|c: char| c.is_whitespace())?;
    let label = rest[..split_at].trim();
    let size = rest[split_at..].trim();
    if label.is_empty() || size.is_empty() {
        return None;
    }

    Some((letter, label.to_string(), size.to_ascii_uppercase()))
}

/// Verifies the required token: case-insensitive drive letter, trimmed label
/// (exact otherwise), case-insensitive size unit. Any mismatch is the
/// existing typed [`ExecuteError::ConfirmationMismatch`].
pub fn verify_windows_volume_confirmation(
    token: &str,
    facts: &WindowsVolumeFacts,
) -> Result<(), ExecuteError> {
    let (letter, label, size) = windows_volume_token_parts(facts)?;
    let Some((got_letter, got_label, got_size)) = split_windows_volume_token(token) else {
        return Err(ExecuteError::ConfirmationMismatch);
    };
    if got_letter != letter || got_label != label || got_size != size.to_ascii_uppercase() {
        return Err(ExecuteError::ConfirmationMismatch);
    }
    Ok(())
}

/// Verifies the extra same-disk token (`SAME DISK <required token>`). The
/// prefix is case-insensitive; the remainder follows the required-token
/// rules.
pub fn verify_windows_same_disk_confirmation(
    token: &str,
    facts: &WindowsVolumeFacts,
) -> Result<(), ExecuteError> {
    let token = token.trim();
    let prefix = token.get(..WINDOWS_SAME_DISK_PREFIX.len()).ok_or_else(|| {
        ExecuteError::WindowsVolumeSameDiskConfirmation(
            "same-disk confirmation must start with 'SAME DISK '".to_string(),
        )
    })?;
    if !prefix.eq_ignore_ascii_case(WINDOWS_SAME_DISK_PREFIX) {
        return Err(ExecuteError::WindowsVolumeSameDiskConfirmation(
            "same-disk confirmation must start with 'SAME DISK '".to_string(),
        ));
    }
    verify_windows_volume_confirmation(&token[WINDOWS_SAME_DISK_PREFIX.len()..], facts).map_err(
        |_| {
            ExecuteError::WindowsVolumeSameDiskConfirmation(
                "same-disk confirmation token does not match the target volume".to_string(),
            )
        },
    )
}

fn windows_volume_flag_refusal(fact: &VolumeFact<bool>, what: &str) -> Option<String> {
    match fact {
        VolumeFact::Known(true) => Some(format!("Volume {}", what)),
        VolumeFact::Known(false) => None,
        VolumeFact::Unreadable(reason) => Some(format!(
            "Cannot read whether the volume {} ({}): refusing destructive operation (fail closed)",
            what, reason
        )),
    }
}

fn windows_volume_set_refusal(
    fact: &VolumeGuidSetFact,
    volume_guid: &str,
    what: &str,
) -> Option<String> {
    match fact {
        VolumeGuidSetFact::Unreadable(reason) => Some(format!(
            "Cannot read the Windows {} volume fact ({}): refusing destructive operation (fail closed)",
            what, reason
        )),
        VolumeGuidSetFact::Known(volumes) => {
            if volumes
                .iter()
                .any(|candidate| volume_guid_eq(candidate, volume_guid))
            {
                Some(format!("Volume {} ({})", what, volume_guid))
            } else {
                None
            }
        }
    }
}

fn windows_volume_known<T: Copy>(fact: &VolumeFact<T>, what: &str) -> Result<T, ExecuteError> {
    match fact {
        VolumeFact::Known(value) => Ok(*value),
        VolumeFact::Unreadable(reason) => Err(ExecuteError::WindowsVolumeNotBasic(format!(
            "Cannot read the volume {} ({}): refusing destructive operation (fail closed)",
            what, reason
        ))),
    }
}

/// Reads the parent-disk layout and returns `(partition, fingerprint)` for the
/// target partition. A layout that cannot be read or has no matching basic
/// partition is a refusal, never a guess.
fn windows_volume_layout_identity(
    backend: &dyn BlockBackend,
    disk_number: u32,
    partition_number: u32,
) -> Result<(crate::backend::windows_parse::ParsedPartition, String), ExecuteError> {
    let layout: ParsedDriveLayout = backend.windows_drive_layout(disk_number).map_err(|e| {
        ExecuteError::WindowsVolumeNotBasic(format!(
            "Cannot read the partition table of disk {} ({}): refusing destructive operation",
            disk_number, e
        ))
    })?;

    if !matches!(layout.style, PartitionStyle::Gpt | PartitionStyle::Mbr) {
        return Err(ExecuteError::WindowsVolumeNotBasic(format!(
            "Disk {} has no basic MBR/GPT partition table ({:?})",
            disk_number, layout.style
        )));
    }
    if layout_is_dynamic(&layout) {
        return Err(ExecuteError::WindowsVolumeNotBasic(format!(
            "Disk {} is a dynamic disk / Storage Spaces member",
            disk_number
        )));
    }

    let partition = layout
        .partitions
        .iter()
        .find(|partition| partition.partition_number == partition_number)
        .cloned()
        .ok_or_else(|| {
            ExecuteError::WindowsVolumeNotBasic(format!(
                "Disk {} has no basic partition #{} in its drive layout",
                disk_number, partition_number
            ))
        })?;

    let fingerprint = compute_windows_partition_fingerprint(&layout.partitions);
    Ok((partition, fingerprint))
}

/// Every fact and policy decision for a Windows volume target, with the
/// typed confirmation excluded: used by `windows-validate` to show the
/// required tokens, warnings and pinned identity, and by
/// [`validate_windows_volume_target`] as its single pre-token decision path.
#[derive(Debug, Clone)]
pub struct WindowsVolumeInspection {
    pub volume_guid: String,
    pub facts: WindowsVolumeFacts,
    pub drive_letter: char,
    pub size_bytes: u64,
    pub logical_block_size: u64,
    pub identity: WindowsVolumeIdentity,
    pub warnings: WindowsVolumeWarnings,
    /// Canonical required token: `<letter>: <label> <size>`.
    pub required_confirmation: String,
    /// `SAME DISK <required token>` when the volume shares the system disk.
    pub required_same_disk_confirmation: Option<String>,
}

/// Runs every Windows volume check **except** the typed confirmation tokens:
/// elevation, drive letter, local drive type, system/app volume,
/// boot/pagefile/hibernation/crash-dump, single basic extent, dynamic disk,
/// Storage Spaces, VHD, BitLocker and geometry. The volume is re-enumerated
/// by the guard (the caller cannot pass stale or forged facts).
pub fn inspect_windows_volume_target(
    backend: &dyn BlockBackend,
    volume_guid: &str,
) -> Result<WindowsVolumeInspection, ExecuteError> {
    // 1. Elevation. Missing/unreadable facts are a refusal, never a pass.
    let boot_facts = backend
        .windows_boot_facts()
        .map_err(|e| {
            ExecuteError::WindowsVolumeNotElevated(format!(
                "Cannot read the Windows elevation fact ({}): refusing destructive operation (fail closed)",
                e
            ))
        })?
        .ok_or_else(|| {
            ExecuteError::WindowsVolumeNotElevated(
                "Windows boot/elevation facts are unavailable on this backend".to_string(),
            )
        })?;
    if let Some(reason) = windows_elevation_refusal(&boot_facts) {
        return Err(ExecuteError::WindowsVolumeNotElevated(reason));
    }

    // 2. Re-enumerate and select the exact volume.
    let volumes = backend.enumerate_volumes().map_err(|e| {
        ExecuteError::UnsupportedOperation(format!(
            "Cannot enumerate Windows volumes on this backend: {}",
            e
        ))
    })?;
    let facts = volumes
        .iter()
        .find(|volume| volume_guid_eq(&volume.volume_guid_path, volume_guid))
        .ok_or_else(|| {
            ExecuteError::DeviceNotFound(format!(
                "Windows volume '{}' was not enumerated",
                volume_guid
            ))
        })?;

    // 3. Drive letter and local drive type: EFI/recovery/OEM volumes,
    //    network shares, CD-ROMs and RAM disks are never targets.
    let letter = match &facts.drive_letters {
        VolumeFact::Known(letters) if !letters.is_empty() => {
            *letters.iter().min().expect("non-empty")
        }
        VolumeFact::Known(_) => {
            return Err(ExecuteError::WindowsVolumeNoDriveLetter(format!(
                "Volume '{}' has no drive-letter mount point",
                facts.volume_guid_path
            )))
        }
        VolumeFact::Unreadable(reason) => {
            return Err(ExecuteError::WindowsVolumeNoDriveLetter(format!(
                "Cannot read the mount points of '{}' ({}): refusing destructive operation (fail closed)",
                facts.volume_guid_path, reason
            )))
        }
    };
    let drive_type = windows_volume_known(&facts.drive_type, "drive type")?;
    if !matches!(
        drive_type,
        crate::backend::VolumeDriveType::Fixed | crate::backend::VolumeDriveType::Removable
    ) {
        return Err(ExecuteError::WindowsVolumeNotBasic(format!(
            "Volume '{}' has drive type {:?}; only local fixed/removable volumes can be wiped",
            facts.volume_guid_path, drive_type
        )));
    }

    // 4. System / running-app volume.
    if let Some(reason) =
        windows_volume_flag_refusal(&facts.is_system_volume, "is the Windows system/boot volume")
    {
        return Err(ExecuteError::WindowsVolumeProtected(reason));
    }
    if let Some(reason) = windows_volume_flag_refusal(
        &facts.hosts_running_app,
        "holds the running Zero Trace application",
    ) {
        return Err(ExecuteError::WindowsVolumeProtected(reason));
    }

    // 5. Page file / hibernation file / crash dump, at volume granularity.
    if let Some(reason) = windows_volume_set_refusal(
        &boot_facts.pagefile_volumes,
        &facts.volume_guid_path,
        "holds an active page file",
    ) {
        return Err(ExecuteError::WindowsVolumeInUse(reason));
    }
    if let Some(reason) = windows_volume_set_refusal(
        &boot_facts.hibernation_volumes,
        &facts.volume_guid_path,
        "holds the hibernation file",
    ) {
        return Err(ExecuteError::WindowsVolumeInUse(reason));
    }
    if let Some(reason) = windows_volume_set_refusal(
        &boot_facts.crashdump_volumes,
        &facts.volume_guid_path,
        "holds the crash-dump target",
    ) {
        return Err(ExecuteError::WindowsVolumeInUse(reason));
    }

    // 6. Exactly one basic local partition.
    let extent_count = windows_volume_known(&facts.extent_count, "extent count")?;
    if extent_count != 1 {
        return Err(ExecuteError::WindowsVolumeNotBasic(format!(
            "Volume '{}' spans {} disk extents (exactly 1 is required)",
            facts.volume_guid_path, extent_count
        )));
    }
    let disk_number =
        windows_volume_known(&facts.disk_number, "disk number")?.ok_or_else(|| {
            ExecuteError::WindowsVolumeNotBasic(format!(
                "Volume '{}' has no single disk number",
                facts.volume_guid_path
            ))
        })?;
    let partition_number = windows_volume_known(&facts.partition_number, "partition number")?
        .ok_or_else(|| {
            ExecuteError::WindowsVolumeNotBasic(format!(
                "Volume '{}' has no basic partition number",
                facts.volume_guid_path
            ))
        })?;

    // 7. Parent-disk layout, dynamic-disk flags, starting offset, fingerprint.
    let (partition, fingerprint) =
        windows_volume_layout_identity(backend, disk_number, partition_number)?;

    // 8. Storage Spaces / VHD / virtual disk transport.
    let devices = backend.enumerate_devices().map_err(|e| {
        ExecuteError::WindowsVolumeNotBasic(format!(
            "Cannot enumerate physical disks to classify disk {} ({}): refusing destructive operation",
            disk_number, e
        ))
    })?;
    let disk_info = devices
        .iter()
        .find(|device| windows_disk_number(&device.name) == Some(disk_number))
        .ok_or_else(|| {
            ExecuteError::WindowsVolumeNotBasic(format!(
                "Physical disk {} was not found in device discovery",
                disk_number
            ))
        })?;
    match disk_info.transport.as_deref() {
        Some("virtual") => {
            return Err(ExecuteError::WindowsVolumeNotBasic(format!(
                "Disk {} is a virtual disk (VHD/VHDX); volume wipes require a physical disk",
                disk_number
            )))
        }
        Some("spaces") => {
            return Err(ExecuteError::WindowsVolumeNotBasic(format!(
                "Disk {} is a Storage Spaces disk; volume wipes require a basic physical disk",
                disk_number
            )))
        }
        Some(_) => {}
        None => {
            return Err(ExecuteError::WindowsVolumeNotBasic(format!(
                "Cannot determine the transport of physical disk {}",
                disk_number
            )))
        }
    }

    // 9. BitLocker: locked and unknown both refuse; unlocked is allowed with
    //    the warning. Unlocked on-disk data is ciphertext, not plaintext.
    if facts.bitlocker_state.treated_as_locked() {
        let reason = facts
            .bitlocker_state
            .reason()
            .unwrap_or("BitLocker reports the volume as locked");
        return Err(ExecuteError::WindowsVolumeBitLockerLocked(format!(
            "Volume '{}': {}",
            facts.volume_guid_path, reason
        )));
    }
    let bitlocker_unlocked = facts.bitlocker_state == BitLockerLockState::Unlocked;

    // 10. Size / logical block size.
    let size_bytes = match &facts.total_bytes {
        VolumeFact::Known(bytes) if *bytes > 0 => *bytes,
        VolumeFact::Known(_) => {
            return Err(ExecuteError::WindowsVolumeGeometry(format!(
                "Volume '{}' reports a zero size",
                facts.volume_guid_path
            )))
        }
        VolumeFact::Unreadable(reason) => {
            return Err(ExecuteError::WindowsVolumeGeometry(format!(
                "Cannot read the size of '{}' ({}): refusing destructive operation (fail closed)",
                facts.volume_guid_path, reason
            )))
        }
    };
    let geometry = backend
        .device_geometry(&facts.volume_guid_path)
        .map_err(|e| {
            ExecuteError::WindowsVolumeGeometry(format!(
                "Cannot read the logical sector size of '{}' ({}): refusing destructive operation (fail closed)",
                facts.volume_guid_path, e
            ))
        })?;
    let logical_block_size = u64::from(geometry.logical_block_size);
    if logical_block_size == 0 {
        return Err(ExecuteError::WindowsVolumeGeometry(format!(
            "Volume '{}' reports a zero logical block size",
            facts.volume_guid_path
        )));
    }
    if size_bytes % logical_block_size != 0 {
        return Err(ExecuteError::WindowsVolumeGeometry(format!(
            "Volume '{}' size {} is not a multiple of the logical block size {}",
            facts.volume_guid_path, size_bytes, logical_block_size
        )));
    }

    // 11. Same-physical-disk-as-system fact: an unreadable system-disk set
    //     refuses (fail closed). The extra token itself is verified by
    //     `validate_windows_volume_target`.
    let system_disks = match &boot_facts.system_disks {
        DiskSetFact::Known(disks) => disks,
        DiskSetFact::Unreadable(reason) => {
            return Err(ExecuteError::WindowsVolumeProtected(format!(
                "Cannot read the Windows system-disk fact ({}): refusing destructive operation (fail closed)",
                reason
            )))
        }
    };
    let same_disk_as_system = system_disks.contains(&disk_number);

    let volume_guid_path = facts.volume_guid_path.clone();
    let identity = WindowsVolumeIdentity {
        disk_number,
        partition_number,
        partition_start_bytes: partition.starting_offset,
        size_bytes,
        volume_guid: volume_guid_path.clone(),
        partition_table_fingerprint: fingerprint,
    };
    let warnings = WindowsVolumeWarnings {
        bitlocker_unlocked,
        same_disk_as_system,
    };
    // Both token builders only need facts that steps 3 and 10 already
    // validated; an unreadable label is still a typed refusal here.
    let required_confirmation = windows_volume_confirmation_token(facts)?;
    let required_same_disk_confirmation = if same_disk_as_system {
        Some(windows_volume_same_disk_token(facts)?)
    } else {
        None
    };

    Ok(WindowsVolumeInspection {
        volume_guid: volume_guid_path,
        facts: facts.clone(),
        drive_letter: letter,
        size_bytes,
        logical_block_size,
        identity,
        warnings,
        required_confirmation,
        required_same_disk_confirmation,
    })
}

/// Validates a Windows volume as a wipe target and mints the sealed
/// [`ValidatedTarget`]. **Every** decision lives here; the backend only
/// supplied facts.
///
/// The volume is re-enumerated by the guard (the caller cannot pass stale or
/// forged facts), then refused with a distinct typed error for: unelevated
/// process, no drive letter, system/app volume, boot/pagefile/hibernation/
/// crash-dump volume, multi-extent / unknown disk or partition / dynamic
/// disk / Storage Spaces / VHD, locked or unknown BitLocker, unreadable or
/// misaligned geometry, and a wrong typed confirmation. An unlocked
/// BitLocker volume is allowed with
/// [`WindowsVolumeWarnings::bitlocker_unlocked`]; a volume on the system
/// volume's physical disk is allowed only with the extra same-disk token and
/// sets [`WindowsVolumeWarnings::same_disk_as_system`].
pub fn validate_windows_volume_target(
    backend: &dyn BlockBackend,
    params: &WindowsVolumeTargetParams,
) -> Result<ValidatedTarget, ExecuteError> {
    let inspection = inspect_windows_volume_target(backend, &params.volume_guid)?;

    // Typed confirmation (single pass/fail decision for the whole chain).
    verify_windows_volume_confirmation(&params.confirmation_token, &inspection.facts)?;

    // Same-physical-disk-as-system policy: not a blanket refusal, but an
    // extra explicit confirmation and a warning flag.
    if let Some(required) = &inspection.required_same_disk_confirmation {
        let token = params.same_disk_confirmation.as_deref().ok_or_else(|| {
            ExecuteError::WindowsVolumeSameDiskConfirmation(format!(
                "Volume '{}' is on the Windows system disk {}; type '{}' to continue",
                inspection.volume_guid, inspection.identity.disk_number, required
            ))
        })?;
        verify_windows_same_disk_confirmation(token, &inspection.facts)?;
    }

    let guard_identity = GuardIdentity {
        canonical_path: inspection.volume_guid.clone(),
        st_rdev: 0,
        major: 0,
        minor: 0,
        is_block: true,
        device_serial: inspection.volume_guid.clone(),
        st_ino: 0,
    };
    let scope = TargetScope::Volume {
        disk_number: inspection.identity.disk_number,
        partition_number: inspection.identity.partition_number,
        start_bytes: 0,
        size_bytes: inspection.size_bytes,
        volume_guid: inspection.volume_guid.clone(),
        drive_letter: inspection.drive_letter,
        logical_block_size: inspection.logical_block_size,
    };

    Ok(ValidatedTarget::sealed_windows_volume(
        inspection.volume_guid,
        guard_identity,
        scope,
        inspection.identity,
        inspection.warnings,
    ))
}

/// Resolves a CLI/UI volume selector (`E`, `E:`, `E:\`, a mount point or a
/// `\\?\Volume{GUID}\` path) to its canonical volume GUID path. A selector
/// that does not resolve is the typed [`ExecuteError::DeviceNotFound`]; a
/// backend without Volume GUID resolution (non-Windows) is
/// [`ExecuteError::UnsupportedOperation`].
pub fn resolve_windows_volume_target(
    backend: &dyn BlockBackend,
    selector: &str,
) -> Result<String, ExecuteError> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(ExecuteError::DeviceNotFound(
            "empty Windows volume selector".to_string(),
        ));
    }
    backend.resolve_volume_guid(selector).map_err(|e| match e {
        crate::backend::BackendError::Unsupported(_) => ExecuteError::UnsupportedOperation(
            "volume GUID resolution is only available on Windows".to_string(),
        ),
        other => ExecuteError::DeviceNotFound(format!(
            "Cannot resolve Windows volume '{}': {}",
            selector, other
        )),
    })
}

/// Re-checks every pinned Windows volume identity value immediately before
/// the lock (Step 1.4). Any drift — vanished volume, changed disk/partition,
/// changed size, changed starting offset, changed partition table, or a
/// volume that became locked — is a hard [`ExecuteError::IdentityMismatch`].
pub fn revalidate_windows_volume_identity(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
) -> Result<(), ExecuteError> {
    let identity = target.windows_volume_identity().ok_or_else(|| {
        ExecuteError::IdentityMismatch(
            "Revalidation requires a validated Windows volume target".to_string(),
        )
    })?;

    let volumes = backend.enumerate_volumes().map_err(|e| {
        ExecuteError::IdentityMismatch(format!(
            "Cannot re-enumerate Windows volumes before the lock: {}",
            e
        ))
    })?;
    let facts = volumes
        .iter()
        .find(|volume| volume_guid_eq(&volume.volume_guid_path, &identity.volume_guid))
        .ok_or_else(|| {
            ExecuteError::IdentityMismatch(format!(
                "Volume '{}' disappeared after validation",
                identity.volume_guid
            ))
        })?;

    if facts.bitlocker_state.treated_as_locked() {
        return Err(ExecuteError::WindowsVolumeBitLockerLocked(format!(
            "Volume '{}' is locked or its BitLocker state is unknown after validation",
            identity.volume_guid
        )));
    }

    let extent_count = windows_volume_known(&facts.extent_count, "extent count")?;
    if extent_count != 1 {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Volume '{}' now spans {} extents (expected 1)",
            identity.volume_guid, extent_count
        )));
    }
    let disk_number =
        windows_volume_known(&facts.disk_number, "disk number")?.ok_or_else(|| {
            ExecuteError::IdentityMismatch(format!(
                "Volume '{}' no longer maps to a single disk",
                identity.volume_guid
            ))
        })?;
    let partition_number = windows_volume_known(&facts.partition_number, "partition number")?
        .ok_or_else(|| {
            ExecuteError::IdentityMismatch(format!(
                "Volume '{}' no longer maps to a basic partition",
                identity.volume_guid
            ))
        })?;
    let size_bytes = windows_volume_known(&facts.total_bytes, "size")?;

    if disk_number != identity.disk_number {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Volume '{}' moved from disk {} to disk {}",
            identity.volume_guid, identity.disk_number, disk_number
        )));
    }
    if partition_number != identity.partition_number {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Volume '{}' moved from partition #{} to #{}",
            identity.volume_guid, identity.partition_number, partition_number
        )));
    }
    if size_bytes != identity.size_bytes {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Volume '{}' size changed from {} to {} bytes",
            identity.volume_guid, identity.size_bytes, size_bytes
        )));
    }

    let (partition, fingerprint) =
        windows_volume_layout_identity(backend, identity.disk_number, identity.partition_number)?;
    if partition.starting_offset != identity.partition_start_bytes {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Partition #{} on disk {} moved from byte {} to byte {}",
            identity.partition_number,
            identity.disk_number,
            identity.partition_start_bytes,
            partition.starting_offset
        )));
    }
    if fingerprint != identity.partition_table_fingerprint {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Partition table of disk {} changed after validation (expected {}, got {})",
            identity.disk_number, identity.partition_table_fingerprint, fingerprint
        )));
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
    })?
    else {
        return Ok(());
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
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
                || name[parent_name.len()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit()))
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

    if !matches!(
        backend.sysfs_class_attr(part_name, "subpartition"),
        Ok(None)
    ) {
        return Ok(true);
    }

    let parent_canonical = backend
        .canonicalize_path(parent_disk, false)
        .unwrap_or_else(|_| parent_disk.to_string());
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
        command_log.push(format!(
            "[DRY RUN] Would check mounts and unmount partition {} and its holders",
            target_partition
        ));
        return Ok((stdout_accum, stderr_accum));
    }

    let target_name = target_partition
        .strip_prefix("/dev/")
        .unwrap_or(target_partition);
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
        let mut holder_mount_point: Option<String> = None;
        let mut is_mounted = false;
        for line in mounts_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() && (parts[0] == holder_dev || parts[0].ends_with(holder)) {
                is_mounted = true;
                holder_mount_point = parts.get(1).map(|m| (*m).to_string());
                break;
            }
        }
        if is_mounted {
            command_log.push(format!(
                "[UNMOUNT] Unmounting active holder: {}",
                holder_dev
            ));
            let (stdout, stderr, code) =
                run_logged_cmd(backend, "umount", &[&holder_dev], command_log)?;
            stdout_accum.push_str(&stdout);
            stderr_accum.push_str(&stderr);
            if code != 0 {
                // Phase-u amendment: plain `umount` (no -f); name the blocking
                // mount point and the umount stderr that explains why the
                // holder could not be unmounted.
                return Err(ExecuteError::CommandFailed(format!(
                    "Target partition {} is held by active holder '{}' which cannot be \
                     unmounted (mounted at {}; umount attempted and failed: {})",
                    target_partition,
                    holder_dev,
                    holder_mount_point
                        .as_deref()
                        .unwrap_or("unknown mount point"),
                    unmount_failure_detail(&stderr),
                )));
            }
        }
    }

    let mut is_target_mounted = false;
    let mut target_mount_point: Option<String> = None;
    for line in mounts_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.is_empty() && (parts[0] == target_partition || parts[0] == target_canonical) {
            is_target_mounted = true;
            target_mount_point = parts.get(1).map(|m| (*m).to_string());
            break;
        }
    }

    if is_target_mounted {
        command_log.push(format!(
            "[UNMOUNT] Unmounting active partition: {}",
            target_partition
        ));
        let (stdout, stderr, code) =
            run_logged_cmd(backend, "umount", &[target_partition], command_log)?;
        stdout_accum.push_str(&stdout);
        stderr_accum.push_str(&stderr);
        if code != 0 {
            // Phase-u amendment: plain `umount` (no -f); report the unmount
            // attempt status, the mount point that is still holding the
            // partition and the umount stderr.
            return Err(ExecuteError::CommandFailed(format!(
                "Failed to unmount partition {}: umount attempted and failed (mounted at {}; \
                 umount stderr: {})",
                target_partition,
                target_mount_point
                    .as_deref()
                    .unwrap_or("unknown mount point"),
                unmount_failure_detail(&stderr),
            )));
        }
    }

    Ok((stdout_accum, stderr_accum))
}

/// Human-readable detail for a failed forced-unmount attempt — `umount` can
/// exit non-zero without printing anything, which must not yield an empty
/// parenthetical in the refusal message.
fn unmount_failure_detail(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        "umount exited non-zero without a message".to_string()
    } else {
        trimmed.to_string()
    }
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
                if let Some(s) = line
                    .strip_prefix("ID_SERIAL_SHORT=")
                    .or_else(|| line.strip_prefix("ID_SERIAL="))
                    .or_else(|| line.strip_prefix("SERIAL="))
                {
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
        size_bytes,
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
    let pinned_size = pinned_device_size(backend, device);
    Ok(ValidatedTarget::sealed(
        guard_identity.canonical_path.clone(),
        guard_identity,
        TargetScope::WholeDisk,
        pinned_size,
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
    let pinned_size = pinned_device_size(backend, &guard_identity.canonical_path);
    Ok(ValidatedTarget::sealed(
        guard_identity.canonical_path.clone(),
        guard_identity,
        TargetScope::WholeDisk,
        pinned_size,
    ))
}

/// P2: geometry snapshot for the pre-tool identity re-check. Best-effort at
/// mint time (fixture backends without sysfs geometry pin `0` = unknown), so
/// no guard path gains a new hard failure here.
fn pinned_device_size(backend: &dyn BlockBackend, canonical_path: &str) -> u64 {
    backend
        .device_geometry(canonical_path)
        .map(|g| g.size_bytes)
        .unwrap_or(0)
}

/// P2: live serial for a whole-device node, when sysfs exposes one.
fn live_device_serial(backend: &dyn BlockBackend, canonical: &str) -> Option<String> {
    let name = canonical.strip_prefix("/dev/").unwrap_or(canonical);
    for attr in &["device/serial", "serial"] {
        if let Ok(Some(content)) = backend.sysfs_class_attr(name, attr) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    for attr in &["device/uevent", "uevent"] {
        if let Ok(Some(uevent)) = backend.sysfs_class_attr(name, attr) {
            for line in uevent.lines() {
                if let Some(s) = line
                    .strip_prefix("ID_SERIAL_SHORT=")
                    .or_else(|| line.strip_prefix("ID_SERIAL="))
                    .or_else(|| line.strip_prefix("SERIAL="))
                {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
    }
    None
}

/// P2: re-validate a guard-minted target **immediately before** a destructive
/// external tool runs. Catches the TOCTOU window between selection/validation
/// and command execution:
///
/// * boot-disk protection is re-evaluated against current mount state,
/// * the node identity (`st_rdev`, inode) must still match the pinned one,
/// * the sysfs serial (when exposed) must still match the confirmed serial,
/// * the device size (when pinned) must be unchanged.
///
/// Skipped in dry-run: no external tool is invoked, so there is nothing to
/// guard. Returns `IdentityMismatch` / `BootDiskProtection` on drift.
pub fn revalidate_target_identity(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
    dry_run: bool,
) -> Result<(), ExecuteError> {
    if dry_run {
        return Ok(());
    }

    let path = target.canonical_path();

    // 1. Boot-disk protection against current mount/swap state.
    check_boot_disk_protection(backend, path, false)?;

    // 2. Same node as the one validated (rdev + inode pinning).
    let stat = backend.stat_path(path).map_err(|e| {
        ExecuteError::IdentityMismatch(format!(
            "Cannot re-stat target {} before firmware command: {}",
            path, e
        ))
    })?;
    let id = target.guard_identity();
    // `libc::dev_t` is u64 on Linux and u32 on Windows: identity conversion on
    // Linux (clippy) and widening on Windows.
    #[allow(clippy::useless_conversion)]
    let pinned_rdev = u64::from(id.st_rdev);
    if stat.is_block != id.is_block
        || stat.rdev != pinned_rdev
        || (id.st_ino != 0 && stat.ino != id.st_ino)
    {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Target {} identity changed after validation (expected rdev {} ino {}, found rdev {} ino {})",
            path, id.st_rdev, id.st_ino, stat.rdev, stat.ino
        )));
    }

    // 3. Serial — only compared when the backend exposes one.
    if !id.device_serial.is_empty() {
        if let Some(live) = live_device_serial(backend, path) {
            if live != id.device_serial {
                return Err(ExecuteError::IdentityMismatch(format!(
                    "Target {} serial changed after validation (expected {}, found {})",
                    path, id.device_serial, live
                )));
            }
        }
    }

    // 4. Size — only compared when geometry was pinned at mint time.
    if target.pinned_size_bytes > 0 {
        let geo = backend.device_geometry(path).map_err(|e| {
            ExecuteError::IdentityMismatch(format!(
                "Cannot re-read geometry for {} before firmware command: {}",
                path, e
            ))
        })?;
        if geo.size_bytes != target.pinned_size_bytes {
            return Err(ExecuteError::IdentityMismatch(format!(
                "Target {} size changed after validation (expected {} bytes, found {})",
                path, target.pinned_size_bytes, geo.size_bytes
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Phase F: post-wipe filesystem recreation guards
// ---------------------------------------------------------------------------

/// `(source, optional major:minor, optional mount point)` fact from the
/// mount/swap state. The mount point (when known) names the blocking mount
/// in refusals so the operator knows exactly what to unmount. Swap has no
/// mount point.
type MountedSourceFact = (String, Option<(u32, u32)>, Option<String>);

/// Source/dev/mount-point facts currently mounted or active as swap.
/// Mountinfo fields: `... major:minor root mount_point options ... - fstype
/// source superopts`; `/proc/mounts` fields: `source mount_point fstype …`.
fn mounted_source_facts(
    backend: &dyn BlockBackend,
) -> Result<Vec<MountedSourceFact>, ExecuteError> {
    let state = backend.read_mount_state().map_err(scan_read_err)?;
    let mut out: Vec<MountedSourceFact> = Vec::new();

    for line in state.mountinfo.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let dev = parse_major_minor(parts[2]);
        let mount_point = Some(parts[4].to_string());
        if let Some(sep) = parts.iter().position(|p| *p == "-") {
            if let Some(source) = parts.get(sep + 2) {
                out.push(((*source).to_string(), dev, mount_point));
            }
        }
    }
    for line in state.mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(source) = parts.first() {
            let mount_point = parts.get(1).map(|m| (*m).to_string());
            out.push((source.to_string(), None, mount_point));
        }
    }
    for line in state.swaps.lines().skip(1) {
        if let Some(source) = line.split_whitespace().next() {
            out.push((source.to_string(), None, None));
        }
    }
    Ok(out)
}

/// Every block device covered by `target`: the target node itself, plus all
/// child partitions when the scope is a whole disk. Used to refuse formatting
/// a disk/partition that still has an active mount (including a sibling
/// partition for whole-disk scope).
fn target_block_names(backend: &dyn BlockBackend, target: &ValidatedTarget) -> Vec<String> {
    let canonical = target.canonical_path();
    let name = canonical
        .strip_prefix("/dev/")
        .unwrap_or(canonical)
        .to_string();
    let mut names = vec![name.clone()];
    if matches!(target.scope(), TargetScope::WholeDisk) {
        for candidate in backend.sysfs_block_names() {
            if candidate != name
                && candidate.starts_with(&name)
                && !matches!(backend.sysfs_class_attr(&candidate, "partition"), Ok(None))
            {
                names.push(candidate);
            }
        }
    }
    names
}

/// Refuse if the validated target (or, for whole-disk scope, any of its
/// partitions) is mounted, held by an active mount, or active as swap.
///
/// This is intentionally stricter than boot-disk protection: boot protection
/// allows mounts under `/mnt`/`/media` to be unmounted, but formatting a
/// mounted filesystem in place is never safe.
pub fn assert_target_not_mounted(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
) -> Result<(), ExecuteError> {
    let sources = mounted_source_facts(backend)?;
    let names = target_block_names(backend, target);
    let id = target.guard_identity();
    let target_dev = (id.major, id.minor);

    for (source, dev, mount_point) in sources {
        let source_name = source.rsplit('/').next().unwrap_or(&source);
        let by_name = names
            .iter()
            .any(|n| n == source_name || source == format!("/dev/{}", n));
        let by_dev = dev == Some(target_dev);
        if by_name || by_dev {
            // P4-fix: name the blocking mount point so the operator knows
            // exactly what must be unmounted first. Swap has no mount point.
            return Err(ExecuteError::TargetMounted(match mount_point {
                Some(mp) => format!(
                    "{} is mounted/active as '{}' (mounted at {})",
                    target.canonical_path(),
                    source,
                    mp
                ),
                None => format!(
                    "{} is mounted/active as '{}'",
                    target.canonical_path(),
                    source
                ),
            }));
        }
    }
    Ok(())
}

/// Refuse a target that belongs to the running system / live medium. The
/// shared boot-disk protection chain owns the policy (normal/live/container,
/// swaps, holders); this wrapper only re-types its refusal for the format
/// step so callers get a precise error.
pub fn assert_target_not_system_partition(
    backend: &dyn BlockBackend,
    target: &ValidatedTarget,
) -> Result<(), ExecuteError> {
    match check_boot_disk_protection(backend, target.canonical_path(), false) {
        Ok(()) => Ok(()),
        Err(ExecuteError::BootDiskProtection(msg)) => Err(ExecuteError::SystemPartition(msg)),
        Err(other) => Err(other),
    }
}

/// F2: after a partition-scope wipe, the table fingerprint captured at
/// validation time must still be identical. Any drift is a hard failure.
pub fn assert_partition_table_unchanged(
    backend: &dyn BlockBackend,
    scope: &TargetScope,
    expected_fingerprint: &str,
) -> Result<String, ExecuteError> {
    let TargetScope::Partition { parent_name, .. } = scope else {
        return Err(ExecuteError::FilesystemScopeMismatch(
            "partition-table assertion requires partition scope".to_string(),
        ));
    };
    let current = compute_partition_table_fingerprint(backend, parent_name)?;
    if current != expected_fingerprint {
        return Err(ExecuteError::IdentityMismatch(format!(
            "Partition table changed during the wipe: expected fingerprint {}, got {}",
            expected_fingerprint, current
        )));
    }
    Ok(current)
}

// ---------------------------------------------------------------------------
// Legacy adapter: the historic `ValidatedPartitionTarget` view (kept for API
// compatibility; the sealed ValidatedTarget above is the write gate).
// ---------------------------------------------------------------------------

impl ValidatedTarget {
    /// Project onto the legacy struct used by existing execution paths.
    pub fn to_legacy_partition_target(&self) -> Option<ValidatedPartitionTarget> {
        match &self.scope {
            TargetScope::WholeDisk | TargetScope::Volume { .. } => None,
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

#[cfg(test)]
mod windows_volume_tests {
    use super::*;
    use crate::backend::mock::MockBackend;
    use crate::backend::windows_parse::{ParsedPartition, PartitionStyle};
    use crate::backend::{
        BackendCapabilities, BitLockerLockState, ExclusiveHandle, HandleReader, VolumeDriveType,
        VolumeFact, WindowsVolumeFacts,
    };
    use crate::types::{BlockWriter, GuardIdentity};
    use std::io;

    const GUID_E: &str = r"\\?\Volume{11111111-1111-1111-1111-111111111111}\";
    const BASIC_DATA_GUID: &str = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
    const SIZE_32GB: u64 = 32_000_000_000;

    fn volume_facts(
        guid: &str,
        letter: char,
        label: &str,
        disk: u32,
        part: u32,
        size: u64,
        drive_type: VolumeDriveType,
    ) -> WindowsVolumeFacts {
        WindowsVolumeFacts {
            volume_guid_path: guid.to_string(),
            mount_points: VolumeFact::Known(vec![format!("{}:\\", letter)]),
            drive_letters: VolumeFact::Known(vec![letter]),
            label: VolumeFact::Known(Some(label.to_string())),
            filesystem: VolumeFact::Known(Some("NTFS".to_string())),
            total_bytes: VolumeFact::Known(size),
            free_bytes: VolumeFact::Known(size / 2),
            drive_type: VolumeFact::Known(drive_type),
            extent_count: VolumeFact::Known(1),
            disk_number: VolumeFact::Known(Some(disk)),
            partition_number: VolumeFact::Known(Some(part)),
            is_bitlocker: VolumeFact::Known(false),
            bitlocker_state: BitLockerLockState::NotEncrypted,
            is_system_volume: VolumeFact::Known(false),
            hosts_running_app: VolumeFact::Known(false),
        }
    }

    fn removable_volume() -> WindowsVolumeFacts {
        volume_facts(
            GUID_E,
            'E',
            "BACKUP",
            1,
            1,
            SIZE_32GB,
            VolumeDriveType::Removable,
        )
    }

    fn basic_layout(part: u32, start: u64, len: u64) -> ParsedDriveLayout {
        ParsedDriveLayout {
            style: PartitionStyle::Gpt,
            partitions: vec![ParsedPartition {
                partition_number: part,
                starting_offset: start,
                partition_length: len,
                start_sector: start / 512,
                size_sectors: len / 512,
                partition_type_guid: Some(BASIC_DATA_GUID.to_string()),
                partition_type_mbr: None,
            }],
        }
    }

    fn boot_facts_with(
        elevated: bool,
        system_disks: Vec<u32>,
        pagefile_volumes: Vec<String>,
        hibernation_volumes: Vec<String>,
        crashdump_volumes: Vec<String>,
    ) -> WindowsBootFacts {
        WindowsBootFacts {
            system_disks: DiskSetFact::known(system_disks),
            boot_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            pagefile_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            hibernation_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            crashdump_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            app_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            pagefile_volumes: VolumeGuidSetFact::known(pagefile_volumes),
            hibernation_volumes: VolumeGuidSetFact::known(hibernation_volumes),
            crashdump_volumes: VolumeGuidSetFact::known(crashdump_volumes),
            elevated: ElevationFact::Known(elevated),
        }
    }

    fn boot_facts(system_disks: Vec<u32>) -> WindowsBootFacts {
        boot_facts_with(true, system_disks, Vec::new(), Vec::new(), Vec::new())
    }

    fn backend_for(
        volume: &WindowsVolumeFacts,
        boot: WindowsBootFacts,
        disk: u32,
        layout: ParsedDriveLayout,
        transport: Option<&str>,
    ) -> MockBackend {
        let size = volume.total_bytes.as_known().copied().unwrap_or(SIZE_32GB);
        let guid = volume.volume_guid_path.clone();
        MockBackend::new()
            .with_capabilities(BackendCapabilities::full())
            .with_windows_boot_facts(boot)
            .with_windows_volumes(vec![volume.clone()])
            .with_windows_disk_layout(disk, layout)
            .with_windows_device(disk, transport)
            .with_geometry(&guid, size, 512)
    }

    fn params_for(volume: &WindowsVolumeFacts) -> WindowsVolumeTargetParams {
        WindowsVolumeTargetParams {
            volume_guid: volume.volume_guid_path.clone(),
            confirmation_token: windows_volume_confirmation_token(volume)
                .unwrap_or_else(|_| "E: FALLBACK 1.0GB".to_string()),
            same_disk_confirmation: None,
        }
    }

    fn validate_with(
        volume: WindowsVolumeFacts,
        boot: WindowsBootFacts,
        layout: ParsedDriveLayout,
        transport: Option<&str>,
        mutate_params: impl FnOnce(&mut WindowsVolumeTargetParams),
    ) -> Result<ValidatedTarget, ExecuteError> {
        let disk = volume
            .disk_number
            .as_known()
            .copied()
            .flatten()
            .unwrap_or(1);
        let backend = backend_for(&volume, boot, disk, layout, transport);
        let mut params = params_for(&volume);
        mutate_params(&mut params);
        validate_windows_volume_target(&backend, &params)
    }

    fn assert_refused(
        result: Result<ValidatedTarget, ExecuteError>,
        predicate: impl Fn(&ExecuteError) -> bool,
        label: &str,
    ) {
        match result {
            Err(error) => assert!(
                predicate(&error),
                "{} was refused with the wrong error: {:?}",
                label,
                error
            ),
            Ok(_) => panic!("{} should have been refused", label),
        }
    }

    #[test]
    fn windows_volume_positive_removable() {
        let volume = removable_volume();
        let backend = backend_for(
            &volume,
            boot_facts(vec![0]),
            1,
            basic_layout(1, 1_048_576, SIZE_32GB),
            Some("usb"),
        );
        let target = validate_windows_volume_target(&backend, &params_for(&volume))
            .expect("removable volume must validate");

        match target.scope() {
            TargetScope::Volume {
                disk_number,
                partition_number,
                start_bytes,
                size_bytes,
                volume_guid,
                drive_letter,
                logical_block_size,
            } => {
                assert_eq!(*disk_number, 1);
                assert_eq!(*partition_number, 1);
                assert_eq!(*start_bytes, 0);
                assert_eq!(*size_bytes, SIZE_32GB);
                assert_eq!(volume_guid, GUID_E);
                assert_eq!(*drive_letter, 'E');
                assert_eq!(*logical_block_size, 512);
            }
            other => panic!("expected Volume scope, got {:?}", other),
        }

        let identity = target.windows_volume_identity().expect("identity pinned");
        assert_eq!(identity.disk_number, 1);
        assert_eq!(identity.partition_number, 1);
        assert_eq!(identity.partition_start_bytes, 1_048_576);
        assert_eq!(identity.size_bytes, SIZE_32GB);
        assert_eq!(identity.volume_guid, GUID_E);
        assert_eq!(
            identity.partition_table_fingerprint,
            compute_windows_partition_fingerprint(
                &basic_layout(1, 1_048_576, SIZE_32GB).partitions
            )
        );
        assert_eq!(target.windows_warnings(), WindowsVolumeWarnings::default());
    }

    #[test]
    fn windows_volume_inspection_exposes_tokens_and_warnings() {
        let volume = removable_volume();
        let backend = backend_for(
            &volume,
            boot_facts(vec![1]),
            1,
            basic_layout(1, 1_048_576, SIZE_32GB),
            Some("usb"),
        );
        let inspection =
            inspect_windows_volume_target(&backend, GUID_E).expect("inspection must succeed");
        assert_eq!(inspection.required_confirmation, "E: BACKUP 32.0GB");
        assert_eq!(
            inspection.required_same_disk_confirmation.as_deref(),
            Some("SAME DISK E: BACKUP 32.0GB")
        );
        assert!(inspection.warnings.same_disk_as_system);
        assert!(!inspection.warnings.bitlocker_unlocked);
        assert_eq!(inspection.identity.size_bytes, SIZE_32GB);
        assert_eq!(inspection.identity.volume_guid, GUID_E);
        assert_eq!(inspection.drive_letter, 'E');
    }

    #[test]
    fn windows_volume_resolution_by_drive_letter() {
        let volume = removable_volume();
        let backend = backend_for(
            &volume,
            boot_facts(vec![0]),
            1,
            basic_layout(1, 1_048_576, SIZE_32GB),
            Some("usb"),
        );
        assert_eq!(
            resolve_windows_volume_target(&backend, "E:").expect("E: must resolve"),
            GUID_E
        );
        assert_eq!(
            resolve_windows_volume_target(&backend, "e").expect("e must resolve"),
            GUID_E
        );
        assert_eq!(
            resolve_windows_volume_target(&backend, GUID_E).expect("GUID must resolve"),
            GUID_E
        );
        assert!(matches!(
            resolve_windows_volume_target(&backend, "Z:"),
            Err(ExecuteError::DeviceNotFound(_))
        ));
        assert!(matches!(
            resolve_windows_volume_target(&backend, "  "),
            Err(ExecuteError::DeviceNotFound(_))
        ));
    }

    #[test]
    fn windows_volume_refuses_unelevated() {
        let volume = removable_volume();
        let result = validate_with(
            volume,
            boot_facts_with(false, vec![0], vec![], vec![], vec![]),
            basic_layout(1, 1_048_576, SIZE_32GB),
            Some("usb"),
            |_| {},
        );
        assert_refused(
            result,
            |e| matches!(e, ExecuteError::WindowsVolumeNotElevated(_)),
            "unelevated process",
        );
    }

    #[test]
    fn windows_volume_refuses_missing_drive_letter() {
        let mut volume = removable_volume();
        volume.drive_letters = VolumeFact::Known(Vec::new());
        volume.mount_points = VolumeFact::Known(Vec::new());
        let result = validate_with(
            volume,
            boot_facts(vec![0]),
            basic_layout(1, 1_048_576, SIZE_32GB),
            Some("usb"),
            |_| {},
        );
        assert_refused(
            result,
            |e| matches!(e, ExecuteError::WindowsVolumeNoDriveLetter(_)),
            "volume without a drive letter",
        );
    }

    #[test]
    fn windows_volume_refuses_non_local_drive_type() {
        for drive_type in [
            VolumeDriveType::Remote,
            VolumeDriveType::CdRom,
            VolumeDriveType::RamDisk,
            VolumeDriveType::NoRootDir,
            VolumeDriveType::Unknown,
            VolumeDriveType::Other(42),
        ] {
            let mut volume = removable_volume();
            volume.drive_type = VolumeFact::Known(drive_type);
            assert_refused(
                validate_with(
                    volume,
                    boot_facts(vec![0]),
                    basic_layout(1, 1_048_576, SIZE_32GB),
                    Some("usb"),
                    |_| {},
                ),
                |e| matches!(e, ExecuteError::WindowsVolumeNotBasic(_)),
                &format!("drive type {:?}", drive_type),
            );
        }

        let mut unreadable = removable_volume();
        unreadable.drive_type = VolumeFact::Unreadable("mock: denied".to_string());
        assert_refused(
            validate_with(
                unreadable,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeNotBasic(_)),
            "unreadable drive type",
        );
    }

    #[test]
    fn windows_volume_refuses_system_and_app_volumes() {
        let mut system = removable_volume();
        system.is_system_volume = VolumeFact::Known(true);
        assert_refused(
            validate_with(
                system,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeProtected(_)),
            "system volume",
        );

        let mut app = removable_volume();
        app.hosts_running_app = VolumeFact::Known(true);
        assert_refused(
            validate_with(
                app,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeProtected(_)),
            "running-app volume",
        );

        let mut unreadable = removable_volume();
        unreadable.is_system_volume = VolumeFact::Unreadable("mock: denied".to_string());
        assert_refused(
            validate_with(
                unreadable,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeProtected(_)),
            "unreadable system flag",
        );
    }

    #[test]
    fn windows_volume_refuses_active_windows_files() {
        for (name, boot) in [
            (
                "page file",
                boot_facts_with(true, vec![0], vec![GUID_E.to_string()], vec![], vec![]),
            ),
            (
                "hibernation file",
                boot_facts_with(true, vec![0], vec![], vec![GUID_E.to_string()], vec![]),
            ),
            (
                "crash dump",
                boot_facts_with(true, vec![0], vec![], vec![], vec![GUID_E.to_string()]),
            ),
        ] {
            assert_refused(
                validate_with(
                    removable_volume(),
                    boot,
                    basic_layout(1, 1_048_576, SIZE_32GB),
                    Some("usb"),
                    |_| {},
                ),
                |e| matches!(e, ExecuteError::WindowsVolumeInUse(_)),
                name,
            );
        }

        let mut boot = boot_facts(vec![0]);
        boot.pagefile_volumes = VolumeGuidSetFact::Unreadable("mock: denied".to_string());
        assert_refused(
            validate_with(
                removable_volume(),
                boot,
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeInUse(_)),
            "unreadable page-file volume fact",
        );
    }

    #[test]
    fn windows_volume_refuses_multi_extent_and_unknown_mapping() {
        let mut multi = removable_volume();
        multi.extent_count = VolumeFact::Known(2);
        multi.disk_number = VolumeFact::Known(None);
        multi.partition_number = VolumeFact::Known(None);
        assert_refused(
            validate_with(
                multi,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeNotBasic(_)),
            "multi-extent volume",
        );

        let mut no_disk = removable_volume();
        no_disk.disk_number = VolumeFact::Known(None);
        assert_refused(
            validate_with(
                no_disk,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeNotBasic(_)),
            "unknown disk number",
        );

        let mut no_partition = removable_volume();
        no_partition.partition_number = VolumeFact::Known(None);
        assert_refused(
            validate_with(
                no_partition,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeNotBasic(_)),
            "unknown partition number",
        );

        let mut unreadable = removable_volume();
        unreadable.extent_count = VolumeFact::Unreadable("mock: denied".to_string());
        assert_refused(
            validate_with(
                unreadable,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeNotBasic(_)),
            "unreadable extent count",
        );
    }

    #[test]
    fn windows_volume_refuses_dynamic_disk() {
        let mut layout = basic_layout(1, 1_048_576, SIZE_32GB);
        layout.style = PartitionStyle::Mbr;
        layout.partitions[0].partition_type_guid = None;
        layout.partitions[0].partition_type_mbr = Some(0x42);
        assert_refused(
            validate_with(
                removable_volume(),
                boot_facts(vec![0]),
                layout,
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeNotBasic(_)),
            "dynamic disk",
        );
    }

    #[test]
    fn windows_volume_refuses_storage_spaces_and_virtual_disks() {
        for transport in ["spaces", "virtual"] {
            assert_refused(
                validate_with(
                    removable_volume(),
                    boot_facts(vec![0]),
                    basic_layout(1, 1_048_576, SIZE_32GB),
                    Some(transport),
                    |_| {},
                ),
                |e| matches!(e, ExecuteError::WindowsVolumeNotBasic(_)),
                transport,
            );
        }

        // Unknown transport is a refusal, not an implicit "physical".
        assert_refused(
            validate_with(
                removable_volume(),
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                None,
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeNotBasic(_)),
            "unknown transport",
        );
    }

    #[test]
    fn windows_volume_refuses_locked_and_unknown_bitlocker() {
        for state in [
            BitLockerLockState::Locked,
            BitLockerLockState::Unknown("mock: cannot classify".to_string()),
        ] {
            let mut volume = removable_volume();
            volume.bitlocker_state = state.clone();
            assert_refused(
                validate_with(
                    volume,
                    boot_facts(vec![0]),
                    basic_layout(1, 1_048_576, SIZE_32GB),
                    Some("usb"),
                    |_| {},
                ),
                |e| matches!(e, ExecuteError::WindowsVolumeBitLockerLocked(_)),
                &format!("BitLocker state {:?}", state),
            );
        }
    }

    #[test]
    fn windows_volume_allows_unlocked_bitlocker_with_warning() {
        let mut volume = removable_volume();
        volume.is_bitlocker = VolumeFact::Known(true);
        volume.bitlocker_state = BitLockerLockState::Unlocked;
        let target = validate_with(
            volume,
            boot_facts(vec![0]),
            basic_layout(1, 1_048_576, SIZE_32GB),
            Some("usb"),
            |_| {},
        )
        .expect("unlocked BitLocker volume must validate");
        let warnings = target.windows_warnings();
        assert!(warnings.bitlocker_unlocked);
        assert!(!warnings.same_disk_as_system);
    }

    #[test]
    fn windows_volume_refuses_unreadable_or_unaligned_geometry() {
        let mut unreadable = removable_volume();
        unreadable.total_bytes = VolumeFact::Unreadable("mock: denied".to_string());
        assert_refused(
            validate_with(
                unreadable,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeGeometry(_)),
            "unreadable volume size",
        );

        let mut unaligned = removable_volume();
        unaligned.total_bytes = VolumeFact::Known(1_000);
        assert_refused(
            validate_with(
                unaligned,
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeGeometry(_)),
            "size not a multiple of the logical block size",
        );
    }

    #[test]
    fn windows_volume_size_token_units() {
        assert_eq!(format_windows_volume_size(29_800_000_000), "29.8GB");
        assert_eq!(format_windows_volume_size(500_107_862_016), "500.1GB");
        assert_eq!(format_windows_volume_size(1_000_000_000_000), "1.0TB");
        assert_eq!(format_windows_volume_size(1_500_000_000_000), "1.5TB");
        assert_eq!(format_windows_volume_size(999_999_999), "1.0GB");
        assert_eq!(format_windows_volume_size(999_950), "1.0MB");
        assert_eq!(format_windows_volume_size(1_000), "1.0KB");
        assert_eq!(format_windows_volume_size(999), "999B");
        assert_eq!(format_windows_volume_size(0), "0B");

        // The exact example format from the Step 1.3 specification.
        let volume = volume_facts(
            GUID_E,
            'E',
            "BACKUP",
            1,
            1,
            29_800_000_000,
            VolumeDriveType::Removable,
        );
        assert_eq!(
            windows_volume_confirmation_token(&volume).unwrap(),
            "E: BACKUP 29.8GB"
        );
    }

    #[test]
    fn windows_volume_requires_the_exact_confirmation_token() {
        let volume = removable_volume();
        assert_eq!(
            windows_volume_confirmation_token(&volume).unwrap(),
            "E: BACKUP 32.0GB"
        );

        // Case-insensitive letter and size unit; lower-case label is a
        // different label and must be refused.
        for token in ["e: BACKUP 32.0gb", "  E:  BACKUP   32.0GB  "] {
            let result = validate_with(
                volume.clone(),
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |params| params.confirmation_token = token.to_string(),
            );
            assert!(result.is_ok(), "token {:?} should be accepted", token);
        }

        for token in [
            "e: backup 32.0GB",
            "E: BACKUP 32.1GB",
            "E: 32.0GB",
            "F: BACKUP 32.0GB",
        ] {
            let result = validate_with(
                volume.clone(),
                boot_facts(vec![0]),
                basic_layout(1, 1_048_576, SIZE_32GB),
                Some("usb"),
                |params| params.confirmation_token = token.to_string(),
            );
            assert_refused(
                result,
                |e| matches!(e, ExecuteError::ConfirmationMismatch),
                token,
            );
        }

        // A volume without a label uses the NO_LABEL placeholder.
        let mut unlabeled = volume;
        unlabeled.label = VolumeFact::Known(None);
        assert_eq!(
            windows_volume_confirmation_token(&unlabeled).unwrap(),
            "E: NO_LABEL 32.0GB"
        );
    }

    #[test]
    fn windows_volume_same_disk_requires_extra_confirmation() {
        let volume = removable_volume();
        let layout = basic_layout(1, 1_048_576, SIZE_32GB);

        // Same disk as the system volume, no extra token -> refuse.
        assert_refused(
            validate_with(
                volume.clone(),
                boot_facts(vec![1]),
                layout.clone(),
                Some("usb"),
                |_| {},
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeSameDiskConfirmation(_)),
            "same-disk volume without confirmation",
        );

        // Wrong extra token -> refuse.
        assert_refused(
            validate_with(
                volume.clone(),
                boot_facts(vec![1]),
                layout.clone(),
                Some("usb"),
                |params| params.same_disk_confirmation = Some("SAME DISK E: OTHER 32.0GB".into()),
            ),
            |e| matches!(e, ExecuteError::WindowsVolumeSameDiskConfirmation(_)),
            "same-disk volume with wrong confirmation",
        );

        // Correct extra token -> allowed with the warning flag.
        let target = validate_with(
            volume.clone(),
            boot_facts(vec![1]),
            layout,
            Some("usb"),
            |params| {
                params.same_disk_confirmation =
                    Some(windows_volume_same_disk_token(&volume).unwrap())
            },
        )
        .expect("same-disk volume with confirmation must validate");
        assert!(target.windows_warnings().same_disk_as_system);
        assert!(!target.windows_warnings().bitlocker_unlocked);
    }

    #[test]
    fn windows_volume_revalidation_detects_drift() {
        let volume = removable_volume();
        let backend = backend_for(
            &volume,
            boot_facts(vec![0]),
            1,
            basic_layout(1, 1_048_576, SIZE_32GB),
            Some("usb"),
        );
        let target = validate_windows_volume_target(&backend, &params_for(&volume))
            .expect("fixture volume must validate");
        revalidate_windows_volume_identity(&backend, &target)
            .expect("unchanged identity must pass");

        // Size drift.
        let mut resized = volume.clone();
        resized.total_bytes = VolumeFact::Known(SIZE_32GB + 4096);
        let backend = backend_for(
            &resized,
            boot_facts(vec![0]),
            1,
            basic_layout(1, 1_048_576, SIZE_32GB),
            Some("usb"),
        );
        assert!(matches!(
            revalidate_windows_volume_identity(&backend, &target),
            Err(ExecuteError::IdentityMismatch(_))
        ));

        // Partition-table drift (same volume, moved partition).
        let backend = backend_for(
            &volume,
            boot_facts(vec![0]),
            1,
            basic_layout(1, 2_097_152, SIZE_32GB),
            Some("usb"),
        );
        assert!(matches!(
            revalidate_windows_volume_identity(&backend, &target),
            Err(ExecuteError::IdentityMismatch(_))
        ));

        // Volume disappeared.
        let backend = MockBackend::new().with_windows_boot_facts(boot_facts(vec![0]));
        assert!(matches!(
            revalidate_windows_volume_identity(&backend, &target),
            Err(ExecuteError::IdentityMismatch(_))
        ));
    }

    struct CountingWriter {
        writes: usize,
        total: u64,
    }

    impl BlockWriter for CountingWriter {
        fn write_chunk(&mut self, _offset: u64, data: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            Ok(data.len())
        }
        fn sync_data(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn flush_buffers(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn total_size(&self) -> io::Result<u64> {
            Ok(self.total)
        }
        fn io_mode(&self) -> &'static str {
            "raw"
        }
    }

    struct EmptyReader;

    impl HandleReader for EmptyReader {
        fn read_at(&self, _offset: u64, len: usize) -> io::Result<Vec<u8>> {
            Ok(vec![0u8; len])
        }
    }

    #[test]
    fn volume_scope_write_at_is_bounded() {
        let size = 4096u64;
        let target = ValidatedTarget::sealed_windows_volume(
            GUID_E.to_string(),
            GuardIdentity {
                canonical_path: GUID_E.to_string(),
                st_rdev: 0,
                major: 0,
                minor: 0,
                is_block: true,
                device_serial: GUID_E.to_string(),
                st_ino: 0,
            },
            TargetScope::Volume {
                disk_number: 1,
                partition_number: 1,
                start_bytes: 0,
                size_bytes: size,
                volume_guid: GUID_E.to_string(),
                drive_letter: 'E',
                logical_block_size: 512,
            },
            WindowsVolumeIdentity {
                disk_number: 1,
                partition_number: 1,
                partition_start_bytes: 1_048_576,
                size_bytes: size,
                volume_guid: GUID_E.to_string(),
                partition_table_fingerprint: "fixture".to_string(),
            },
            WindowsVolumeWarnings::default(),
        );
        let mut handle = ExclusiveHandle::new(
            target,
            GUID_E.to_string(),
            "raw",
            512,
            Box::new(CountingWriter {
                writes: 0,
                total: size,
            }),
            Box::new(EmptyReader),
            None,
        );

        assert_eq!(handle.write_at(0, &[0u8; 512]).unwrap(), 512);
        assert_eq!(handle.write_at(size - 512, &[0u8; 512]).unwrap(), 512);
        assert!(handle.write_at(size - 1, &[0u8; 2]).is_err());
        assert!(handle.write_at(size, &[0u8; 1]).is_err());
        assert!(handle.write_at(u64::MAX, &[0u8; 2]).is_err());
    }
}
