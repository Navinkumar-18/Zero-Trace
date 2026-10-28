//! C1: platform abstraction — `BlockBackend`.
//!
//! Design contract (Phase C hard rules):
//!
//! * **Backends report facts; the shared guard chain decides.** No safety
//!   decision may live behind this interface. Every fact the guard chain
//!   consumes is a trait method; the *policy* built on those facts
//!   (boot-disk protection, live/normal/container rules, partition
//!   validation, fingerprint invariance, confirmation) lives in
//!   [`crate::guard`] — shared, platform-neutral code.
//! * **Writes require a [`ValidatedTarget`](crate::guard::ValidatedTarget).**
//!   [`BlockBackend::open_exclusive`] only accepts a target minted by the
//!   guard chain (private constructor), so bypassing the guard fails to
//!   compile — see the `compile_fail` proof on that type.
//! * **Errors, never panics.** Unsupported operations return
//!   [`BackendError::Unsupported`]; stub backends (Windows, Android) refuse
//!   everything.
//!
//! Implementations:
//! * `backend::linux::LinuxBackend` — the only real backend (cfg linux).
//! * `backend::windows` / `backend::android` — compile-only stubs.
//! * `backend::mock::MockBackend` — in-memory test backend with fault
//!   injection; must pass the shared conformance suite in
//!   `backend::conformance`.

pub mod android;
pub mod conformance;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod mock;
pub mod unsupported;
pub mod windows;
pub mod windows_parse;

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::guard::ValidatedTarget;
use crate::types::{BlockWriter, BootEnvironment, ExecuteError};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed backend errors. `Unsupported` is the stub-backend refusal; guard
/// decisions surface as `ExecuteError` at the guard layer, not here.
///
/// C2a note: no `Clone`/`PartialEq`/`Eq` — the `OpenFailed` carrier holds an
/// `ExecuteError` (io errors and messages are not cloneable/comparable), and
/// nothing compares backend errors by value.
#[derive(Debug)]
pub enum BackendError {
    /// The backend (or platform) does not support this operation at all.
    Unsupported(&'static str),
    /// A fact could not be read (missing file, unreadable sysfs, ...).
    Unavailable(String),
    /// The underlying I/O failed.
    Io(String),
    /// `open_exclusive` delegates device opening to shared writer-opening
    /// code whose typed errors (boot-disk protection, identity mismatch,
    /// not-found, ...) carry safety meaning. The variant is carried verbatim
    /// so callers see the exact historic `ExecuteError` (C2a: lossless).
    OpenFailed(ExecuteError),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::Unsupported(what) => write!(f, "Unsupported operation: {}", what),
            BackendError::Unavailable(msg) => write!(f, "Unavailable: {}", msg),
            BackendError::Io(msg) => write!(f, "I/O error: {}", msg),
            // Display delegates to the historic error so messages are unchanged.
            BackendError::OpenFailed(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for BackendError {}

impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        BackendError::Io(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Capability flags (C1 / C6 / C7)
// ---------------------------------------------------------------------------

/// What the platform can actually do. Consumed by the Dart UI to disable
/// unsupported actions with a reason (never silently hidden) and recorded on
/// certificates (C7, additive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub raw_write: bool,
    pub discard: bool,
    pub secure_erase: bool,
    pub sanitize: bool,
    pub nvme_format: bool,
    pub partition_scope: bool,
    pub live_mode_possible: bool,
    pub supports_system_volume: bool,
}

impl BackendCapabilities {
    /// Stub platforms (Windows, Android): refuse everything.
    pub const fn unsupported() -> Self {
        Self {
            raw_write: false,
            discard: false,
            secure_erase: false,
            sanitize: false,
            nvme_format: false,
            partition_scope: false,
            live_mode_possible: false,
            supports_system_volume: false,
        }
    }

    /// Every capability enabled (Linux: the engine gates per-operation).
    pub const fn full() -> Self {
        Self {
            raw_write: true,
            discard: true,
            secure_erase: true,
            sanitize: true,
            nvme_format: true,
            partition_scope: true,
            live_mode_possible: true,
            supports_system_volume: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Fact types reported by backends
// ---------------------------------------------------------------------------

/// Raw mount/swap state. Content strings (not parsed records) so the shared
/// guard chain owns parsing — including strictness and error messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountState {
    /// Content of the resolved mountinfo file (self/mountinfo → mountinfo →
    /// mounts fallback chain resolved by the backend).
    pub mountinfo: String,
    /// Content of the mounts file (empty when absent).
    pub mounts: String,
    /// Content of /proc/swaps (empty when absent).
    pub swaps: String,
}

/// Identity facts of a path (fstat equivalent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatFact {
    pub rdev: u64,
    pub ino: u64,
    pub is_block: bool,
    pub is_regular: bool,
}

/// Sysfs relation between block devices (holder/slave graph edges).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    Holders,
    Slaves,
}

/// Whole-device geometry facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceGeometry {
    pub size_bytes: u64,
    pub logical_block_size: u32,
}

/// Discovery facts (C1 `enumerate_devices` / `enumerate_partitions`).
/// The Linux backend fills these from the same probing the Dart layer uses;
/// stub backends return `Unsupported`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub size_bytes: u64,
    pub is_removable: bool,
    pub is_rotational: bool,
    pub transport: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionFacts {
    pub name: String,
    pub partition_number: u32,
    pub start_sector: u64,
    pub size_sectors: u64,
    pub fs_type: Option<String>,
    pub label: Option<String>,
}

/// A set of Windows disk numbers reported by a backend.
///
/// D-a piece 2: this is a **fact**, not a decision. `Known` always carries a
/// sorted, duplicate-free snapshot (a volume that spans several disks lists
/// every member); `Unreadable` is an exists-but-unreadable reason that the
/// shared guard must refuse on. A backend never converts an unreadable fact
/// into an empty set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskSetFact {
    Known(Vec<u32>),
    Unreadable(String),
}

impl DiskSetFact {
    /// Build a `Known` fact with deterministic (sorted, unique) contents.
    pub fn known<I: IntoIterator<Item = u32>>(disks: I) -> Self {
        let mut disks: Vec<u32> = disks.into_iter().collect();
        disks.sort_unstable();
        disks.dedup();
        Self::Known(disks)
    }

    pub fn unreadable(reason: impl Into<String>) -> Self {
        Self::Unreadable(reason.into())
    }

    /// Known disks, or `None` when the fact is unreadable.
    pub fn disks(&self) -> Option<&[u32]> {
        match self {
            Self::Known(disks) => Some(disks),
            Self::Unreadable(_) => None,
        }
    }

    pub fn is_unreadable(&self) -> bool {
        matches!(self, Self::Unreadable(_))
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Known(_) => None,
            Self::Unreadable(reason) => Some(reason),
        }
    }
}

/// Whether the process token is elevated (`TOKEN_QUERY` + `TokenElevation`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElevationFact {
    Known(bool),
    Unreadable(String),
}

impl ElevationFact {
    pub fn is_elevated(&self) -> Option<bool> {
        match self {
            Self::Known(value) => Some(*value),
            Self::Unreadable(_) => None,
        }
    }

    pub fn is_unreadable(&self) -> bool {
        matches!(self, Self::Unreadable(_))
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Known(_) => None,
            Self::Unreadable(reason) => Some(reason),
        }
    }
}

/// Windows boot/system facts consumed by the shared guard chain (D-a piece 2).
///
/// Every field is either a known set of disk numbers or a typed unreadable
/// reason. A volume spanning multiple disks is represented by every member
/// disk. The guard refuses a target when it matches any set **or** when any
/// fact is unreadable; elevation is recorded here because future write paths
/// require an elevated token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsBootFacts {
    /// Disk(s) holding `GetSystemWindowsDirectoryW` (the Windows directory).
    pub system_disks: DiskSetFact,
    /// Disk(s) holding the boot volume (`%SystemDrive%`).
    pub boot_disks: DiskSetFact,
    /// Disk(s) holding active page files from `PagingFiles`.
    pub pagefile_disks: DiskSetFact,
    /// Disk(s) holding `hiberfil.sys` when hibernation is enabled.
    pub hibernation_disks: DiskSetFact,
    /// Disk(s) holding the configured crash-dump / minidump targets.
    pub crashdump_disks: DiskSetFact,
    /// Disk(s) holding this executable and its application data directory.
    pub app_disks: DiskSetFact,
    /// Whether the current process token is elevated (`TokenElevation`).
    pub elevated: ElevationFact,
}

// ---------------------------------------------------------------------------
// Exclusive handle (C1: write primitives exist ONLY on a handle, and a
// handle can only be created from a guard-validated target)
// ---------------------------------------------------------------------------

/// Read side of an exclusive handle (verification sampling).
pub trait HandleReader: Send + Sync {
    fn read_at(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>>;
}

/// An exclusively-opened target. Constructed only via
/// [`BlockBackend::open_exclusive`], which requires a guard-minted
/// [`ValidatedTarget`]; `write_at`/`flush` live here and nowhere else.
pub struct ExclusiveHandle {
    target: ValidatedTarget,
    path: String,
    io_mode: &'static str,
    logical_block_size: u32,
    writer: Box<dyn BlockWriter>,
    reader: Box<dyn HandleReader>,
    /// Raw fd of the writer where the backend exposes one (Linux);
    /// `None` for memory-backed backends (mock) and platforms without fds.
    raw_fd: Option<i32>,
}

impl ExclusiveHandle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: ValidatedTarget,
        path: String,
        io_mode: &'static str,
        logical_block_size: u32,
        writer: Box<dyn BlockWriter>,
        reader: Box<dyn HandleReader>,
        raw_fd: Option<i32>,
    ) -> Self {
        Self {
            target,
            path,
            io_mode,
            logical_block_size,
            writer,
            reader,
            raw_fd,
        }
    }

    /// Guard-minted target backing this handle.
    pub fn target(&self) -> &ValidatedTarget {
        &self.target
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn io_mode(&self) -> &'static str {
        self.io_mode
    }

    pub fn logical_block_size(&self) -> u32 {
        self.logical_block_size
    }

    pub fn total_size(&self) -> std::io::Result<u64> {
        self.writer.total_size()
    }

    /// Write at `offset` — **absolute device byte offset**, bounds-enforced
    /// against the validated scope: a partition-scoped handle refuses any
    /// write outside `[start_bytes, start_bytes + size_bytes)`, so it can
    /// never touch the partition table or sibling partitions.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> std::io::Result<usize> {
        if let crate::guard::TargetScope::Partition {
            start_bytes,
            size_bytes,
            ..
        } = self.target.scope()
        {
            let end = offset.checked_add(data.len() as u64).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "offset overflow")
            })?;
            let lo = *start_bytes;
            let hi = start_bytes.checked_add(*size_bytes).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "scope overflow")
            })?;
            if offset < lo || end > hi {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "write [{}..{}) outside validated partition range [{}..{}) for {}",
                        offset, end, lo, hi, self.path
                    ),
                ));
            }
        }
        self.writer.write_chunk(offset, data)
    }

    /// Durability barrier: fsync + cache flush.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.sync_data()?;
        self.writer.flush_buffers()
    }

    /// Read back through the handle (verification sampling).
    pub fn read_at(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        self.reader.read_at(offset, len)
    }

    /// Raw fd of the writer, when the backend exposes one. Legacy device
    /// ioctl flows (BLKDISCARD) use this to issue commands on the very fd
    /// opened through this handle instead of re-opening the device (C2a).
    pub fn raw_fd(&self) -> Option<i32> {
        self.raw_fd
    }

    /// Flush device buffers only (BLKFLSBUF on the handle's fd) — no fsync.
    pub fn flush_buffers_only(&mut self) -> std::io::Result<()> {
        self.writer.flush_buffers()
    }
}

/// C2a: the handle itself is a `BlockWriter` so legacy execution loops
/// (`execute_writer_overwrite`, `PartitionRangeWriter`) consume it directly
/// without any code outside `backend/` touching the device.
///
/// Coordinate note: legacy loops write **node-relative** offsets on the fd
/// they opened (whole-disk node: absolute; partition node: partition-
/// relative), which is exactly what the inner writer receives here. The
/// validated-scope gate lives on [`ExclusiveHandle::write_at`] (the C1
/// shared interface, parent-disk coordinates) and on the callers' own
/// bounds guards (`PartitionRangeWriter`, kernel node capacity) — the
/// adapter adds no translation, preserving byte-identical legacy behavior.
impl BlockWriter for ExclusiveHandle {
    fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<usize, std::io::Error> {
        self.writer.write_chunk(offset, data)
    }

    fn sync_data(&mut self) -> Result<(), std::io::Error> {
        self.writer.sync_data()
    }

    fn flush_buffers(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush_buffers()
    }

    fn total_size(&self) -> Result<u64, std::io::Error> {
        self.writer.total_size()
    }

    fn logical_block_size(&self) -> u32 {
        self.logical_block_size
    }

    fn io_mode(&self) -> &'static str {
        self.io_mode
    }
}

// ---------------------------------------------------------------------------
// The trait (C1)
// ---------------------------------------------------------------------------

/// Platform disk-access primitives. See module docs for the contract.
pub trait BlockBackend {
    /// Stable backend identifier ("linux", "windows", "android", "mock").
    fn name(&self) -> &'static str;
    /// Platform token for certificates/detect output ("linux", ...).
    fn platform(&self) -> &'static str;
    fn capabilities(&self) -> BackendCapabilities;

    // -- Discovery ---------------------------------------------------------

    fn enumerate_devices(&self) -> Result<Vec<DeviceInfo>, BackendError>;
    fn enumerate_partitions(&self, device: &str) -> Result<Vec<PartitionFacts>, BackendError>;

    // -- Facts consumed by the shared guard chain --------------------------

    fn read_mount_state(&self) -> Result<MountState, BackendError>;
    /// Content of `<proc>/self/mountinfo` only — `None` when absent. The
    /// pre-write recheck uses this exact file (no fallback chain), keeping
    /// historic fail-open-if-missing semantics for that one path.
    fn mountinfo_self(&self) -> Result<Option<String>, BackendError>;
    /// Content of `<proc>/mounts` read directly (missing/unreadable → empty),
    /// as used by the unmount flow — independent of the mountinfo chain.
    fn mounts_file(&self) -> String;
    fn boot_environment(&self) -> Result<BootEnvironment, ExecuteError>;
    /// Windows boot/system facts for the shared disk-refusal policy (D-a
    /// piece 2). `Ok(None)` means "not applicable on this platform" — only
    /// `WindowsBackend` returns `Some`. A field that exists but cannot be
    /// read must be `Unreadable`, never an empty set (the guard fail-closes).
    fn windows_boot_facts(&self) -> Result<Option<WindowsBootFacts>, BackendError> {
        Ok(None)
    }
    fn canonicalize_path(&self, path: &str, dry_run: bool) -> Result<String, ExecuteError>;
    /// `class/block/<name>/<attr_rel>` content (e.g. `partition`, `start`,
    /// `size`, `dev`, `uevent`, `device/serial`, `queue/logical_block_size`).
    ///
    /// `Ok(None)` = attribute absent; `Err` = attribute exists but could not
    /// be read (fail-closed sites distinguish this — see `guard`).
    fn sysfs_class_attr(
        &self,
        block_name: &str,
        attr_rel: &str,
    ) -> Result<Option<String>, BackendError>;
    fn sysfs_block_names(&self) -> Vec<String>;
    fn sysfs_block_exists(&self, name: &str) -> bool;
    /// Whether `class/block/<name>/partition` exists — existence semantics
    /// (an existing-but-unreadable attribute still counts), derived from the
    /// strict attribute read.
    fn sysfs_is_partition(&self, name: &str) -> bool {
        !matches!(self.sysfs_class_attr(name, "partition"), Ok(None))
    }
    /// `read_link` target of `class/block/<name>` (parent-disk heuristic).
    fn sysfs_parent_link(&self, name: &str) -> Option<String>;
    /// Holder/slave names of `class/block/<name>/<relation>/`. C2c: `Ok(vec![])`
    /// means the relation dir is absent (historic skip); an **unreadable**
    /// dir is `Err` — the guard fail-closes instead of skipping.
    fn sysfs_related_names(
        &self,
        name: &str,
        relation: Relation,
    ) -> Result<Vec<String>, BackendError>;
    /// All member device names under `sys/fs/btrfs/<uuid>/devices/*`. C2c:
    /// absent sysfs tree → `Ok(vec![])`; unreadable tree → `Err` (fail closed).
    fn btrfs_member_devices(&self) -> Result<Vec<String>, BackendError>;
    /// Display path of the sysfs class/block dir (error messages embed it).
    fn sysfs_root_display(&self) -> String;
    /// Backend's view of a device file path for raw reads (e.g. MBR probe):
    /// injected `dev_root` join on fixture contexts (`device` = original
    /// `/dev/...` argument), canonical path otherwise — matching the historic
    /// `is_mbr_extended_partition` logic exactly.
    fn device_file_path(&self, device: &str, canonical: &str) -> PathBuf;
    /// Backing device (major, minor) of a plain file — swap-file resolution.
    /// Returns `None` for fixture/injected contexts (matching the historic
    /// `proc_root == "/proc"` gate).
    fn stat_backing_device(&self, path: &str) -> Option<(u32, u32)>;
    /// Raw read from a device/file path (MBR probes, volume headers).
    fn read_raw(&self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>, BackendError>;
    /// fstat facts of a path.
    fn stat_path(&self, path: &str) -> Result<StatFact, BackendError>;
    /// `O_EXCL` open probe (EBUSY → typed error, fstat, close).
    /// `canonical_path` is opened; `device` is the original display name used
    /// in error messages (historic behavior).
    fn probe_exclusive_open(
        &self,
        canonical_path: &str,
        device: &str,
    ) -> Result<StatFact, ExecuteError>;
    /// Run an external command (umount, ...). The shared guard chain owns
    /// logging and interpretation; backends only execute.
    fn exec(&self, program: &str, args: &[&str]) -> Result<(String, String, i32), BackendError>;
    /// Device geometry composed from sysfs facts (default: identical for
    /// every sysfs-reporting backend; stubs override to `Unsupported`).
    fn device_geometry(&self, target: &str) -> Result<DeviceGeometry, BackendError> {
        let name = target.strip_prefix("/dev/").unwrap_or(target);
        let size_sectors: u64 = self
            .sysfs_class_attr(name, "size")?
            .unwrap_or_default()
            .trim()
            .parse()
            .map_err(|_| BackendError::Unavailable(format!("Corrupt sysfs size for {}", name)))?;
        let logical_block_size: u32 = self
            .sysfs_class_attr(name, "queue/logical_block_size")?
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(512);
        Ok(DeviceGeometry {
            size_bytes: size_sectors * 512,
            logical_block_size,
        })
    }

    // -- Actions -----------------------------------------------------------

    /// Unmount every mount whose source is the validated target — composed
    /// from `mounts_file` + `exec` facts (shared logic; stubs override to
    /// `Unsupported`).
    fn unmount(&self, target: &ValidatedTarget) -> Result<(), BackendError> {
        let canonical = target.canonical_path();
        let name = canonical.rsplit('/').next().unwrap_or(canonical);
        let mounts = self.mounts_file();
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let src = parts[0];
            let src_name = src.rsplit('/').next().unwrap_or(src);
            if src == canonical || src_name == name {
                let (_, stderr, code) = self.exec("umount", &["-f", src])?;
                if code != 0 {
                    return Err(BackendError::Io(format!(
                        "umount failed for {}: {}",
                        src, stderr
                    )));
                }
            }
        }
        Ok(())
    }

    /// Exclusive open of a guard-validated target. THE write gate.
    fn open_exclusive(&self, target: &ValidatedTarget) -> Result<ExclusiveHandle, BackendError>;
    /// Read back through a handle (verification sampling) — identical
    /// delegation for every backend.
    fn read_at(
        &self,
        handle: &ExclusiveHandle,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, BackendError> {
        handle
            .read_at(offset, len)
            .map_err(|e| BackendError::Io(e.to_string()))
    }
    fn discard_range(
        &self,
        handle: &ExclusiveHandle,
        offset: u64,
        len: u64,
    ) -> Result<(), BackendError>;

    /// F2: ask the kernel to re-read the partition table after a wipe/format.
    /// Partition-scoped targets re-read the parent disk (so the partition
    /// appears again); whole-disk targets re-read the device itself. This
    /// only re-reads — it never modifies the table.
    fn reread_partition_table(&self, _target: &ValidatedTarget) -> Result<(), BackendError> {
        Err(BackendError::Unsupported("partition-table re-read"))
    }
}

/// C5: the process-wide backend selector. Linux gets the only real backend;
/// Windows/Android get compile-only stubs that refuse everything.
pub fn current_backend() -> Box<dyn BlockBackend> {
    #[cfg(target_os = "linux")]
    {
        Box::new(crate::backend::linux::LinuxBackend::system())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(crate::backend::windows::windows_backend())
    }
    #[cfg(target_os = "android")]
    {
        Box::new(crate::backend::android::android_backend())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
    {
        // Unknown platforms behave like the stubs: refuse everything.
        Box::new(crate::backend::unsupported::UnsupportedBackend::new(
            "unknown-platform",
            "unknown",
        ))
    }
}
