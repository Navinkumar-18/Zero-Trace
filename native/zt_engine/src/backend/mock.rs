//! C4: the in-memory test backend.
//!
//! [`MockBackend`] implements [`BlockBackend`] entirely from configurable
//! maps — devices, partitions, mount/swap state, boot environment, exec
//! results — plus **fault injection** (write error, short write, device
//! shrink via attribute mutation, busy unmount, fingerprint change,
//! unreadable sysfs, busy O_EXCL). It backs the shared conformance suite in
//! [`crate::backend::conformance`] so the same guard-chain tests can run
//! against any future backend.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};

use crate::backend::{
    BackendCapabilities, BackendError, BlockBackend, ExclusiveHandle, HandleReader, MountState,
    PartitionFacts, Relation, StatFact,
};
use crate::guard::ValidatedTarget;
use crate::types::{BlockWriter, BootEnvironment, ExecuteError};

/// Configurable write faults for handles opened through this backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WriteFault {
    /// Writes behave normally.
    #[default]
    None,
    /// Every write fails (I/O error).
    Error,
    /// Writes succeed for at most `n` bytes then report a short write.
    ShortWrite(usize),
}

/// In-memory [`BlockBackend`]. Facts come from maps; actions mutate the
/// shared in-memory device image.
pub struct MockBackend {
    id: &'static str,
    platform: &'static str,
    capabilities: BackendCapabilities,

    mountinfo: Option<String>,
    mounts: String,
    swaps: String,
    boot_env: BootEnvironment,

    canonical: HashMap<String, String>,
    attrs: HashMap<String, HashMap<String, String>>,
    /// `<block>/<attr>` pairs that exist but cannot be read (fail-closed
    /// sites must see a read error, not an absent attribute).
    unreadable: HashSet<String>,
    parents: HashMap<String, String>,
    holders: HashMap<String, Vec<String>>,
    slaves: HashMap<String, Vec<String>>,
    btrfs_members: Vec<String>,
    file_backing: HashMap<String, (u32, u32)>,
    raw_files: HashMap<String, Vec<u8>>,
    stats: HashMap<String, StatFact>,
    exec_results: HashMap<String, (String, String, i32)>,
    /// O_EXCL probe failure injection (busy device).
    exclusive_busy: bool,

    /// Shared device image backing handles opened by this backend.
    data: Arc<Mutex<Vec<u8>>>,
    write_fault: WriteFault,
    logical_block_size: u32,
}

fn makedev(major: u32, minor: u32) -> u64 {
    ((major as u64) << 8) | (minor as u64)
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            id: "mock",
            platform: "mock",
            capabilities: BackendCapabilities::full(),
            mountinfo: None,
            mounts: String::new(),
            swaps: String::new(),
            boot_env: BootEnvironment::Normal,
            canonical: HashMap::new(),
            attrs: HashMap::new(),
            unreadable: HashSet::new(),
            parents: HashMap::new(),
            holders: HashMap::new(),
            slaves: HashMap::new(),
            btrfs_members: Vec::new(),
            file_backing: HashMap::new(),
            raw_files: HashMap::new(),
            stats: HashMap::new(),
            exec_results: HashMap::new(),
            exclusive_busy: false,
            data: Arc::new(Mutex::new(Vec::new())),
            write_fault: WriteFault::None,
            logical_block_size: 512,
        }
    }

    // -- Builders ----------------------------------------------------------

    pub fn with_id(mut self, id: &'static str) -> Self {
        self.id = id;
        self
    }

    pub fn with_capabilities(mut self, caps: BackendCapabilities) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn with_mountinfo(mut self, content: &str) -> Self {
        self.mountinfo = Some(content.to_string());
        self
    }

    pub fn with_mounts(mut self, content: &str) -> Self {
        self.mounts = content.to_string();
        self
    }

    pub fn with_swaps(mut self, content: &str) -> Self {
        self.swaps = content.to_string();
        self
    }

    pub fn with_boot_env(mut self, env: BootEnvironment) -> Self {
        self.boot_env = env;
        self
    }

    /// Register a whole-disk block device (sysfs `dev` attr + `/dev/<name>`
    /// canonicalization + stat identity).
    pub fn add_block(mut self, name: &str, major: u32, minor: u32) -> Self {
        self.attrs
            .entry(name.to_string())
            .or_default()
            .insert("dev".to_string(), format!("{}:{}", major, minor));
        self.canonical
            .insert(format!("/dev/{}", name), format!("/dev/{}", name));
        self.stats.insert(
            format!("/dev/{}", name),
            StatFact {
                rdev: makedev(major, minor),
                ino: 1000 + stats_ino(name),
                is_block: true,
                is_regular: false,
            },
        );
        self
    }

    /// Register a partition under `parent` with sysfs geometry and parent
    /// link (the guard chain's parent-resolution path).
    #[allow(clippy::too_many_arguments)]
    pub fn add_partition(
        mut self,
        name: &str,
        parent: &str,
        number: u32,
        start_sectors: u64,
        size_sectors: u64,
        major: u32,
        minor: u32,
    ) -> Self {
        let attrs = self.attrs.entry(name.to_string()).or_default();
        attrs.insert("partition".to_string(), number.to_string());
        attrs.insert("start".to_string(), start_sectors.to_string());
        attrs.insert("size".to_string(), size_sectors.to_string());
        attrs.insert("dev".to_string(), format!("{}:{}", major, minor));
        self.parents.insert(name.to_string(), parent.to_string());
        self.canonical
            .insert(format!("/dev/{}", name), format!("/dev/{}", name));
        self.stats.insert(
            format!("/dev/{}", name),
            StatFact {
                rdev: makedev(major, minor),
                ino: 1000 + stats_ino(name),
                is_block: true,
                is_regular: false,
            },
        );
        self
    }

    /// Explicit path canonicalization (symlink-style aliases).
    pub fn canonicalize_map(mut self, from: &str, to: &str) -> Self {
        self.canonical.insert(from.to_string(), to.to_string());
        self
    }

    /// Override/add a raw sysfs attribute (e.g. `queue/logical_block_size`).
    pub fn set_attr(mut self, block: &str, attr: &str, value: &str) -> Self {
        self.attrs
            .entry(block.to_string())
            .or_default()
            .insert(attr.to_string(), value.to_string());
        self
    }

    /// Mark an attribute as existing-but-unreadable (fail-closed sites).
    pub fn with_unreadable_attr(mut self, block: &str, attr: &str) -> Self {
        self.unreadable.insert(format!("{}/{}", block, attr));
        self
    }

    /// File-backed swap: `(major, minor)` returned for `stat_backing_device`.
    pub fn with_file_backing(mut self, path: &str, major: u32, minor: u32) -> Self {
        self.file_backing
            .insert(path.to_string(), (major, minor));
        self
    }

    /// Register a dm/holder edge (`block` has holder `holder` in sysfs).
    pub fn with_holder(mut self, block: &str, holder: &str) -> Self {
        self.holders
            .entry(block.to_string())
            .or_default()
            .push(holder.to_string());
        self
    }

    pub fn with_raw_file(mut self, path: &str, bytes: Vec<u8>) -> Self {
        self.raw_files.insert(path.to_string(), bytes);
        self
    }

    /// Scripted exec result for `"program arg1 arg2"`; default exit 0.
    pub fn with_exec_result(
        mut self,
        cmd: &str,
        stdout: &str,
        stderr: &str,
        code: i32,
    ) -> Self {
        self.exec_results.insert(
            cmd.to_string(),
            (stdout.to_string(), stderr.to_string(), code),
        );
        self
    }

    /// Make the O_EXCL probe report a busy device.
    pub fn with_exclusive_busy(mut self) -> Self {
        self.exclusive_busy = true;
        self
    }

    /// Size the shared device image to `len` zero bytes.
    pub fn with_device_size(mut self, len: usize) -> Self {
        self.data = Arc::new(Mutex::new(vec![0u8; len]));
        self
    }

    pub fn with_write_fault(mut self, fault: WriteFault) -> Self {
        self.write_fault = fault;
        self
    }

    pub fn with_logical_block_size(mut self, lbs: u32) -> Self {
        self.logical_block_size = lbs;
        self
    }

    // -- Introspection for tests ------------------------------------------

    /// Snapshot of the shared device image.
    pub fn data(&self) -> Vec<u8> {
        self.data.lock().unwrap().clone()
    }

    /// Truncate the shared device image (device-shrink fault).
    pub fn shrink_device_to(&self, len: usize) {
        self.data.lock().unwrap().truncate(len);
    }

    /// Mutate a sysfs attribute **while the backend is still owned** — the
    /// "device shrink" / "partition-table fingerprint change" fault for
    /// re-validation after parameters were captured.
    pub fn mutate_attr(&mut self, block: &str, attr: &str, value: &str) {
        self.attrs
            .entry(block.to_string())
            .or_default()
            .insert(attr.to_string(), value.to_string());
    }
}

fn stats_ino(name: &str) -> u64 {
    name.bytes().map(|b| b as u64).sum()
}

// ---------------------------------------------------------------------------
// Writers / readers over the shared image
// ---------------------------------------------------------------------------

struct MockWriter {
    data: Arc<Mutex<Vec<u8>>>,
    fault: WriteFault,
}

impl BlockWriter for MockWriter {
    fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<usize, io::Error> {
        match self.fault {
            WriteFault::Error => Err(io::Error::other("mock write fault (injected)")),
            WriteFault::ShortWrite(max) => {
                let n = max.min(data.len());
                self.write_at(offset, &data[..n])?;
                Ok(n)
            }
            WriteFault::None => {
                self.write_at(offset, data)?;
                Ok(data.len())
            }
        }
    }

    fn sync_data(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    fn flush_buffers(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    fn total_size(&self) -> Result<u64, io::Error> {
        Ok(self.data.lock().unwrap().len() as u64)
    }

    fn io_mode(&self) -> &'static str {
        "mock"
    }
}

impl MockWriter {
    /// Absolute-offset write into the image; never extends past the device
    /// end (fail closed, like a real block device).
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        let mut buf = self.data.lock().unwrap();
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        if end > buf.len() as u64 {
            return Err(io::Error::other(format!(
                "mock: write [{}..{}) beyond device end {}",
                offset,
                end,
                buf.len()
            )));
        }
        let start = offset as usize;
        buf[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }
}

struct MockReader {
    data: Arc<Mutex<Vec<u8>>>,
}

impl HandleReader for MockReader {
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let buf = self.data.lock().unwrap();
        if offset as usize >= buf.len() {
            return Ok(Vec::new());
        }
        let start = offset as usize;
        let end = (start + len).min(buf.len());
        Ok(buf[start..end].to_vec())
    }
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

impl BlockBackend for MockBackend {
    fn name(&self) -> &'static str {
        self.id
    }

    fn platform(&self) -> &'static str {
        self.platform
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities
    }

    fn enumerate_devices(&self) -> Result<Vec<crate::backend::DeviceInfo>, BackendError> {
        if self.capabilities == BackendCapabilities::unsupported() {
            return Err(BackendError::Unsupported("device enumeration"));
        }
        let mut out = Vec::new();
        for name in self.attrs.keys() {
            if self.parents.contains_key(name) {
                continue;
            }
            out.push(crate::backend::DeviceInfo {
                name: name.clone(),
                model: None,
                serial: None,
                size_bytes: 0,
                is_removable: false,
                is_rotational: false,
                transport: None,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn enumerate_partitions(&self, device: &str) -> Result<Vec<PartitionFacts>, BackendError> {
        let parent = device.strip_prefix("/dev/").unwrap_or(device);
        let mut out: Vec<PartitionFacts> = Vec::new();
        for (name, attrs) in &self.attrs {
            if self.parents.get(name).map(String::as_str) != Some(parent) {
                continue;
            }
            let number: u32 = attrs
                .get("partition")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let start_sector: u64 = attrs
                .get("start")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let size_sectors: u64 = attrs
                .get("size")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            out.push(PartitionFacts {
                name: name.clone(),
                partition_number: number,
                start_sector,
                size_sectors,
                fs_type: None,
                label: None,
            });
        }
        out.sort_by_key(|p| p.partition_number);
        Ok(out)
    }

    fn read_mount_state(&self) -> Result<MountState, BackendError> {
        let mountinfo = self
            .mountinfo
            .clone()
            .ok_or_else(|| {
                BackendError::Unavailable("No mountinfo or mounts file found: fail closed".to_string())
            })?;
        Ok(MountState {
            mountinfo,
            mounts: self.mounts.clone(),
            swaps: self.swaps.clone(),
        })
    }

    fn mountinfo_self(&self) -> Result<Option<String>, BackendError> {
        Ok(self.mountinfo.clone())
    }

    fn mounts_file(&self) -> String {
        self.mounts.clone()
    }

    fn boot_environment(&self) -> Result<BootEnvironment, ExecuteError> {
        Ok(self.boot_env)
    }

    fn canonicalize_path(&self, path: &str, dry_run: bool) -> Result<String, ExecuteError> {
        if dry_run {
            return Ok(path.to_string());
        }
        if let Some(canon) = self.canonical.get(path) {
            return Ok(canon.clone());
        }
        Err(ExecuteError::DeviceNotFound(format!(
            "Cannot resolve device path {}",
            path
        )))
    }

    fn sysfs_class_attr(
        &self,
        block_name: &str,
        attr_rel: &str,
    ) -> Result<Option<String>, BackendError> {
        let key = format!("{}/{}", block_name, attr_rel);
        if self.unreadable.contains(&key) {
            return Err(BackendError::Io("mock: attribute exists but is unreadable".into()));
        }
        Ok(self
            .attrs
            .get(block_name)
            .and_then(|m| m.get(attr_rel))
            .cloned())
    }

    fn sysfs_block_names(&self) -> Vec<String> {
        self.attrs.keys().cloned().collect()
    }

    fn sysfs_block_exists(&self, name: &str) -> bool {
        self.attrs.contains_key(name)
    }

    fn sysfs_parent_link(&self, name: &str) -> Option<String> {
        self.parents.get(name).cloned()
    }

    fn sysfs_related_names(&self, name: &str, relation: Relation) -> Vec<String> {
        match relation {
            Relation::Holders => self.holders.get(name).cloned().unwrap_or_default(),
            Relation::Slaves => self.slaves.get(name).cloned().unwrap_or_default(),
        }
    }

    fn btrfs_member_devices(&self) -> Vec<String> {
        self.btrfs_members.clone()
    }

    fn sysfs_root_display(&self) -> String {
        "<mock-sysfs>".to_string()
    }

    fn device_file_path(&self, device: &str, canonical: &str) -> std::path::PathBuf {
        // Fixture-style behavior: raw files are keyed by their /dev path.
        let _ = canonical;
        std::path::PathBuf::from(device)
    }

    fn stat_backing_device(&self, path: &str) -> Option<(u32, u32)> {
        self.file_backing.get(path).cloned()
    }

    fn read_raw(&self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>, BackendError> {
        let file = self.raw_files.get(path).ok_or_else(|| {
            BackendError::Io(format!("mock: no such file {}", path))
        })?;
        let start = offset as usize;
        let end = start.checked_add(len as usize).ok_or_else(|| {
            BackendError::Io("mock: read overflow".to_string())
        })?;
        if end > file.len() {
            return Err(BackendError::Io(
                "mock: failed to fill whole buffer".to_string(),
            ));
        }
        Ok(file[start..end].to_vec())
    }

    fn stat_path(&self, path: &str) -> Result<StatFact, BackendError> {
        self.stats.get(path).copied().ok_or_else(|| {
            BackendError::Io(format!("mock: cannot stat {}", path))
        })
    }

    fn probe_exclusive_open(
        &self,
        _canonical_path: &str,
        device: &str,
    ) -> Result<StatFact, ExecuteError> {
        if self.exclusive_busy {
            return Err(ExecuteError::CommandFailed(format!(
                "the system remounted the drive, retry (Device {} is busy or mounted with O_EXCL conflict)",
                device
            )));
        }
        Ok(StatFact {
            rdev: 0,
            ino: 0,
            is_block: true,
            is_regular: false,
        })
    }

    fn exec(&self, program: &str, args: &[&str]) -> Result<(String, String, i32), BackendError> {
        let cmd = format!("{} {}", program, args.join(" "));
        let (out, err, code) = self
            .exec_results
            .get(&cmd)
            .cloned()
            .unwrap_or_else(|| (String::new(), String::new(), 0));
        Ok((out, err, code))
    }

    fn open_exclusive(&self, target: &ValidatedTarget) -> Result<ExclusiveHandle, BackendError> {
        if !self.capabilities.raw_write {
            return Err(BackendError::Unsupported("mock: raw_write disabled"));
        }
        let path = target.canonical_path().to_string();
        let writer = MockWriter {
            data: self.data.clone(),
            fault: self.write_fault,
        };
        let reader = MockReader {
            data: self.data.clone(),
        };
        Ok(ExclusiveHandle::new(
            target.clone(),
            path,
            "mock",
            self.logical_block_size,
            Box::new(writer),
            Box::new(reader),
        ))
    }

    fn discard_range(
        &self,
        _handle: &ExclusiveHandle,
        _offset: u64,
        _len: u64,
    ) -> Result<(), BackendError> {
        if !self.capabilities.discard {
            return Err(BackendError::Unsupported("mock: discard disabled"));
        }
        Ok(())
    }
}
