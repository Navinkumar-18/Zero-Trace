//! C5: generic compile-only stub backend — **refuses every operation**.
//!
//! Shared by the Windows and Android stubs (and unknown targets): every
//! fact/action returns [`BackendError::Unsupported`] (or the typed
//! `ExecuteError::UnsupportedOperation` for guard-facing facts) and
//! [`BackendCapabilities`] are all `false`. Nothing here ever touches
//! hardware, files or processes.

use std::path::PathBuf;

use crate::backend::{
    BackendCapabilities, BackendError, BlockBackend, DeviceGeometry, DeviceInfo, ExclusiveHandle,
    MountState, PartitionFacts, StatFact,
};
use crate::guard::ValidatedTarget;
use crate::types::{BootEnvironment, ExecuteError};

/// Backend id / platform of a stub that refuses everything.
pub struct UnsupportedBackend {
    id: &'static str,
    platform: &'static str,
}

impl UnsupportedBackend {
    pub const fn new(id: &'static str, platform: &'static str) -> Self {
        Self { id, platform }
    }
}

macro_rules! unsupported {
    ($e:expr) => {
        Err(BackendError::Unsupported($e))
    };
}

impl BlockBackend for UnsupportedBackend {
    fn name(&self) -> &'static str {
        self.id
    }

    fn platform(&self) -> &'static str {
        self.platform
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::unsupported()
    }

    // -- Discovery ---------------------------------------------------------

    fn enumerate_devices(&self) -> Result<Vec<DeviceInfo>, BackendError> {
        unsupported!("device enumeration")
    }

    fn enumerate_partitions(&self, _device: &str) -> Result<Vec<PartitionFacts>, BackendError> {
        unsupported!("partition enumeration")
    }

    // -- Facts -------------------------------------------------------------

    fn read_mount_state(&self) -> Result<MountState, BackendError> {
        unsupported!("mount state")
    }

    fn mountinfo_self(&self) -> Result<Option<String>, BackendError> {
        unsupported!("mountinfo")
    }

    fn mounts_file(&self) -> String {
        String::new()
    }

    fn boot_environment(&self) -> Result<BootEnvironment, ExecuteError> {
        Err(ExecuteError::UnsupportedOperation(
            "boot environment detection on this platform".into(),
        ))
    }

    fn canonicalize_path(&self, _path: &str, _dry_run: bool) -> Result<String, ExecuteError> {
        Err(ExecuteError::UnsupportedOperation(
            "path canonicalization on this platform".into(),
        ))
    }

    fn sysfs_class_attr(
        &self,
        _block_name: &str,
        _attr_rel: &str,
    ) -> Result<Option<String>, BackendError> {
        unsupported!("sysfs attributes")
    }

    /// Stubs report no sysfs facts at all — override the existence-deriving
    /// default (which treats read errors as "exists" for fail-closed Linux
    /// semantics; a stub has nothing to fail closed on).
    fn sysfs_is_partition(&self, _name: &str) -> bool {
        false
    }

    fn sysfs_block_names(&self) -> Vec<String> {
        Vec::new()
    }

    fn sysfs_block_exists(&self, _name: &str) -> bool {
        false
    }

    fn sysfs_parent_link(&self, _name: &str) -> Option<String> {
        None
    }

    fn sysfs_related_names(
        &self,
        _name: &str,
        _relation: crate::backend::Relation,
    ) -> Result<Vec<String>, crate::backend::BackendError> {
        Ok(Vec::new())
    }

    fn btrfs_member_devices(&self) -> Result<Vec<String>, crate::backend::BackendError> {
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
        unsupported!("raw reads")
    }

    fn stat_path(&self, _path: &str) -> Result<StatFact, BackendError> {
        unsupported!("stat")
    }

    fn probe_exclusive_open(
        &self,
        _canonical_path: &str,
        device: &str,
    ) -> Result<StatFact, ExecuteError> {
        Err(ExecuteError::UnsupportedOperation(format!(
            "exclusive open of {} on this platform",
            device
        )))
    }

    fn exec(&self, _program: &str, _args: &[&str]) -> Result<(String, String, i32), BackendError> {
        unsupported!("command execution")
    }

    fn device_geometry(&self, _target: &str) -> Result<DeviceGeometry, BackendError> {
        unsupported!("device geometry")
    }

    // -- Actions -----------------------------------------------------------

    fn unmount(&self, _target: &ValidatedTarget) -> Result<(), BackendError> {
        unsupported!("unmount")
    }

    fn open_exclusive(&self, _target: &ValidatedTarget) -> Result<ExclusiveHandle, BackendError> {
        unsupported!("exclusive write access")
    }

    fn discard_range(
        &self,
        _handle: &ExclusiveHandle,
        _offset: u64,
        _len: u64,
    ) -> Result<(), BackendError> {
        unsupported!("discard")
    }
}
