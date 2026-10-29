//! C4: the shared **backend conformance suite**.
//!
//! Every backend must pass these checks — they exercise the *shared* guard
//! chain ([`crate::guard`]) purely through [`BlockBackend`] facts, so the
//! same suite runs against `MockBackend` (here), `LinuxBackend` (fixture
//! test below + the engine's full historic test suite), and — when their
//! targets are built — the Windows/Android stubs via [`stubs_refuse_everything`].
//!
//! Each function returns `Ok(())` on conformance and `Err(description)`
//! otherwise. Fixture requirements are documented per function; the unit
//! tests below construct a standard fixture (`sda` = protected boot disk,
//! `sdb`/`sdb1` = wipe target).

use crate::backend::mock::MockBackend;
use crate::backend::BlockBackend;
use crate::guard::{self, TargetScope};
use crate::types::{ExecuteError, PartitionTargetParams};

const SERIAL: &str = "CONFORMANCE-SERIAL";

/// Standard fixture: internal boot disk `sda` (8:0, root mounted), wipe
/// target `sdb` (16:0) with one partition `sdb1` (16:1, 2048..6144 sectors),
/// 8 MiB in-memory image, mountinfo rooted on `/dev/sda`.
pub fn mock_fixture() -> MockBackend {
    MockBackend::new()
        .with_id("conformance-mock")
        .with_mountinfo("25 30 8:0 / / rw,relatime shared:1 - ext4 /dev/sda rw\n")
        .with_mounts("")
        .with_swaps("")
        .add_block("sda", 8, 0)
        .add_partition("sda1", "sda", 1, 2048, 4096, 8, 1)
        .add_block("sdb", 16, 0)
        .add_partition("sdb1", "sdb", 1, 2048, 4096, 16, 1)
        .with_device_size(8 * 1024 * 1024)
}

/// Expected `PartitionTargetParams` for `device` — computes the partition
/// table fingerprint from the backend's own facts (call BEFORE any fault
/// injection to capture a pre-fault expectation).
pub fn partition_params(
    backend: &dyn BlockBackend,
    device: &str,
    expected_num: u32,
    expected_start: u64,
    expected_size: u64,
) -> Result<PartitionTargetParams, String> {
    let parent = guard::resolve_parent_disk(backend, device).map_err(|e| e.to_string())?;
    let fingerprint =
        guard::compute_partition_table_fingerprint(backend, &parent).map_err(|e| e.to_string())?;
    Ok(PartitionTargetParams {
        expected_partition_num: expected_num,
        expected_start_sector: expected_start,
        expected_size_sectors: expected_size,
        expected_partuuid: None,
        expected_table_fingerprint: fingerprint,
    })
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

/// Refuses the protected boot disk (name- and major:minor-based).
pub fn refuses_boot_disk(backend: &dyn BlockBackend, target: &str) -> Result<(), String> {
    match guard::check_boot_disk_protection(backend, target, false) {
        Err(ExecuteError::BootDiskProtection(msg)) => {
            if msg.contains("protected") || msg.contains("Refusing") {
                Ok(())
            } else {
                Err(format!("wrong BootDiskProtection message: {}", msg))
            }
        }
        other => Err(format!("expected BootDiskProtection, got {:?}", other)),
    }
}

/// Never proceeds without the typed confirmation token (A5).
pub fn refuses_confirmation_mismatch(
    backend: &dyn BlockBackend,
    target: &str,
    serial: &str,
) -> Result<(), String> {
    match guard::validate_whole_disk_target(backend, target, "NOT-THE-SERIAL", serial, false) {
        Err(ExecuteError::ConfirmationMismatch) => Ok(()),
        other => Err(format!(
            "expected ConfirmationMismatch, got {:?}",
            other.map(|_| ())
        )),
    }
}

/// A correct token on a non-protected disk mints a `ValidatedTarget`
/// (whole-disk scope) — the only input `open_exclusive` accepts.
/// `dry_run` is passed through so fixture backends (whose canonical `/dev`
/// paths don't exist on the host) can exercise the gate without the identity
/// stat — exactly like the historic dry-run flows.
pub fn mints_confirmed_whole_disk_target(
    backend: &dyn BlockBackend,
    target: &str,
    serial: &str,
    dry_run: bool,
) -> Result<(), String> {
    let vt = guard::validate_whole_disk_target(backend, target, serial, serial, dry_run)
        .map_err(|e| format!("expected a validated target, got error: {}", e))?;
    if vt.scope() != &TargetScope::WholeDisk {
        return Err(format!("expected WholeDisk scope, got {:?}", vt.scope()));
    }
    if vt.device_serial() != serial {
        return Err("serial not pinned on the validated target".to_string());
    }
    Ok(())
}

/// Container/overlay root without live markers → refuse everything (A3b).
pub fn refuses_container_environment(
    backend: &dyn BlockBackend,
    target: &str,
) -> Result<(), String> {
    match guard::check_boot_disk_protection(backend, target, false) {
        Err(ExecuteError::BootDiskProtection(msg)) if msg.contains("Container") => Ok(()),
        other => Err(format!("expected container refusal, got {:?}", other)),
    }
}

/// Live-boot overlay root must NOT trip the anonymous-device fail-closed
/// rule for `/` itself (A3b live rule) — the target disk stays usable.
pub fn live_root_stays_usable(backend: &dyn BlockBackend, target: &str) -> Result<(), String> {
    guard::check_boot_disk_protection(backend, target, false)
        .map(|_| ())
        .map_err(|e| format!("live root should not block target: {}", e))
}

/// Active swap partitions are protected regardless of mount state.
pub fn refuses_active_swap(backend: &dyn BlockBackend, swap_target: &str) -> Result<(), String> {
    match guard::check_boot_disk_protection(backend, swap_target, false) {
        Err(ExecuteError::BootDiskProtection(_)) => Ok(()),
        other => Err(format!("expected swap refusal, got {:?}", other)),
    }
}

/// A stale partition-table fingerprint aborts before any open.
pub fn fingerprint_mismatch_aborts(
    backend: &dyn BlockBackend,
    device: &str,
    params: &PartitionTargetParams,
) -> Result<(), String> {
    match guard::validate_partition_target(backend, device, params, false, SERIAL) {
        Err(ExecuteError::IdentityMismatch(msg)) if msg.contains("fingerprint") => Ok(()),
        other => Err(format!(
            "expected fingerprint mismatch, got {:?}",
            other.map(|_| ())
        )),
    }
}

/// Geometry captured before a device shrink no longer matches sysfs →
/// `IdentityMismatch` (device-shrink fault).
pub fn geometry_change_aborts(
    backend: &dyn BlockBackend,
    device: &str,
    params: &PartitionTargetParams,
) -> Result<(), String> {
    match guard::validate_partition_target(backend, device, params, false, SERIAL) {
        Err(ExecuteError::IdentityMismatch(_)) => Ok(()),
        other => Err(format!(
            "expected identity mismatch, got {:?}",
            other.map(|_| ())
        )),
    }
}

/// Writes outside the validated partition range never reach the writer
/// (checked in `ExclusiveHandle::write_at`, before any device operation).
pub fn out_of_range_write_refused(
    backend: &dyn BlockBackend,
    device: &str,
    params: &PartitionTargetParams,
) -> Result<(), String> {
    let vt = guard::validate_partition_target(backend, device, params, false, SERIAL)
        .map_err(|e| format!("validate: {}", e))?;
    let (lo, hi) = vt
        .scope()
        .partition_range()
        .ok_or_else(|| "expected partition scope".to_string())?;
    let mut handle = backend
        .open_exclusive(&vt)
        .map_err(|e| format!("open_exclusive: {}", e))?;

    // Past the end.
    match handle.write_at(hi, &[0u8; 512]) {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {}
        other => return Err(format!("expected InvalidInput past end, got {:?}", other)),
    }
    // Crossing the end.
    match handle.write_at(hi - 4, &[0u8; 8]) {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {}
        other => {
            return Err(format!(
                "expected InvalidInput crossing end, got {:?}",
                other
            ))
        }
    }
    // Before the start (partition table area).
    if lo >= 512 {
        match handle.write_at(lo - 512, &[0u8; 512]) {
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {}
            other => {
                return Err(format!(
                    "expected InvalidInput before start, got {:?}",
                    other
                ))
            }
        }
    }
    Ok(())
}

/// Injected write errors surface as I/O errors (fail-closed) on the
/// in-range path.
pub fn write_fault_propagates(
    backend: &dyn BlockBackend,
    device: &str,
    params: &PartitionTargetParams,
) -> Result<(), String> {
    let vt = guard::validate_partition_target(backend, device, params, false, SERIAL)
        .map_err(|e| format!("validate: {}", e))?;
    let (lo, _) = vt
        .scope()
        .partition_range()
        .ok_or_else(|| "expected partition scope".to_string())?;
    let mut handle = backend
        .open_exclusive(&vt)
        .map_err(|e| format!("open_exclusive: {}", e))?;
    match handle.write_at(lo, &[0u8; 512]) {
        Err(_) => Ok(()),
        Ok(n) => Err(format!("expected write error, got Ok({})", n)),
    }
}

/// Injected short writes report the partial count — callers must treat
/// `Ok(n) < requested` as incomplete (engine loops handle this).
pub fn short_write_reported(
    backend: &dyn BlockBackend,
    device: &str,
    params: &PartitionTargetParams,
) -> Result<(), String> {
    let vt = guard::validate_partition_target(backend, device, params, false, SERIAL)
        .map_err(|e| format!("validate: {}", e))?;
    let (lo, _) = vt
        .scope()
        .partition_range()
        .ok_or_else(|| "expected partition scope".to_string())?;
    let mut handle = backend
        .open_exclusive(&vt)
        .map_err(|e| format!("open_exclusive: {}", e))?;
    match handle.write_at(lo, &[0u8; 512]) {
        Ok(n) if n < 512 => Ok(()),
        other => Err(format!("expected short write < 512, got {:?}", other)),
    }
}

/// A mounted holder that cannot be unmounted aborts (exec fact → shared
/// policy). Fixture: holder registered + holder mount in mounts + exec
/// result scripted to exit non-zero.
pub fn busy_unmount_refused(backend: &dyn BlockBackend, partition_dev: &str) -> Result<(), String> {
    let mut log = Vec::new();
    match guard::unmount_target_partition_and_holders(backend, partition_dev, false, &mut log) {
        Err(ExecuteError::CommandFailed(msg)) if msg.contains("cannot be unmounted") => Ok(()),
        other => Err(format!("expected busy-unmount refusal, got {:?}", other)),
    }
}

/// P4-fix: the busy-unmount refusal must name the holder's blocking mount
/// point and state that the forced unmount was attempted and failed —
/// "cannot be unmounted" alone leaves the operator guessing.
pub fn busy_unmount_names_mount_point(
    backend: &dyn BlockBackend,
    partition_dev: &str,
    expected_mount_point: &str,
) -> Result<(), String> {
    let mut log = Vec::new();
    match guard::unmount_target_partition_and_holders(backend, partition_dev, false, &mut log) {
        Err(ExecuteError::CommandFailed(msg)) => {
            if msg.contains("cannot be unmounted")
                && msg.contains(expected_mount_point)
                && msg.contains("forced unmount attempted and failed")
            {
                Ok(())
            } else {
                Err(format!(
                    "busy-unmount refusal must name '{}' and the unmount attempt: {}",
                    expected_mount_point, msg
                ))
            }
        }
        other => Err(format!("expected busy-unmount refusal, got {:?}", other)),
    }
}

/// P4-fix: a mounted-target refusal must name the blocking mount point so
/// the operator knows exactly what to unmount before retrying.
pub fn mounted_target_names_mount_point(
    backend: &dyn BlockBackend,
    target: &crate::guard::ValidatedTarget,
    expected_mount_point: &str,
) -> Result<(), String> {
    match guard::assert_target_not_mounted(backend, target) {
        Err(ExecuteError::TargetMounted(msg)) => {
            if msg.contains("mounted/active as") && msg.contains(expected_mount_point) {
                Ok(())
            } else {
                Err(format!(
                    "mounted-target refusal must name '{}': {}",
                    expected_mount_point, msg
                ))
            }
        }
        other => Err(format!(
            "expected TargetMounted, got {:?}",
            other.map(|_| ())
        )),
    }
}

/// Busy O_EXCL probe surfaces the historic retry message.
pub fn exclusive_busy_reported(backend: &dyn BlockBackend, device: &str) -> Result<(), String> {
    match guard::verify_exclusive_access_and_recheck(backend, device, false) {
        Err(ExecuteError::CommandFailed(msg)) if msg.contains("busy or mounted with O_EXCL") => {
            Ok(())
        }
        other => Err(format!("expected O_EXCL busy error, got {:?}", other)),
    }
}

/// Stub backends (Windows/Android/unknown) refuse every fact and action and
/// report all-false capabilities.
pub fn stubs_refuse_everything(backend: &dyn BlockBackend) -> Result<(), String> {
    if backend.capabilities() != crate::backend::BackendCapabilities::unsupported() {
        return Err("stub capabilities must be all-false".to_string());
    }
    if let Ok(devices) = backend.enumerate_devices() {
        if !devices.is_empty() {
            return Err("stub enumerated devices".to_string());
        }
    }
    if let Ok(parts) = backend.enumerate_partitions("/dev/sda") {
        if !parts.is_empty() {
            return Err("stub enumerated partitions".to_string());
        }
    }
    if backend.read_mount_state().is_ok() {
        return Err("stub reported mount state".to_string());
    }
    if backend.mountinfo_self().is_ok() {
        return Err("stub reported mountinfo".to_string());
    }
    if !backend.mounts_file().is_empty() {
        return Err("stub reported mounts".to_string());
    }
    if backend.boot_environment().is_ok() {
        return Err("stub reported boot environment".to_string());
    }
    if backend.canonicalize_path("/dev/sda", false).is_ok() {
        return Err("stub canonicalized".to_string());
    }
    if backend.sysfs_class_attr("sda", "dev").is_ok() {
        return Err("stub reported sysfs".to_string());
    }
    if !backend.sysfs_block_names().is_empty()
        || backend.sysfs_block_exists("sda")
        || backend.sysfs_is_partition("sda1")
        || backend.sysfs_parent_link("sda1").is_some()
        || !backend
            .sysfs_related_names("sda", crate::backend::Relation::Holders)
            .unwrap_or_default()
            .is_empty()
        || !backend
            .btrfs_member_devices()
            .unwrap_or_default()
            .is_empty()
    {
        return Err("stub leaked sysfs facts".to_string());
    }
    if backend.stat_backing_device("/swapfile").is_some() {
        return Err("stub reported file backing".to_string());
    }
    if backend.read_raw("/dev/sda", 0, 512).is_ok()
        || backend.stat_path("/dev/sda").is_ok()
        || backend.exec("true", &[]).is_ok()
        || backend.device_geometry("/dev/sda").is_ok()
    {
        return Err("stub performed an I/O fact operation".to_string());
    }
    if guard::verify_exclusive_access_and_recheck(backend, "/dev/sda", false).is_ok() {
        return Err("stub passed the exclusive-access probe".to_string());
    }
    Ok(())
}

/// D-a piece 2: the shared Windows policy must refuse `device` with a message
/// containing `expected`.
pub fn windows_refuses_disk(
    backend: &dyn BlockBackend,
    device: &str,
    expected: &str,
) -> Result<(), String> {
    match guard::check_windows_boot_disk_protection(backend, device) {
        Err(ExecuteError::BootDiskProtection(msg)) if msg.contains(expected) => Ok(()),
        other => Err(format!(
            "expected Windows BootDiskProtection containing '{}', got {:?}",
            expected, other
        )),
    }
}

/// D-a piece 2: a disk named by no boot evidence and an elevated process must
/// pass the Windows policy.
pub fn windows_allows_disk(backend: &dyn BlockBackend, device: &str) -> Result<(), String> {
    guard::check_windows_boot_disk_protection(backend, device)
        .map(|_| ())
        .map_err(|e| format!("disk should be allowed, got: {}", e))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::mock::WriteFault;
    use crate::types::BootEnvironment;

    fn fixture() -> MockBackend {
        mock_fixture()
    }

    #[test]
    fn conformance_refuses_boot_disk() {
        refuses_boot_disk(&fixture(), "/dev/sda").expect("boot disk must be refused");
        refuses_boot_disk(&fixture(), "/dev/sda1").expect("boot partition must be refused");
    }

    #[test]
    fn conformance_refuses_confirmation_mismatch() {
        refuses_confirmation_mismatch(&fixture(), "/dev/sdb", SERIAL)
            .expect("wrong token must never mint a target");
    }

    #[test]
    fn conformance_mints_confirmed_whole_disk_target() {
        mints_confirmed_whole_disk_target(&fixture(), "/dev/sdb", SERIAL, false)
            .expect("confirmed target on a free disk must validate");
    }

    #[test]
    fn conformance_refuses_container_environment() {
        let b = fixture().with_boot_env(BootEnvironment::Container);
        refuses_container_environment(&b, "/dev/sdb").expect("container must refuse");
    }

    #[test]
    fn conformance_live_root_stays_usable() {
        // Overlay root (anonymous major 0) + Live classification: the live
        // rule exempts `/` itself; sdb (not mounted, not swap) stays usable.
        let b = fixture()
            .with_mountinfo("25 30 0:1 / / rw,relatime - overlay overlay rw\n")
            .with_boot_env(BootEnvironment::Live);
        live_root_stays_usable(&b, "/dev/sdb").expect("live root must not block /dev/sdb");
    }

    #[test]
    fn conformance_refuses_active_swap() {
        let b = fixture().with_swaps(
            "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n\
             /dev/sda1                               partition\t1048576\t0\t-2\n",
        );
        refuses_active_swap(&b, "/dev/sda1").expect("active swap must be refused");
    }

    // -----------------------------------------------------------------------
    // C2c: fail-closed scan helpers — exists-but-unreadable state must block
    // the wipe, never be skipped as absent.
    // -----------------------------------------------------------------------

    #[test]
    fn conformance_unreadable_holders_fail_closed() {
        // sdb's holders dir exists but cannot be read: the guard must block
        // the wipe, never treat it as "no holders".
        let b = fixture().with_unreadable_relation("sdb", crate::backend::Relation::Holders);
        match guard::check_boot_disk_protection(&b, "/dev/sdb", false) {
            Err(ExecuteError::BootDiskProtection(msg)) => {
                assert!(
                    msg.contains("holders"),
                    "message must name the unreadable dir: {}",
                    msg
                )
            }
            other => panic!("expected BootDiskProtection, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn conformance_unreadable_slaves_fail_closed() {
        let b = fixture().with_unreadable_relation("sdb", crate::backend::Relation::Slaves);
        match guard::check_boot_disk_protection(&b, "/dev/sdb", false) {
            Err(ExecuteError::BootDiskProtection(msg)) => {
                assert!(
                    msg.contains("slaves"),
                    "message must name the unreadable dir: {}",
                    msg
                )
            }
            other => panic!("expected BootDiskProtection, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn conformance_unreadable_mountinfo_fails_closed() {
        // Mountinfo exists but cannot be read: fail closed, never scan as
        // "no mounts".
        let b = fixture().with_unreadable_mountinfo();
        match guard::check_boot_disk_protection(&b, "/dev/sdb", false) {
            Err(ExecuteError::BootDiskProtection(msg)) => {
                assert!(
                    msg.contains("mountinfo"),
                    "message must name the unreadable file: {}",
                    msg
                )
            }
            other => panic!("expected BootDiskProtection, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn conformance_unreadable_mount_source_sysfs_fails_closed() {
        // A protected mount whose /dev source's sysfs dev file exists but is
        // unreadable: the scan fails closed instead of skipping the source.
        let b = fixture().with_unreadable_attr("sda", "dev");
        match guard::check_boot_disk_protection(&b, "/dev/sdb", false) {
            Err(ExecuteError::BootDiskProtection(msg)) => {
                assert!(
                    msg.contains("unreadable"),
                    "message must name the read failure: {}",
                    msg
                )
            }
            other => panic!("expected BootDiskProtection, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn conformance_fingerprint_mismatch_aborts() {
        let b = fixture();
        let mut params = partition_params(&b, "/dev/sdb1", 1, 2048, 4096).expect("params");
        params.expected_table_fingerprint = "stale-fingerprint".to_string();
        fingerprint_mismatch_aborts(&b, "/dev/sdb1", &params)
            .expect("stale fingerprint must abort");
    }

    #[test]
    fn conformance_geometry_change_aborts() {
        let mut b = fixture();
        let params = partition_params(&b, "/dev/sdb1", 1, 2048, 4096).expect("params");
        // Device shrink: sysfs size no longer matches the captured params.
        b.mutate_attr("sdb1", "size", "1024");
        geometry_change_aborts(&b, "/dev/sdb1", &params).expect("shrink must abort");
    }

    #[test]
    fn conformance_out_of_range_write_refused() {
        let b = fixture();
        let params = partition_params(&b, "/dev/sdb1", 1, 2048, 4096).expect("params");
        out_of_range_write_refused(&b, "/dev/sdb1", &params).expect("bounds must hold");
        // Nothing was written: image is still all zeros.
        assert!(
            b.data().iter().all(|&x| x == 0),
            "no bytes may reach the device"
        );
    }

    #[test]
    fn conformance_write_error_propagates() {
        let b = fixture().with_write_fault(WriteFault::Error);
        let params = partition_params(&b, "/dev/sdb1", 1, 2048, 4096).expect("params");
        write_fault_propagates(&b, "/dev/sdb1", &params).expect("write error must surface");
        assert!(
            b.data().iter().all(|&x| x == 0),
            "failed write must not persist"
        );
    }

    #[test]
    fn conformance_short_write_reported() {
        let b = fixture().with_write_fault(WriteFault::ShortWrite(100));
        let params = partition_params(&b, "/dev/sdb1", 1, 2048, 4096).expect("params");
        short_write_reported(&b, "/dev/sdb1", &params).expect("short write must be reported");
    }

    #[test]
    fn conformance_busy_unmount_refused() {
        let b = fixture()
            .with_mounts("/dev/dm-0 /mnt/data ext4 rw 0 0\n")
            .with_exec_result("umount -f /dev/dm-0", "", "target is busy", 1);
        // holders: sdb1 → dm-0 (registered via mountinfo? explicit holder map)
        let b = {
            // MockBackend builders don't expose holders yet — register via
            // the dedicated helper.
            b.with_holder("sdb1", "dm-0")
        };
        busy_unmount_refused(&b, "/dev/sdb1").expect("busy holder must abort");
    }

    #[test]
    fn conformance_busy_unmount_names_mount_point() {
        // P4-fix: the refusal names the holder's mount point and the failed
        // unmount attempt, not just "cannot be unmounted".
        let b = fixture()
            .with_mounts("/dev/dm-0 /mnt/secret_vol ext4 rw 0 0\n")
            .with_holder("sdb1", "dm-0")
            .with_exec_result("umount -f /dev/dm-0", "", "target is busy", 1);
        busy_unmount_names_mount_point(&b, "/dev/sdb1", "/mnt/secret_vol")
            .expect("busy-unmount refusal must name the mount point");
    }

    #[test]
    fn conformance_target_unmount_failure_names_mount_point() {
        // P4-fix: when the target itself is mounted and the forced unmount
        // fails, the refusal reports the attempt and the mount point.
        let b = fixture()
            .with_mounts("/dev/sdb1 /mnt/data ext4 rw 0 0\n")
            .with_exec_result(
                "umount -f /dev/sdb1",
                "",
                "umount: /dev/sdb1: target is busy.",
                1,
            );
        let mut log = Vec::new();
        let err = guard::unmount_target_partition_and_holders(&b, "/dev/sdb1", false, &mut log)
            .expect_err("a failed forced unmount must refuse");
        match err {
            ExecuteError::CommandFailed(msg) => {
                assert!(
                    msg.contains("Failed to unmount partition /dev/sdb1"),
                    "got {}",
                    msg
                );
                assert!(msg.contains("/mnt/data"), "got {}", msg);
                assert!(msg.contains("forced unmount attempted and failed"), "got {}", msg);
                assert!(msg.contains("target is busy"), "got {}", msg);
            }
            other => panic!("expected CommandFailed, got {:?}", other),
        }
    }

    #[test]
    fn conformance_mounted_target_names_mount_point() {
        // P4-fix: a mounted partition refused before format must name the
        // blocking mount point in the TargetMounted error.
        let mut b = fixture();
        let params = partition_params(&b, "/dev/sdb1", 1, 2048, 4096).expect("params");
        let vt = guard::validate_partition_target(&b, "/dev/sdb1", &params, false, SERIAL)
            .expect("validated partition target");
        b.mutate_mountinfo(
            "25 30 8:0 / / rw,relatime shared:1 - ext4 /dev/sda rw\n\
             26 30 16:1 / /mnt/data rw,relatime shared:1 - ext4 /dev/sdb1 rw\n",
        );
        mounted_target_names_mount_point(&b, &vt, "/mnt/data")
            .expect("mounted-target refusal must name the mount point");
    }

    #[test]
    fn conformance_exclusive_busy_reported() {
        let b = fixture().with_exclusive_busy();
        exclusive_busy_reported(&b, "/dev/sdb").expect("busy O_EXCL must surface");
    }

    #[test]
    fn conformance_stubs_refuse_everything() {
        let win = crate::backend::windows::windows_backend();
        stubs_refuse_everything(&win).expect("windows stub must refuse");
        let android = crate::backend::android::android_backend();
        stubs_refuse_everything(&android).expect("android stub must refuse");
        let unknown = crate::backend::unsupported::UnsupportedBackend::new("x", "x");
        stubs_refuse_everything(&unknown).expect("unknown stub must refuse");
    }

    #[test]
    fn conformance_whole_disk_roundtrip() {
        // Validated whole-disk target: in-range write + read-back + flush.
        let b = fixture();
        let vt = guard::validate_whole_disk_target(&b, "/dev/sdb", SERIAL, SERIAL, false)
            .expect("validated target");
        let mut handle = b.open_exclusive(&vt).expect("open");
        let n = handle.write_at(4096, &[0xAB; 512]).expect("in-range write");
        assert_eq!(n, 512);
        handle.flush().expect("flush");
        let back = handle.read_at(4096, 512).expect("read back");
        assert_eq!(back, vec![0xAB; 512]);
        assert_eq!(&b.data()[4096..4608], &[0xAB; 512][..]);
    }

    #[test]
    fn conformance_backends_have_no_safety_policy() {
        // Backends only report facts: the SAME facts produce the same guard
        // decision regardless of backend identity — here, mock ids.
        let a = fixture().with_id("mock-a");
        let bb = fixture().with_id("mock-b");
        let res_a = guard::check_boot_disk_protection(&a, "/dev/sda", false).map(|_| ());
        let res_b = guard::check_boot_disk_protection(&bb, "/dev/sda", false).map(|_| ());
        assert_eq!(
            format!("{:?}", res_a.err().map(|e| e.to_string())),
            format!("{:?}", res_b.err().map(|e| e.to_string())),
        );
    }

    // -----------------------------------------------------------------------
    // D-a piece 2: Windows boot facts → shared disk refusal.
    // -----------------------------------------------------------------------

    use crate::backend::{DiskSetFact, ElevationFact, WindowsBootFacts};

    fn windows_facts() -> WindowsBootFacts {
        WindowsBootFacts {
            system_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            boot_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            pagefile_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            hibernation_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            crashdump_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            app_disks: DiskSetFact::known(std::iter::empty::<u32>()),
            elevated: ElevationFact::Known(true),
        }
    }

    #[test]
    fn conformance_windows_refuses_system_disk() {
        let mut facts = windows_facts();
        facts.system_disks = DiskSetFact::known([0]);
        let b = fixture().with_windows_boot_facts(facts);
        windows_refuses_disk(
            &b,
            r"\\.\PhysicalDrive0",
            "Windows is running from this disk. Use the Zero Trace live USB",
        )
        .expect("system disk must be refused");
    }

    #[test]
    fn conformance_windows_refuses_pagefile_on_second_disk() {
        let mut facts = windows_facts();
        facts.system_disks = DiskSetFact::known([0]);
        facts.pagefile_disks = DiskSetFact::known([1]);
        let b = fixture().with_windows_boot_facts(facts);
        windows_refuses_disk(&b, r"\\.\PhysicalDrive1", "page file")
            .expect("page-file disk must be refused");
        windows_refuses_disk(
            &b,
            r"\\.\PhysicalDrive0",
            "Windows is running from this disk",
        )
        .expect("system disk must still be refused");
    }

    #[test]
    fn conformance_windows_refuses_hibernation_disk() {
        let mut facts = windows_facts();
        facts.hibernation_disks = DiskSetFact::known([2]);
        let b = fixture().with_windows_boot_facts(facts);
        windows_refuses_disk(&b, r"\\.\PhysicalDrive2", "hibernation file")
            .expect("hibernation disk must be refused");
    }

    #[test]
    fn conformance_windows_refuses_crashdump_disk() {
        let mut facts = windows_facts();
        facts.crashdump_disks = DiskSetFact::known([3]);
        let b = fixture().with_windows_boot_facts(facts);
        windows_refuses_disk(&b, r"\\.\PhysicalDrive3", "crash-dump")
            .expect("crash-dump disk must be refused");
    }

    #[test]
    fn conformance_windows_refuses_disk_holding_the_app_on_usb() {
        let mut facts = windows_facts();
        facts.app_disks = DiskSetFact::known([4]);
        let b = fixture().with_windows_boot_facts(facts);
        windows_refuses_disk(&b, r"\\.\PhysicalDrive4", "Zero Trace application")
            .expect("the running app's own USB stick must be refused");
    }

    #[test]
    fn conformance_windows_unreadable_fact_refuses_every_disk() {
        let mut facts = windows_facts();
        facts.pagefile_disks = DiskSetFact::unreadable("registry access denied");
        let b = fixture().with_windows_boot_facts(facts);
        windows_refuses_disk(&b, r"\\.\PhysicalDrive9", "Cannot read")
            .expect("an unreadable fact must fail closed for every disk");
    }

    #[test]
    fn conformance_windows_refuses_when_not_elevated() {
        let mut facts = windows_facts();
        facts.elevated = ElevationFact::Known(false);
        let b = fixture().with_windows_boot_facts(facts);
        windows_refuses_disk(&b, r"\\.\PhysicalDrive5", "not running elevated")
            .expect("future writes require an elevated token");
    }

    #[test]
    fn conformance_windows_multi_disk_volume_protects_every_member() {
        let mut facts = windows_facts();
        facts.system_disks = DiskSetFact::known([1, 2]);
        let b = fixture().with_windows_boot_facts(facts);
        windows_refuses_disk(
            &b,
            r"\\.\PhysicalDrive1",
            "Windows is running from this disk",
        )
        .expect("first member disk must be refused");
        windows_refuses_disk(
            &b,
            r"\\.\PhysicalDrive2",
            "Windows is running from this disk",
        )
        .expect("second member disk must be refused");
    }

    #[test]
    fn conformance_windows_happy_path_allows_a_free_disk() {
        let b = fixture().with_windows_boot_facts(windows_facts());
        windows_allows_disk(&b, r"\\.\PhysicalDrive7").expect("free disk must be allowed");
    }

    #[test]
    fn conformance_non_windows_backend_has_no_windows_policy() {
        // No injected facts → the Windows policy is not applicable and must
        // not invent a refusal for a Linux/mock target.
        windows_allows_disk(&fixture(), r"\\.\PhysicalDrive7")
            .expect("non-Windows backend must not apply Windows boot facts");
    }
}

/// Linux-fixture run of the shared suite: `LinuxBackend` must produce the
/// same guard decisions from real sysfs/proc facts (fixtures only — never
/// real hardware).
#[cfg(all(test, target_os = "linux"))]
mod linux_fixture {
    use super::*;
    use crate::execute::FsContext;
    use std::fs;
    use std::path::PathBuf;

    fn write(path: &PathBuf, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn linux_fixture() -> (tempfile::TempDir, crate::backend::linux::LinuxBackend) {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        let proc = tmp.path().join("proc");
        let dev = tmp.path().join("dev");
        fs::create_dir_all(&dev).unwrap();
        write(&sys.join("class/block/sda/dev"), "8:0\n");
        write(&sys.join("class/block/sdb/dev"), "16:0\n");
        // Device nodes: canonicalization/stat need existing paths (regular
        // files stand in for block devices in fixtures — identity checks
        // accept regular files exactly like the historic code).
        fs::write(dev.join("sda"), b"").unwrap();
        fs::write(dev.join("sdb"), b"").unwrap();
        write(
            &proc.join("self/mountinfo"),
            "25 30 8:0 / / rw,relatime shared:1 - ext4 /dev/sda rw\n",
        );
        write(
            &proc.join("swaps"),
            "Filename\tType\tSize\tUsed\tPriority\n",
        );
        let backend = crate::backend::linux::LinuxBackend::new(FsContext {
            proc_root: proc,
            sys_root: sys,
            dev_root: dev,
        });
        (tmp, backend)
    }

    #[test]
    fn linux_conformance_refuses_boot_disk() {
        let (_tmp, backend) = linux_fixture();
        refuses_boot_disk(&backend, "/dev/sda").expect("boot disk must be refused");
    }

    #[test]
    fn linux_conformance_unreadable_swaps_fails_closed() {
        // C2c: an exists-but-unreadable /proc/swaps (here: a directory, so
        // the read fails deterministically for any uid) must block the wipe
        // instead of being skipped as "no swaps".
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        let proc = tmp.path().join("proc");
        let dev = tmp.path().join("dev");
        fs::create_dir_all(&dev).unwrap();
        write(&sys.join("class/block/sda/dev"), "8:0\n");
        write(&sys.join("class/block/sdb/dev"), "16:0\n");
        fs::write(dev.join("sda"), b"").unwrap();
        fs::write(dev.join("sdb"), b"").unwrap();
        write(
            &proc.join("self/mountinfo"),
            "25 30 8:0 / / rw,relatime shared:1 - ext4 /dev/sda rw\n",
        );
        // swaps exists but is unreadable (a directory): read_to_string fails.
        fs::create_dir_all(proc.join("swaps")).unwrap();
        let backend = crate::backend::linux::LinuxBackend::new(FsContext {
            proc_root: proc,
            sys_root: sys,
            dev_root: dev,
        });
        match guard::check_boot_disk_protection(&backend, "/dev/sdb", false) {
            Err(ExecuteError::BootDiskProtection(msg)) => {
                assert!(
                    msg.contains("swaps"),
                    "message must name the unreadable file: {}",
                    msg
                )
            }
            other => panic!("expected BootDiskProtection, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn linux_conformance_confirmation_gate() {
        let (_tmp, backend) = linux_fixture();
        refuses_confirmation_mismatch(&backend, "/dev/sdb", SERIAL)
            .expect("wrong token must never mint a target");
        // dry_run: fixture canonical paths (/dev/sdb) don't exist on the
        // host, matching the historic fixture/dry-run usage of the guard.
        mints_confirmed_whole_disk_target(&backend, "/dev/sdb", SERIAL, true)
            .expect("confirmed target must validate");
    }

    #[test]
    fn linux_conformance_boot_environment_facts() {
        let (_tmp, backend) = linux_fixture();
        let env = backend.boot_environment().expect("normal root");
        assert_eq!(env, crate::types::BootEnvironment::Normal);
        // Live marker: overlay root + boot=live cmdline → Live.
        assert!(fs::write(
            _tmp.path().join("proc/cmdline"),
            "BOOT_IMAGE=/live/vmlinuz boot=live quiet"
        )
        .is_ok());
        let _ = fs::write(
            _tmp.path().join("proc/self/mountinfo"),
            "25 30 0:1 / / rw,relatime - overlay overlay rw\n",
        );
        let env2 = backend.boot_environment().expect("live root");
        assert_eq!(env2, crate::types::BootEnvironment::Live);
    }

    // -----------------------------------------------------------------------
    // P2: firmware tools require a ValidatedTarget and re-validate identity
    // immediately before execution; refusals never reach the tool.
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn firmware_fixture() -> MockBackend {
        // sda is the boot disk; sdb is a free 8 MiB disk with serial + size
        // pinned by the guard at mint time.
        MockBackend::new()
            .with_id("firmware-mock")
            .with_mountinfo("25 30 8:0 / / rw,relatime shared:1 - ext4 /dev/sda rw\n")
            .with_mounts("")
            .with_swaps("")
            .add_block("sda", 8, 0)
            .add_block("sdb", 16, 0)
            .set_attr("sdb", "size", "16384")
            .set_attr("sdb", "device/serial", SERIAL)
            .with_device_size(8 * 1024 * 1024)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn firmware_tool_refused_when_target_identity_changed() {
        use crate::execute::run_firmware_cmd;
        use crate::guard::validate_whole_disk_flow_target;

        let mut backend = firmware_fixture();
        let target = validate_whole_disk_flow_target(&backend, "/dev/sdb", SERIAL, SERIAL, false)
            .expect("confirmed free disk must mint");

        // TOCTOU: the node is swapped/replaced after validation.
        backend.mutate_attr("sdb", "device/serial", "SOME-OTHER-DISK");

        let mut log = Vec::new();
        let err = run_firmware_cmd(
            &backend,
            &target,
            "hdparm",
            &["--security-erase", "p", "/dev/sdb"],
            true,
            false,
            &mut log,
        )
        .expect_err("identity drift must refuse the tool");

        match err {
            ExecuteError::IdentityMismatch(msg) => {
                assert!(
                    msg.contains("serial"),
                    "message must name the drift: {}",
                    msg
                )
            }
            other => panic!("expected IdentityMismatch, got {:?}", other),
        }
        assert_eq!(log.len(), 1, "the refused step must be logged exactly once");
        assert!(log[0].starts_with("[REFUSED] hdparm --security-erase p /dev/sdb"));
        assert!(backend.executed_commands().is_empty(), "no tool may run");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn firmware_tool_refused_when_target_becomes_boot_disk() {
        use crate::execute::run_firmware_cmd;
        use crate::guard::validate_whole_disk_flow_target;

        let mut backend = firmware_fixture();
        let target = validate_whole_disk_flow_target(&backend, "/dev/sdb", SERIAL, SERIAL, false)
            .expect("confirmed free disk must mint");

        // TOCTOU: the device is mounted as / after validation (16:0 = sdb).
        backend.mutate_mountinfo("25 30 16:0 / / rw,relatime shared:1 - ext4 /dev/sdb rw\n");

        let mut log = Vec::new();
        let err = run_firmware_cmd(
            &backend,
            &target,
            "nvme",
            &["sanitize", "/dev/sdb", "-a", "start-block-erase"],
            true,
            false,
            &mut log,
        )
        .expect_err("boot disk must refuse the tool");

        match err {
            ExecuteError::BootDiskProtection(_) => {}
            other => panic!("expected BootDiskProtection, got {:?}", other),
        }
        assert!(log[0].starts_with("[REFUSED] nvme sanitize /dev/sdb"));
        assert!(backend.executed_commands().is_empty(), "no tool may run");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn firmware_flow_logs_exact_commands_on_validated_target() {
        use crate::execute::ata_secure_erase_with;
        use crate::guard::validate_whole_disk_flow_target;

        let backend = firmware_fixture();
        let target = validate_whole_disk_flow_target(&backend, "/dev/sdb", SERIAL, SERIAL, false)
            .expect("confirmed free disk must mint");

        let (tx, _rx) = tokio::sync::mpsc::channel(32);
        let report = ata_secure_erase_with(&backend, &target, false, false, tx)
            .await
            .expect("mock tool sequence must succeed");

        let expected = vec![
            "hdparm -I /dev/sdb".to_string(),
            "hdparm --user-master u --security-set-pass p /dev/sdb".to_string(),
            "hdparm --security-erase p /dev/sdb".to_string(),
            "hdparm -F /dev/sdb".to_string(),
        ];
        assert!(report.success);
        assert_eq!(
            report.command_log, expected,
            "exact executed steps, in order"
        );
        assert_eq!(
            backend.executed_commands(),
            expected,
            "the backend saw exactly the logged steps (no shell, no extras)"
        );
    }
}
