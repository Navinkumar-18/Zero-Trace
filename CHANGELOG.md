# Changelog

All notable changes to the Zero Trace project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - Phase 1: Hardened Boot-Disk Protection

### Added
- **Hardened Kernel Boot-Disk Protection (`native/zt_engine/src/execute.rs`)**:
  - Implemented `FsContext` for dependency injection of procfs, sysfs, and devfs in unit testing.
  - Implemented device path canonicalization resolving symlinks (`/dev/disk/by-id/*`, `/dev/disk/by-path/*`, `/dev/root`, etc.).
  - Implemented `/proc/self/mountinfo` parser checking device `major:minor` rather than raw string prefixes.
  - Implemented mount point allowlist: only `/mnt`, `/media`, and `/run/media/*` are treated as unmountable; all other mounts (including root `/`, `/boot`, `/usr`, `/var`, `/home`, etc.) and live media (`/run/live/medium`, `/run/archiso`) are strictly protected.
  - Added Btrfs anonymous major:minor (major 0) resolution via mount source and `/sys/fs/btrfs/<uuid>/devices/` member discovery with fail-closed semantics.
  - Added `/proc/swaps` parser protecting active swap partitions and swap files (resolved via filesystem `st_dev`).
  - Added recursive sysfs holder and slave graph traversal (`/sys/class/block/<dev>/holders`, `/sys/class/block/<dev>/slaves`) to catch LVM, LUKS (`dm-crypt`), and `mdraid` stacks.
  - Added whole-disk vs. partition relationship detection: refuses operations on whole disks when any partition is protected, or on partitions belonging to a disk hosting a protected mount.
  - Added exclusive access verification (`verify_exclusive_access_and_recheck`): opens block device with `O_RDONLY | O_EXCL`, checks `fstat` `st_rdev`, and re-verifies boot protection immediately post-unmount before destructive commands.
  - Fail-closed enforcement: refuses execution if `/` root mount is missing, if a container/overlayfs root is detected, if target is non-existent in real mode, or if any sysfs `dev` entry is unparseable.
- **Dart Advisory Guardrails (`lib/services/policy_layer.dart` & `device_intelligence_service.dart`)**:
  - Added `PolicyLayer.isMountUnmountable` allowlist mirroring the Rust protection rules.
  - Updated `DeviceIntelligenceService` to flag devices with non-unmountable partition mounts or swap files as `isSystemDisk = true`.
- **Test Suites**:
  - Added 18 fixture tests in `native/zt_engine/src/execute.rs` covering: plain partition root, LVM root, LUKS-on-LVM, mdraid, whole-disk mdraid member, by-id symlink, swap partition, swap file, btrfs root, multi-device btrfs, `/dev/root` and `/dev/mapper` aliases, NVMe partition naming, cyclic holders, non-existent target (real mode vs. dry-run), partition mounted under `/mnt`, container overlayfs root, missing root, and unparseable input.
  - Added `test/policy_layer_test.dart` with unit tests for `PolicyLayer.isMountUnmountable` and protected mount policy validation.
