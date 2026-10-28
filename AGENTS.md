# Agent Guidelines

## Git & Branching Rules

- Work on the branch that is currently checked out; do not create branches unless I ask. Start every task with a clean git status; if it is not clean, stop and tell me.
- Do not commit. Leave all changes in the working tree and report with `git diff --stat`; I review and commit myself.
- Never push, reset --hard, clean, checkout ., rebase or amend. I push and roll back myself.
- Before engine, guard or signing changes, remind me to tag a checkpoint.
- Run `flutter analyze`, `flutter test` (default concurrency) and the cargo checks before reporting, and show the real output.

## Platform Support (Phase C)

One shared guard chain + one UI; platform-specific disk access sits behind the
`BlockBackend` interface (`native/zt_engine/src/backend.rs`).

| Layer | Where | Compiled on |
| :--- | :--- | :--- |
| Guard chain (boot-disk protection, live/normal/container rules, confirmation token, partition validation, fingerprint, O_EXCL) | `src/guard.rs` | every target |
| Shared types + `ValidatedTarget` (private constructor) | `src/types.rs`, `src/guard.rs` | every target |
| `BlockBackend` trait, `current_backend()`, capabilities | `src/backend.rs` | every target |
| `LinuxBackend` (the only real backend; owns all raw device opens/ioctls incl. `DirectBlockWriter` and the read/write primitives) | `src/backend/linux.rs` | Linux |
| `WindowsBackend` — read-only facts only (geometry, drive layout, storage descriptors, single-disk volume extents, boot/system facts incl. system/boot/pagefile/hibernation/crash-dump/app disks + elevation); all capabilities false, every write/wipe action `Unsupported` | `src/backend/windows.rs` + `src/backend/windows_parse.rs` | Windows; the pure parse/decision modules also build under `cfg(test)` on every host |
| Android/unknown stubs (`Unsupported`, caps all false) | `src/backend/{unsupported,android}.rs` | every target |
| `MockBackend` + shared conformance suite | `src/backend/{mock,conformance}.rs` | every target |
| Engine modules (`detect`, `execute`, `partitions`, `verify`, `main`) | `src/` | Linux only (`#[cfg(target_os = "linux")]`); other targets get a stub `main` that exits 2 |
| Dart `PlatformBackend` + provider | `lib/services/platform_backend.dart` | picked via `Platform.isX`; stubs report `isSupported=false` with *"Not available on this platform"* |

Rules for agents:

- **A backend never decides safety.** It reports facts (`Ok(Some/None)`,
  `Err` = exists-but-unreadable → fail closed); `src/guard.rs` owns every
  decision. `open_exclusive`/`write_at` accept only a guard-minted
  `ValidatedTarget` — the `compile_fail` doc test on `ValidatedTarget` must
  keep passing (bypass must not compile).
- **Legacy writers routed through the guard (Phase C2a):** every execution
  flow (`software_overwrite`, `software_overwrite_partition`, `discard_erase`,
  `discard_erase_partition`) mints a `ValidatedTarget` via
  `guard::validate_whole_disk_flow_target` / `validate_partition_target`
  (historic check order and error precedence preserved) and obtains its
  writer through `BlockBackend::open_exclusive` (`execute::open_validated_writer`)
  — no flow opens a device directly. Raw device opening is private to the
  backend: `DirectBlockWriter` (O_EXCL open ladder, fd identity
  re-validation) and the read/ioctl primitives (`open_read_direct_fd`,
  `open_read_buffered`, `drop_cache_for_read`, `blkdiscard_range`) live in
  `backend/linux.rs`; `execute` only re-exports the type so its
  characterization tests keep compiling unchanged. Firmware flows drive
  external tools and never open devices in-process.
- **Firmware flows take a `ValidatedTarget` (Phase P2):** `ata_secure_erase`,
  `ata_sanitize`, `nvme_sanitize`, `opal_revert` and `emmc_sanitize` expose
  target-taking entry points (`*_validated` plus backend-injectable `*_with`
  variants used by the MockBackend tests). Every external tool call goes
  through `BlockBackend::exec` with an argv list — never `Command` directly,
  never a shell — and every destructive call
  (`execute::run_firmware_cmd`) runs
  `guard::revalidate_target_identity` immediately before execution:
  boot-disk protection against current mounts, node `st_rdev`/inode, sysfs
  serial (when exposed) and the size pinned at mint time. The historic
  `(device, token, serial)` signatures remain only as compatibility adapters
  that mint a target first. Partition table/partition probes and the
  read-only Windows probe also route through the backend.
- **Windows is facts-only (Phases D-a 1 + 2):** `WindowsBackend` opens every
  disk and volume with `dwDesiredAccess = 0` or `FILE_READ_ATTRIBUTES` only; no
  write, lock, dismount, discard or format path exists, `capabilities()` is
  all-false and every action returns `Unsupported`. Discovery fails closed:
  only `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` mean an absent
  `PhysicalDriveN`; access-denied, unreadable volumes, non-
  `ERROR_NO_MORE_FILES` `FindNextVolumeW` errors, failed/short/malformed/zero
  geometry probes and empty/multi-extent volume probes are typed errors, never
  a silent skip and never `size_bytes = 0`. Phase D-a piece 2 adds read-only
  boot facts (`GetSystemWindowsDirectoryW`, `%SystemDrive%`, `PagingFiles`,
  `HibernateEnabled`, `CrashControl`, `GetModuleFileNameW` + `%LOCALAPPDATA%`,
  `TokenElevation` with `TOKEN_QUERY` only); multi-disk volumes map to every
  member disk and any unreadable fact stays `Unreadable` (never an empty set).
  The shared `guard::check_windows_boot_disk_protection` /
  `check_windows_boot_facts_for_disk` refuses system/boot/pagefile/
  hibernation/crash-dump/app disks and unelevated processes; existing Linux
  guard rules are unchanged. The Dart Windows platform backend arrives later.
  Parser fixtures and discovery/boot decisions run on Linux through
  `#[cfg(any(target_os = "windows", test))]`; no test touches a real device.
- **Static scan (Phase C2b + P2 + D-a 2):** `tests/guard_entry_scan_test.rs`
  (`no_direct_device_opens_or_ioctls_outside_backend`) fails the build if
  any source outside `src/backend/` uses `libc::open`/`libc::ioctl` or
  opens device paths with std; `destructive_tools_require_backend_or_
  validated_target` fails on shell construction, unresolved
  `Command::new(...)` outside `src/backend/`, or a destructive tool literal
  (`hdparm`, `nvme`, `sedutil-cli`, `blkdiscard`, `smartctl`, `mmc`, …)
  outside a function taking `&ValidatedTarget`; `win32_device_apis_only_in_
  backend` keeps `CreateFileW`/`DeviceIoControl` inside `backend/`; and
  `windows_files_have_no_write_class_constants` rejects every write-class
  Win32/registry constant or API (`GENERIC_WRITE`, `FILE_WRITE_*`, `WriteFile`,
  `FSCTL_LOCK_VOLUME`, `FSCTL_DISMOUNT_VOLUME`, `IOCTL_DISK_SET_*`,
  `KEY_SET_VALUE`, `RegSetValueEx`, …) in **both** `windows.rs` and
  `windows_parse.rs`. The only `libc::open` exception is the checkpoint
  temp-file creation (`write_checkpoint_file_in_dir`,
  `O_CREAT|O_EXCL|O_NOFOLLOW` on a plain file, never a device); the std-open
  exception list is empty.
- **Display rules (Phase P1):** partition titles are filesystem-based
  (`FAT32 volume`, `exFAT volume`, `NTFS volume`, `ext4 volume`, size);
  `Windows volume (NTFS, size)` appears only when the read-only probe found
  `\Windows`. EFI System / Recovery / Microsoft Reserved keep structural
  names. Capability rows use green (available), orange (unknown), gray
  (not applicable **or** not supported on this device); red is reserved for
  real failures.
- **Knowledge base (Phase P4):** `assets/knowledge/*.md` entries are
  `review_status: reviewed`, pass `KnowledgeLint`, are reachable through the
  assistant router for at least two sample questions, and must agree with the
  capability matrix (`test/ai/knowledge_required_entries_test.dart`). Entries
  never contain runnable commands, brittle citations, or overclaiming
  wording. When engine/UI behavior changes, update the affected entry and its
  assertions in the same change.
- **Fail-closed scans (Phase C2c — the single intended behavior change,
  stricter never looser):** during the guard scan, exists-but-unreadable
  sysfs/procfs state blocks the wipe with a typed `BootDiskProtection`
  error instead of being skipped as absent — unreadable `holders`/`slaves`
  dirs, unreadable btrfs device tree, unreadable
  `swaps`/`mounts`/`mountinfo`, and unreadable mount-source `dev`
  attributes. Absent state keeps its historic permissive semantics
  (`Ok(None)`, missing dirs/files). Fault injection lives in
  `MockBackend::with_unreadable_relation`, `with_unreadable_mountinfo`,
  `with_unreadable_attr` and the Linux-fixture unreadable-swaps test.
- **Never run the ignored hardware tests** (`cargo test --ignored`): the two
  legacy loop-device tests and the two P3 loop-image isolation tests need
  real loop devices + sudo and are permanently out of scope. The P3 tests are
  additionally gated behind `--features loopdev_tests`; manual command:
  `sudo env "PATH=$PATH" cargo test --features loopdev_tests --test
  loopdev_isolation_test -- --ignored --nocapture`.
- **Goldens** (`tests/fixtures/golden/*`,
  `test/fixtures/certificate_payload_v4_golden.json`) are characterization
  baselines: they may only change for an intentional, reviewed protocol
  change via `ZT_UPDATE_GOLDEN=1`. A diff after a refactor is a regression
  signal, not something to regenerate away.
- **Existing test assertions are frozen** — Phase refactors may only make
  mechanical import/path edits to tests, never weaken or delete them.
- **Additive-only protocol fields:** detect output, certificate payloads and
  checkpoints may gain fields only when present (old fixtures must verify or
  parse byte-identically).

Reference test counts after Phase D-a piece 2 (Phase D baseline: Dart 455 /
Rust 252 + 5 ignored): `flutter test` → 455 passing; `cargo test` → 274
passing, 5 ignored, 0 failed (includes the `compile_fail` doc test; the
five ignored are the two legacy loop-device writer tests
(`native_writer_test`, `partition_scope_test`) plus the three loop-image
tests (`loopdev_filesystem_recreation_test` and two in
`loopdev_isolation_test`), all of which need root + real loop devices;
the loop-image ones also require `--features loopdev_tests` to execute);
`flutter analyze` and `cargo clippy --all-targets -- -D warnings` must be
clean, and `cargo check` must pass for the `x86_64-pc-windows-gnu`,
`x86_64-pc-windows-msvc` and `aarch64-linux-android` targets.
