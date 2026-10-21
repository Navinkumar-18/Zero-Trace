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
| Windows/Android/unknown stubs (`Unsupported`, caps all false) | `src/backend/{unsupported,windows,android}.rs` | every target |
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
- **Static scan (Phase C2b):** `tests/guard_entry_scan_test.rs`
  (`no_direct_device_opens_or_ioctls_outside_backend`) fails the build if
  any source outside `src/backend/` uses `libc::open`/`libc::ioctl` or
  opens device paths with std. The only `libc::open` exception is the
  checkpoint temp-file creation (`write_checkpoint_file_in_dir`,
  `O_CREAT|O_EXCL|O_NOFOLLOW` on a plain file, never a device); the
  std-open exception list is empty.
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
  loop-device tests need real disks + sudo and are permanently out of scope.
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

Reference test counts after Phase C2 (Phase C baseline: Dart 434 / Rust
197 + 2 ignored): `flutter test` → 434 passing; `cargo test` → 203
passing, 2 ignored, 0 failed (includes the `compile_fail` doc test; the
+6 are the new C2 conformance/scan tests); `flutter analyze` and
`cargo clippy --all-targets -- -D warnings` must be clean, and
`cargo check` must pass for the `x86_64-pc-windows-gnu` and
`aarch64-linux-android` targets.
