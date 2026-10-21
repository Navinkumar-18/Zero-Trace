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
| `LinuxBackend` (the only real backend) | `src/backend/linux.rs` | Linux |
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
- **Known legacy-writer caveat (honest status):** the existing execution
  paths (`software_overwrite*`, `discard_*`, firmware flows) still open their
  writers through their historic call sites and keep their legacy writer
  construction; the `ValidatedTarget` + `open_exclusive` path is the new
  shared interface, exercised end-to-end by the conformance suite and
  guarded at every device-level entry point per
  `tests/guard_entry_scan_test.rs`. Fully rewiring every legacy writer
  through `ExclusiveHandle` would change execution behavior, so it was
  deliberately deferred — do not "fix" it casually; if you rewire it, the
  full test suite plus golden fixtures must stay byte-identical and the
  change must be explicitly approved.
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

Reference test counts after Phase C (baseline was Dart 422 / Rust 173 + 2
ignored): `flutter test` → 434 passing; `cargo test` → 197 passing, 2
ignored, 0 failed (includes the `compile_fail` doc test); `flutter analyze`
and `cargo clippy --all-targets -- -D warnings` must be clean.
