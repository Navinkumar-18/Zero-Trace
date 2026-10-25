# TASKS.md — Zero Trace 2.0 work log

Baseline: branch `main`, HEAD `edb3e8e`, working tree clean at start.

| Task | Status | What is left |
|------|--------|--------------|
| 1. checkpoint-path fix | DONE | — |
| 2. warning cleanup | DONE | — |
| 3. AI assistant | DONE | — |
| 4. real History | DONE | — |
| 5. partition layer review | DONE | — |
| 6. wipe entry guard | DONE | — |
| 7. documentation honesty | DONE | — |

## Task 4 notes
- The audit/cert backend already existed on `main` (inherited from the
  `fix/history-honesty` branch). Task 4 completed the missing spec pieces and
  rebuilt the deleted History screen:
  - `lib/simple/history_screen.dart` rebuilt fresh for the current light theme,
    inside `SimpleShell`, reachable from the Advanced drawer (`/history` route
    restored; `/advanced/history` redirects to it). Last 100 entries (lazy
    `ListView.builder`); `UntrustedText` on every device string; integrity row;
    "Hide simulated" filter (default on); legacy entries (no `isSimulated` field)
    under a collapsed "Legacy entries, source unknown" section; actions view
    certificate/failure report, export PDF, view raw JSON; honest empty state.
  - `AuditLogService`: added `outcome`
    (completed|wipe_failed|verify_failed|interrupted|cancelled) and derived
    `isLegacy`; canonical JSON now excludes floats (entropy is a fixed-decimal
    string); certificates/report dirs are 0700 and files 0600 via empty temp ->
    chmod -> write -> atomic rename; append repairs a torn/missing-newline tail;
    a head-anchor file (`audit_log.anchor.json`, last hash + count) detects tail
    truncation; chain verification now runs in an `Isolate`.
  - `SanitizationController` writes `outcome` at all eight append sites.
  - Tests added to `test/audit_log_service_test.dart` (canonical test vector,
    tail-truncation, torn-tail repair, garbled-fragment drop, outcome round-trip,
    0700/0600 stat) and `test/simple/history_screen_test.dart` (empty state, real
    entry appears, simulated hidden/shown, legacy hidden/revealed, tampered log
    shows broken row).
- Known pre-existing issue (NOT introduced by Task 4): `cargo test`'s
  `native_writer_test` calls the engine's checkpoint writer with the default
  state dir, creating then deleting a file in `~/.local/state/zero_trace`; the
  directory contents stay empty but its mtime changes, so the mandated
  "no change" `ls -la` check fails after `cargo test`. The Dart app never writes
  there. Left as-is (Rust test, out of Task 4 scope) — flagged for review.

## Task 1 notes
- `deviceSize` was added to `active_job.json` in addition to the requested
  `methodKind`, because matching the engine checkpoint's `device_size` needs an
  expected size stored on the active job.
- Byte progress is surfaced only for `methodKind == 'overwrite'` (the only
  byte-tracked path). Firmware/unknown show `state unknown`, never a byte count.
- Rust contract test calls the engine's real writer
  `zt_engine::execute::write_checkpoint_file_in_dir` (pub) in a temp dir.

## Task 7 notes (documentation honesty)
Corrected claims that were not backed by the code, and updated `CHANGELOG.md`:

- `native/zt_engine/README.md`: "Reads `/proc/mounts`" → `/proc/self/mountinfo`
  (execute.rs reads mountinfo with a fallback); "retype the full device serial"
  → the confirmation field is the last 4 serial characters (or path+size for
  generic serials), matching `confirm_wipe_dialog.dart`; overwrite tool `dd` →
  "Native direct-I/O writer" (the engine writes directly, it does not shell out
  to `dd`); softened "compliant" to "aligned with". Added a note that
  `certificate.rs` (HMAC-SHA256/Ed25519, unit-tested, key at
  `~/.zero_trace/keys/ed25519.key` 0600) is **not** wired into the app's
  certificate flow, which uses ECDSA P-256 / SHA-256.
- `tools/manual_throttled_wipe_test.md`: corrected the checkpoint location from
  the stale `/tmp/zt_checkpoint_<serial>.json` to the real
  `active_checkpoint.json` under `$ZT_CHECKPOINT_DIR` (default
  `~/.local/state/zero_trace`), and fixed the cleanup command.
- `README.md`: clarified the assistant is deterministic/offline (no cloud, no
  LLM); reworded the self-signed certificate note to describe exactly what the
  ECDSA signature covers.
- `CHANGELOG.md`: added an `[Unreleased]` section for partition scope, the real
  audit log, the History screen, the deterministic assistant and the wipe guard.
- Verified claims: the audit log **is** hash-chained with a head anchor and an
  "integrity check" label (not "tamper-proof"); `KnowledgeLoader.production()`
  exists; certificate files are stored. No changes needed for those.

## Task 6 notes (wipe entry guard)
- Two real gaps closed on top of code that already existed on the branch:
  - Removed the dead public `runSanitizationPipelineForTesting()` wrapper (it
    called the pipeline and was referenced nowhere); the pipeline is now only
    reachable through the private `_runSanitizationPipeline()`.
  - `WipeAuthorization` now records the typed confirmation result
    (`typedConfirmation`, the exact text entered in `confirm_wipe_dialog.dart`)
  in addition to the already-pinned `deviceSerial`, `intent`/`overrideMethod`
  and `authorizedAt` timestamp.
- `startSimpleWipe(...)` requires `WipeAuthorization`; partition wiping runs
  through the same entry point (the job carries `_selectedPartition`).
- `WipeAuthorization` has a private constructor; only
  `lib/simple/confirm_wipe_dialog.dart` mints it (the two dialog buttons), plus
  the `@visibleForTesting` `forTesting` factory.
- Guard tests: `test/wipe_entry_point_guard_test.dart` statically scans `lib/`
  and asserts only `lib/simple/drive_detail_screen.dart` calls the wipe entry
  points, and includes a deliberately violating fixture proving the scan can
  fail. Added a widget test in `test/simple/confirm_dialog_test.dart` proving
  the minted token pins the serial, the typed confirmation text ("1494") and a
  timestamp inside the dialog lifetime.

## Task 5 notes (partition layer review, commit 8442e72)
Reviewed `partition_info.dart`, `partition_table_service.dart`, `job_state_file.dart`
and the certificate changes. Findings and fixes:

- Labels: `PartitionInfo.label` is already `UntrustedText`; the lsblk parser wraps
  raw labels and `test/partition_scope_dart_test.dart` asserts `.sanitized`
  strips ANSI/control bytes. No change needed.
- Fingerprint: `PartitionTableService.computeFingerprint` (SHA-256 over sorted
  `"num:start:size\n"`, 512-byte sectors) matches the Rust
  `test_partition_table_fingerprint_shared_test_vector` pinned hash. **Fixed a
  real gap**: `RealSanitizationService` only passed `--expected-table-fingerprint`
  in partition mode, contradicting "passed to EVERY engine run". Extracted
  `buildSanitizeArgs(...)` and now the fingerprint is passed on whole-disk runs
  too whenever the device has a known partition table (the engine enforces it in
  partition mode and ignores it otherwise; Dart no longer silently drops it).
  New tests in `test/partition_scope_dart_test.dart` assert it is present in both
  whole-disk and partition arg vectors and omitted only when there is no table.
- Internal-disk refusal: **Fixed a real gap** — `PolicyLayer` refused only the
  system disk, protected partitions and swap, so a partition on a non-removable
  internal disk was still allowed. Added a strict rule: partition scope requires
  `device.isRemovable`; otherwise refuses with "Partition-scoped wiping is only
  permitted on removable media." Test added.
- `AssistantContext`: carries `isPartitionScope`, partition number, label
  (`UntrustedText`), fs type and sizes; covered by the existing shared test.
- Certificates: v3 payload includes `certVersion` and `scope`, and tampering with
  `scope`/`partitionsWiped`/`limitation` breaks the ECDSA signature. v1 legacy
  (no `certVersion`) and v2 full-disk still verify
  (`test/certificate_service_test.dart`). The v2 payload branch is byte-identical
  to code at `39acb0c` (compared `git show 39acb0c:lib/services/certificate_service.dart`),
  so the generated v2 fixture is exactly what the pre-8442e72 code produced.
- No UI built (chooser stays OUT OF SCOPE).

## NOT IN SCOPE (STOP — do not start)
- privilege separation (pkexec/polkit)
- unified Ed25519 signing
- Windows and Android backends
- internal-disk partition wiping
- the partition chooser UI
- any engine change
- any test on real hardware

## Task 3 notes
- Routing is deterministic token scoring (`lib/services/assistant_router.dart`);
  ties break by lexicographic handler id, zero score -> `fallback`. Handlers may
  declare a `requires` token gate so a shared generic word (e.g. "method") cannot
  route to an unrelated handler.
- Four new advisory handlers added: `partition_limitations`,
  `partition_overwrite`, `data_status`, `command_refusal`. Content contracts are
  asserted in `test/ai/new_handlers_test.dart` (no "wiped" for partial scope, no
  "permanently"/"unrecoverable", simulated runs say nothing was erased, no shell
  commands).
- The knowledge base loads once at startup via `KnowledgeBase.initialize()`
  (`lib/services/knowledge/knowledge_base.dart`), called from `main()`. Assets are
  registered at `assets/knowledge/`. Release builds
  serve only `review_status: reviewed`; non-reviewed/malformed entries are
  skipped. `AiAssistantScreen` takes an optional injected `AiService` and
  otherwise uses the startup instance.
- Six reviewed entries ship as of Phase P4, so conceptual questions are
  answered from `assets/knowledge/` when a reviewed entry matches; otherwise
  the built-in handlers answer.

## KB entries shipped (Phase P4)
- `clear_vs_purge`, `nist_standards`, `crypto_erase`, `pales_research`,
  `ssd_overwrite`, `partition_overwrite` — all `review_status: reviewed`,
  lint-clean, reachable from at least two sample questions each, and checked
  against the capability matrix by `test/ai/knowledge_required_entries_test.dart`.
  Update an entry and its assertions together whenever behavior changes.
