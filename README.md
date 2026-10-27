# Zero Trace 2.0

> **AI-Assisted Secure Data Sanitization for Trustworthy IT Asset Recycling**  
> *Aligned with NIST SP 800-88 Rev. 2 and IEEE 2883:2022 standards.*

Zero Trace 2.0 is a media-aware, research-backed secure sanitization and verification platform. It integrates low-level storage device capability analysis, trusted sanitization execution via a native Rust engine, standards-aligned policy decision support, statistical sector verification, and cryptographically verifiable audit certification (ECDSA P-256 / SHA-256).

---

## Architecture

- **UI Layer (Flutter Desktop):** Cross-platform interface built in Flutter for Linux desktop, providing hardware discovery visualization, risk assessment, interactive sanitization workflow, and certificate verification.
- **Engine Layer (`native/zt_engine`):** High-assurance Rust execution core interfacing directly with Linux block devices and storage controller commands (ATA Secure Erase, NVMe Format/Sanitize, cryptographic erase, multi-pass block overwrite).
- **Safety Layer (`PolicyLayer`):** Multi-layered safeguards ensuring system/boot disks cannot be targeted, requiring explicit device serial-number confirmation, and keeping the built-in assistant **advisory-only and deterministic** (offline rule-based handlers plus reviewed local knowledge entries, no cloud service, no LLM). Firmware commands run only against a guard-minted `ValidatedTarget`, and the device identity (node, serial, size, boot-disk state) is re-checked immediately before every destructive tool call.

---

## Media Support Matrix

| Media Type | Sanitization Level | Supported Operations | Notes |
| :--- | :--- | :--- | :--- |
| **NVMe SSD** | **Full Support** | NVMe Format, Crypto Erase, Block Erase | Native controller firmware purge |
| **SATA SSD** | **Full Support** | ATA Sanitize, ATA Enhanced Secure Erase, Overwrite | Hardware purge commands if unlocked |
| **Magnetic HDD** | **Full Support / Clear-only** | ATA Secure Erase, Multi-pass Overwrite (DoD/NIST) | Overwrite effective for magnetic media |
| **eMMC / UFS** | **Full / Clear-only** | eMMC Erase / Trim / Overwrite | Purge depends on controller command support |
| **USB Flash Drives** | **Clear-only** | Logical block overwrite | Cannot purge wear-leveling remapped blocks |
| **SD / MicroSD Cards** | **Clear-only** | Logical block overwrite | Treated as flash media without firmware purge |
| **Optical Media / Tape** | **Not Supported** | — | Physical destruction required |
| **Smartphones / Tablets** | **Not Supported** | — | Planned for future research |
| **RAID / Virtual Volumes** | **Not Supported** | — | Only direct physical block devices |

---

## Device Display Rules

Device detail pages describe what the facts actually say:

- **Partition labels are filesystem-based:** `FAT32 volume`, `exFAT volume`,
  `NTFS volume`, `ext4 volume`, … with the partition size. `Windows volume
  (NTFS, size)` appears only after the read-only probe confirmed a Windows
  installation on that volume; EFI System, Recovery and Microsoft Reserved
  keep their structural names. The raw volume label stays visible in the
  detail line.
- **Capability status colors:** green = available, orange = unknown, gray =
  not applicable **or** not supported on this device (with the reason text
  shown). Red is reserved for real failures.

---

## Platform Support

Phase C introduced one shared guard chain and one UI, with platform-specific
disk access behind the `BlockBackend` interface
(`native/zt_engine/src/backend.rs`). Backends only report facts; every safety
decision lives in the shared guard chain (`native/zt_engine/src/guard.rs`).

| Platform | Engine backend | Device discovery | UI actions | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Linux** (x86_64) | `LinuxBackend` — real sysfs/proc facts, O_EXCL exclusive access, raw I/O | `lsblk` via `LinuxPlatformBackend` | Fully enabled | **Supported** — the only shipping platform; all tests run here |
| **Windows** (x86_64-pc-windows-gnu / x86_64-pc-windows-msvc) | `WindowsBackend` — read-only Win32 facts (drive geometry, partition layout, storage descriptors, single-disk volume extents); every write/wipe action returns `Unsupported` and all capabilities are false | Read-only scan of `PhysicalDrive0..63` plus volume enumeration; fails closed on access-denied, unreadable volumes, failed/short geometry probes and non-`ERROR_NO_MORE_FILES` enumeration errors | Disabled with the reason *"Not available on this platform"* | **Read-only facts only** — no write, lock, dismount, discard or format path; system-disk (`C:`) refusal arrives in a later piece; CI `cargo check` on both Windows targets |
| **Android** (aarch64-linux-android) | `UnsupportedBackend` stub — returns `Unsupported`, zero capability flags | Returns an empty list | Disabled with the reason *"Not available on this platform"* | Compile-only stub; gated by CI `cargo check` |
| **Anything else** | `UnsupportedBackend` stub (fail closed) | Returns an empty list | Disabled with the reason *"Not available on this platform*" | Refused |

Notes:

- A backend can never write without a guard-minted `ValidatedTarget`
  (private constructor; proven by a `compile_fail` doc test), so stub
  platforms are denied at compile time, not just at runtime.
- The Windows backend is a facts-only probe in this pass: on Windows the
  engine answers `zt_engine windows-facts` with read-only device/partition
  JSON, and every other command exits 2. It never requests write access,
  never locks, dismounts, discards or formats, and never reports
  `size_bytes = 0` for a failed probe — discovery errors are returned
  instead of skipped. The Dart `WindowsPlatformBackend` and the `C:` /
  system-disk refusal are deliberately out of scope for this piece.
- `DETECT_REPORT` output carries additive `platform` and `capabilities`
  fields; v4 certificates carry signed `platform`/`backend` fields only when
  present, so all older certificates verify byte-identically.
- See `AGENTS.md` for the backend layout, test counts, golden-fixture rules
  and the known legacy-writer caveat.

---

## Known Limitations

1. **Flash Media Wear Remapping:** Overwrite operations cannot reach hidden or wear-remapped flash blocks on SD cards and USB thumb drives. For Confidential or Restricted data on flash media without firmware-level purge support, physical destruction is recommended per NIST SP 800-88.
2. **Statistical Verification:** Post-sanitization verification uses statistical sampling (50 pseudo-random sector reads plus Shannon entropy analysis), not an exhaustive full-media read.
3. **Self-Signed Certificates:** Audit certificates are signed with an ECDSA P-256 / SHA-256 local keypair. The signature lets a verifier detect modification of the certificate's own signed fields, but the key is local rather than a third-party CA, and it does not attest to anything outside the signed fields.
4. **Target Platform:** Currently tested and validated exclusively on **Linux** (kernel 5.x/6.x with direct block device access).
5. **Unsupported Media:** Smart devices, hardware RAID volumes, optical media (CD/DVD/Blu-ray), and magnetic tape are currently unsupported.

---

## Getting Started

### Prerequisites
- Linux OS (Ubuntu 22.04+ or similar)
- Flutter SDK (3.x+)
- Rust & Cargo (1.75+)
- Linux utilities: `lsblk`, `smartctl`, `nvme-cli`, `hdparm`

### Running the Application
```bash
# Analyze Flutter code
flutter analyze

# Run unit and widget tests
flutter test

# Run the Flutter desktop app
flutter run -d linux
```

### Building the Native Rust Engine
```bash
cd native/zt_engine
cargo test
cargo build --release
```

### Manual Loop-Image Isolation Tests (root only)

The engine ships two `#[ignore]`d tests that build a three-partition image,
wipe one partition (or the whole device) and compare the untouched bytes. They
attach real loop devices and are never part of the normal suite:

```bash
cd native/zt_engine
sudo env "PATH=$PATH" cargo test --features loopdev_tests \
    --test loopdev_isolation_test -- --ignored --nocapture
```

Do not run them automatically in CI or in agent sessions.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

