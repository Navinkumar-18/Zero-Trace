# Zero Trace 2.0

> **AI-Assisted Secure Data Sanitization for Trustworthy IT Asset Recycling**  
> *Aligned with NIST SP 800-88 Rev. 2 and IEEE 2883:2022 standards.*

Zero Trace 2.0 is a media-aware, research-backed secure sanitization and verification platform. It integrates low-level storage device capability analysis, trusted sanitization execution via a native Rust engine, standards-aligned policy decision support, statistical sector verification, and cryptographically verifiable audit certification (ECDSA P-256 / SHA-256).

---

## Architecture

- **UI Layer (Flutter Desktop):** Cross-platform interface built in Flutter for Linux desktop, providing hardware discovery visualization, risk assessment, interactive sanitization workflow, and certificate verification.
- **Engine Layer (`native/zt_engine`):** High-assurance Rust execution core interfacing directly with Linux block devices and storage controller commands (ATA Secure Erase, NVMe Format/Sanitize, cryptographic erase, multi-pass block overwrite).
- **Safety Layer (`PolicyLayer`):** Multi-layered safeguards ensuring system/boot disks cannot be targeted, requiring explicit device serial-number confirmation, and keeping the built-in assistant **advisory-only and deterministic** (offline rule-based handlers, no cloud service, no LLM).

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

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

