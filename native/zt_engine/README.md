# Zero Trace 2.0 — Rust Execution Engine (`zt_engine`)

**Secure data sanitization engine aligned with NIST SP 800-88 Rev. 1 and IEEE 2883:2022.**

## Overview

This Rust crate is the execution core of Zero Trace 2.0. It provides:

| Module | Purpose |
|:---|:---|
| `detect.rs` | CLI-based device capability probing (smartctl, hdparm, nvme, sedutil-cli, mmc) |
| `execute.rs` | Firmware/software sanitize command execution with dry-run & safety guardrails |
| `verify.rs` | Post-sanitization O_DIRECT LBA sector sampling with SHA-256 fingerprinting |
| `certificate.rs` | HMAC-SHA256 and Ed25519 certificate signing with key persistence |

## Required Linux Packages

```bash
# Required for device capability probing
sudo apt install smartmontools   # smartctl
sudo apt install hdparm          # ATA security features (already installed)
sudo apt install nvme-cli        # NVMe sanitize capabilities
sudo apt install mmc-utils       # eMMC sanitize capabilities

# Required for TCG OPAL / SED support
# sedutil-cli: build from source or download from
# https://github.com/Drive-Trust-Alliance/sedutil/wiki/Executable-Distributions
```

> **Note:** All hardware sanitization commands require **root privileges** (`sudo`).

## Building

```bash
cd native/zt_engine
cargo build
```

## Testing

```bash
# Unit tests (no hardware needed)
cargo test

# Loop-device integration tests (requires sudo)
sudo cargo test --features loopdev_tests
```

## Safety Guardrails

The execution engine has multiple layers of protection:

1. **Boot-disk protection**: Reads `/proc/self/mountinfo` (with a `/proc/mounts` fallback) and refuses to operate on any device hosting `/`, `/boot`, or `/boot/efi`
2. **Confirmation token**: Every operation requires a `confirmation_token` that must exactly match the device serial number
3. **Dry-run default**: All execution functions accept a `dry_run: bool` parameter — when `true`, commands are logged but never executed
4. **Policy layer**: The Flutter PolicyLayer validates operations before they reach Rust
5. **Serial re-entry dialog**: The UI requires the operator to re-type the last 4 characters of the device serial (or path + size for drives with no usable serial) before real execution

## Supported Sanitization Methods

| Method | Tool | Media Types |
|:---|:---|:---|
| NVMe Sanitize (Block/Crypto Erase) | `nvme sanitize` | NVMe SSDs |
| ATA Secure Erase (Normal/Enhanced) | `hdparm --security-erase` | SATA HDDs/SSDs |
| ATA Sanitize (Block/Crypto/Overwrite) | `hdparm --sanitize-*` | SATA SSDs |
| TCG OPAL Cryptographic Erase | `sedutil-cli --revertTPer` | Self-Encrypting Drives |
| eMMC Sanitize | `mmc sanitize` | eMMC embedded flash |
| Software Overwrite (1-pass/3-pass/DoD) | Native direct-I/O writer | All block devices |

## Certificate Signing (`certificate.rs`)

`certificate.rs` implements HMAC-SHA256 and Ed25519 signing with key
persistence, and is unit-tested. Note that the Flutter application signs its
audit certificates with its own local **ECDSA P-256 / SHA-256** keypair (see the
root `README.md`); this Rust module is not currently wired into the app's
certificate flow.

## Ed25519 Key Storage

On first certificate signing with Ed25519, a keypair is generated and stored at:
```
~/.zero_trace/keys/ed25519.key    (permissions: 0600)
```

The public key is embedded in every signed certificate for independent third-party verification.
