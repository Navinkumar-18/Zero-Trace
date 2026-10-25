---
id: ssd_overwrite
title: Why overwriting an SSD is not a reliable purge
review_status: reviewed
last_reviewed: 2026-10-25
topics:
  - flash
  - overwrite
  - sanitization
keywords:
  - ssd
  - overwrite
  - flash
  - nvme
  - solid state
  - logical overwrite
  - trim
  - clear
  - purge
  - ftl
  - unreliable
applies_when:
  is_flash: true
---

Conventional logical overwriting is not a reliable universal sanitization method for SSD, NVMe, or other flash storage.

**Why**

- The flash translation layer maps logical addresses to physical NAND pages inside the controller.
- Wear leveling and garbage collection may send a zero write to a different physical page and leave the original data in place.
- Spare blocks and over-provisioned regions are not addressable by the host at all.
- TRIM is a performance hint; on its own it is insufficient for sanitization.

**What the capability matrix says**

Zero Trace marks Logical Overwrite as not available for SATA and NVMe SSDs, with the reason that overwrite is not recommended for flash media because of the FTL, wear leveling, and spare blocks. On magnetic media the same matrix marks logical overwrite as effective.

**What to use instead**

Prefer a controller-level mechanism the device reports: NVMe Sanitize, ATA Sanitize, or cryptographic erase when hardware encryption is present. These operate below the FTL and can address physical regions the host cannot see. When no such command is available, treat a flash overwrite as Clear-level only and consider physical destruction for sensitive data leaving organizational control.

Formatting or deleting files does not sanitize flash storage either.
