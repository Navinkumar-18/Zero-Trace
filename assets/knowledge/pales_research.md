---
id: pales_research
title: PALES research and the flash translation layer
review_status: reviewed
last_reviewed: 2026-10-25
topics:
  - research
  - flash
  - ftl
keywords:
  - pales
  - ftl
  - flash translation layer
  - research
  - wear leveling
  - garbage collection
  - spare blocks
  - over-provisioning
  - ssd
---

PALES (Optimizing Secure Data Deletion in SSDs via Page Group and Reprogram Speedup) is research showing that secure deletion on an SSD differs fundamentally from overwriting a magnetic disk.

**What the research highlights**

- **Flash translation layer (FTL):** the drive keeps its own mapping between logical addresses the host sends and physical NAND pages. The operating system cannot choose the physical page that receives a write.
- **Wear leveling:** the controller spreads writes across NAND blocks to extend drive life, so a logical write may land somewhere other than the old data.
- **Garbage collection:** the controller reclaims invalid pages asynchronously. Data marked as deleted can persist physically until collection runs.
- **Spare blocks and over-provisioning:** part of the flash capacity is reserved by the controller and is not addressable by the host.

**Implication for Zero Trace**

Simple logical overwriting cannot reach every physical flash cell. The old pages may still hold data even after a complete pass of zeros. Device-supported sanitization commands that operate below the FTL are preferred for flash media, and a logical overwrite of flash is treated as Clear-level only.

Zero Trace does not claim that a host-level overwrite purges flash. It checks which controller-level commands the device reports and recommends accordingly.
