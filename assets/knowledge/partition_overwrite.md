---
id: partition_overwrite
title: Overwriting a single partition: scope and limits
review_status: reviewed
last_reviewed: 2026-10-25
topics:
  - partition
  - overwrite
  - scope
keywords:
  - partition
  - partition overwrite
  - overwrite a partition
  - overwrite partition
  - partition table
  - other partitions
  - unallocated
  - whole disk
  - clear
---

Zero Trace can overwrite a single selected partition. That operation has a deliberately narrow scope.

**Only the selected range is written**

- The overwrite covers the partition's own sectors.
- The partition table, which describes the drive layout, lies outside the target range and is not overwritten.
- A partition overwrite leaves other partitions, unallocated gaps, and the space between partitions untouched.

**Assurance level**

- On flash media, a partition overwrite is Clear-level only. The controller can remap logical writes away from old physical pages, and spare or over-provisioned areas are not reachable.
- On magnetic media, the overwrite can reach Clear level for the target partition, but it cannot cover controller-hidden areas such as HPA or DCO regions.
- A partition overwrite is not a Purge-level sanitization of the drive.

**For whole-drive assurance**

Target the full device or use a device-supported sanitize command. The assistant describes method choices; it never runs a command. Only the engine performs a wipe, after the usual confirmation and safety checks.
