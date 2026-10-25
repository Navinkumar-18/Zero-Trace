---
id: clear_vs_purge
title: Clear versus Purge sanitization levels
review_status: reviewed
last_reviewed: 2026-10-25
topics:
  - sanitization levels
  - nist
  - assurance
keywords:
  - clear
  - purge
  - clear vs purge
  - sanitization level
  - overwrite
  - hardware command
  - whole device
---

**Clear** and **Purge** are the two logical sanitization assurance levels described by NIST SP 800-88 Rev. 2. Clear differs from Purge in what it protects against and in the assurance it provides.

**Clear**

- Protects against simple, non-invasive data recovery attempts.
- A full overwrite with zeros or a pattern is an example.
- Suitable for internal reuse and low-sensitivity data.
- Does not reach hidden or reserved areas, reallocated sectors, or flash regions managed by the drive controller.

**Purge**

- Makes recovery infeasible with state-of-the-art laboratory techniques.
- Requires a device-level hardware command run against the whole device, such as ATA Sanitize, NVMe Sanitize, or cryptographic erase on a self-encrypting drive.
- Appropriate for confidential data leaving organizational control.

**How Zero Trace applies this**

- A partition wipe overwrites only the selected partition. It is a Clear-level operation.
- A logical overwrite of flash media is also Clear-level, because the controller can remap writes away from old physical pages.
- Zero Trace does not treat a partition wipe or a flash overwrite as Purge.
- Purge needs a device-supported command on the whole device. Zero Trace runs that command through its engine; the assistant only explains the result.

**Destroy** is a separate physical category. It renders the media unusable and is not performed by Zero Trace.
