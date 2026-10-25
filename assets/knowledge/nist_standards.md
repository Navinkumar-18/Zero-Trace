---
id: nist_standards
title: NIST SP 800-88 Rev. 2 sanitization categories
review_status: reviewed
last_reviewed: 2026-10-25
topics:
  - nist
  - standards
  - sanitization categories
keywords:
  - nist
  - standards
  - 800-88
  - sp 800-88
  - clear
  - purge
  - destroy
  - guidance
---

NIST SP 800-88 Rev. 2 provides media sanitization guidance for information systems. Zero Trace is aligned with its sanitization categories and explains them in the assistant.

**Clear**

Logical techniques that protect against simple, non-invasive data recovery. Overwriting is the usual example. Clear is appropriate for internal reuse or low-sensitivity data.

**Purge**

Physical or logical techniques that render data recovery infeasible using state-of-the-art laboratory techniques. Device-level sanitize commands and cryptographic erase are examples. Purge is required for confidential data leaving organizational control.

**Destroy**

Physical destruction that renders the media unusable, such as disintegration, incineration, or shredding. It is required for the highest sensitivity data. Zero Trace does not perform physical destruction; it can flag a device for destruction when software sanitization cannot provide enough assurance.

**Cryptographic erase**

Destruction of encryption keys on self-encrypting devices. It can satisfy Purge requirements when the drive encrypted data from the start and the firmware implements key destruction correctly.

**Risk-based choice**

The right category depends on media type, data sensitivity, and where the device is going. Zero Trace reports capability facts and recommends a method; the final decision stays with the operator and policy.
