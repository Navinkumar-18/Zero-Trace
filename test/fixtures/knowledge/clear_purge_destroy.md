---
id: kb_clear_purge_destroy
title: NIST SP 800-88 Sanitization Categories
review_status: placeholder
last_reviewed: 2026-10-04
topics:
  - sanitization
  - nist
  - compliance
keywords:
  - clear
  - purge
  - destroy
  - categories
applies_when:
  platform: linux
error_codes:
  - permissionDenied
---
Storage sanitization removes data from media so that recovery is not possible through normal or laboratory techniques.

NIST media sanitization defines three primary categories:

CLEAR addresses logical techniques applied against standard read and write interfaces. It protects against simple, non-invasive software data recovery tools. Clearing is typically accomplished through single-pass or multi-pass overwrite. It is suitable for internal organizational reuse where media remains within the same security environment.

PURGE provides a higher level of protection against laboratory attack tools. Purge techniques execute device controller firmware commands, such as cryptographic erase, ATA Sanitize, or NVMe Sanitize. These commands operate below the host file system and address non-user-accessible areas, reallocated sectors, and reserved blocks.

DESTROY is the physical destruction of the storage medium to prevent data retrieval. Methods include disintegration, incineration, shredding, and pulverization. Physical destruction is recommended when media is defective, cannot accept sanitize commands, or holds highly sensitive information before external disposal.
