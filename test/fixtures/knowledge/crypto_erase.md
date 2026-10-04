---
id: kb_crypto_erase
title: Cryptographic Erase Principles and Limitations
review_status: placeholder
last_reviewed: 2026-10-04
topics:
  - encryption
  - purge
  - sanitize
keywords:
  - crypto
  - cryptographic
  - erase
  - key
applies_when:
  platform: linux
error_codes:
  - securityFrozen
---
Cryptographic erase renders target data unreadable by sanitizing or destroying the internal cryptographic keys used to encrypt user data on self-encrypting drives.

Self-encrypting storage hardware continuously encrypts all data written to media using an internal Media Encryption Key. When a cryptographic erase command is executed, the storage controller generates a new key or discards the existing key, rendering previously recorded ciphertext computationally infeasible to decrypt.

This technique operates in seconds regardless of media capacity. It reaches all physical storage areas, including wear-leveled blocks, bad sectors, and hidden regions.

However, cryptographic erase depends strictly on the drive having been encrypted throughout its operational lifecycle. It cannot scrub unencrypted remnants written before encryption was enabled. In addition, sector readback cannot verify key destruction through pattern inspection because encrypted ciphertext remains on the physical media.
