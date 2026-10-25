---
id: crypto_erase
title: Cryptographic erase on self-encrypting drives
review_status: reviewed
last_reviewed: 2026-10-25
topics:
  - encryption
  - sanitization
  - purge
keywords:
  - cryptographic erase
  - crypto erase
  - encryption key
  - self-encrypting drive
  - sed
  - opal
  - nvme
  - hardware encryption
---

Cryptographic erase destroys the encryption key used by a self-encrypting drive, so the stored ciphertext can no longer be decrypted.

**How it works**

- A self-encrypting drive encrypts all data at the hardware level with an internal media encryption key.
- Cryptographic erase destroys that key, not the data itself.
- Without the key, the remaining ciphertext is computationally infeasible to decrypt.

**Advantages**

- Near-instantaneous execution, measured in seconds rather than hours.
- Covers all physical regions, including spare blocks and over-provisioned areas, because the whole medium is encrypted.

**Limitations**

- Requires the drive to have been encrypting data from the start.
- Relies on a correct firmware implementation of key destruction.
- Cannot be verified by reading sectors: encrypted data remains, only the key is gone.

**Zero Trace behavior**

The capability matrix reports Cryptographic Erase as available only when hardware encryption is detected on the device. Without that detection the method is marked unavailable, and Zero Trace recommends a device-supported sanitize command instead. Cryptographic erase is a Purge-level method when the requirements above are met.
