/// Storage capability detection model for Zero Trace 2.0
/// Tracks which sanitization mechanisms are available for a device.

enum CapabilityStatus {
  available,
  notAvailable,
  unknown,
  notApplicable,
}

extension CapabilityStatusExtension on CapabilityStatus {
  String get displayName {
    switch (this) {
      case CapabilityStatus.available:
        return 'AVAILABLE';
      case CapabilityStatus.notAvailable:
        return 'NOT AVAILABLE';
      case CapabilityStatus.unknown:
        return 'UNKNOWN';
      case CapabilityStatus.notApplicable:
        return 'NOT APPLICABLE';
    }
  }

  String get icon {
    switch (this) {
      case CapabilityStatus.available:
        return '✓';
      case CapabilityStatus.notAvailable:
        return '✗';
      case CapabilityStatus.unknown:
        return '?';
      case CapabilityStatus.notApplicable:
        return '—';
    }
  }
}

class StorageCapability {
  final String name;
  final CapabilityStatus status;
  final String description;

  const StorageCapability({
    required this.name,
    required this.status,
    required this.description,
  });
}

class DeviceCapabilities {
  final String deviceId;
  final List<StorageCapability> capabilities;

  const DeviceCapabilities({
    required this.deviceId,
    required this.capabilities,
  });

  /// Build capabilities from a DeviceProfile's boolean flags.
  static DeviceCapabilities fromDeviceFlags({
    required String deviceId,
    required String mediaType,
    required bool supportsAtaSecureErase,
    required bool supportsAtaSanitize,
    required bool supportsNvmeSanitize,
    required bool supportsEmmcSanitize,
    required bool supportsTrim,
    required bool isHardwareEncrypted,
    required bool hpaDcoPresent,
  }) {
    final caps = <StorageCapability>[];

    // ATA Secure Erase
    if (mediaType == 'hdd' || mediaType == 'sataSsd') {
      caps.add(StorageCapability(
        name: 'ATA Secure Erase',
        status: supportsAtaSecureErase
            ? CapabilityStatus.available
            : CapabilityStatus.notAvailable,
        description: 'Controller-level ATA Secure Erase command.',
      ));
    } else {
      caps.add(const StorageCapability(
        name: 'ATA Secure Erase',
        status: CapabilityStatus.notApplicable,
        description: 'ATA commands not applicable to this interface.',
      ));
    }

    // ATA Sanitize
    if (mediaType == 'sataSsd') {
      caps.add(StorageCapability(
        name: 'ATA Sanitize Block Erase',
        status: supportsAtaSanitize
            ? CapabilityStatus.available
            : CapabilityStatus.notAvailable,
        description: 'ATA Sanitize command with block erase action.',
      ));
    } else {
      caps.add(const StorageCapability(
        name: 'ATA Sanitize Block Erase',
        status: CapabilityStatus.notApplicable,
        description: 'ATA Sanitize not applicable to this media type.',
      ));
    }

    // NVMe Sanitize
    if (mediaType == 'nvmeSsd') {
      caps.add(StorageCapability(
        name: 'NVMe Sanitize',
        status: supportsNvmeSanitize
            ? CapabilityStatus.available
            : CapabilityStatus.notAvailable,
        description:
            'NVMe Sanitize command across all namespaces and over-provisioned regions.',
      ));
    } else {
      caps.add(const StorageCapability(
        name: 'NVMe Sanitize',
        status: CapabilityStatus.notApplicable,
        description: 'NVMe commands not applicable to this interface.',
      ));
    }

    // Cryptographic Erase
    caps.add(StorageCapability(
      name: 'Cryptographic Erase',
      status: isHardwareEncrypted
          ? CapabilityStatus.available
          : CapabilityStatus.notAvailable,
      description: isHardwareEncrypted
          ? 'Hardware encryption key destruction renders data unrecoverable.'
          : 'No hardware encryption detected. Cryptographic erase unavailable.',
    ));

    // eMMC Sanitize
    if (mediaType == 'emmc') {
      caps.add(StorageCapability(
        name: 'eMMC Sanitize',
        status: supportsEmmcSanitize
            ? CapabilityStatus.available
            : CapabilityStatus.notAvailable,
        description: 'eMMC controller sanitize erase operation.',
      ));
    } else {
      caps.add(const StorageCapability(
        name: 'eMMC Sanitize',
        status: CapabilityStatus.notApplicable,
        description: 'eMMC commands not applicable to this interface.',
      ));
    }

    // TRIM
    caps.add(StorageCapability(
      name: 'TRIM / Deallocate',
      status: supportsTrim
          ? CapabilityStatus.available
          : CapabilityStatus.notAvailable,
      description: supportsTrim
          ? 'Controller supports TRIM/deallocate hint for block management.'
          : 'TRIM not supported or not applicable.',
    ));

    // Overwrite
    if (mediaType == 'hdd') {
      caps.add(const StorageCapability(
        name: 'Logical Overwrite',
        status: CapabilityStatus.available,
        description:
            'Full LBA zero-fill overwrite is effective for magnetic media.',
      ));
    } else if (mediaType == 'sataSsd' || mediaType == 'nvmeSsd') {
      caps.add(const StorageCapability(
        name: 'Logical Overwrite',
        status: CapabilityStatus.notAvailable,
        description:
            'Overwrite is not recommended for flash media due to FTL, wear leveling, and spare blocks.',
      ));
    } else {
      caps.add(const StorageCapability(
        name: 'Logical Overwrite',
        status: CapabilityStatus.unknown,
        description: 'Overwrite effectiveness unknown for this media type.',
      ));
    }

    // HPA/DCO Warning
    if (hpaDcoPresent) {
      caps.add(const StorageCapability(
        name: 'HPA/DCO Hidden Sectors',
        status: CapabilityStatus.available,
        description:
            'WARNING: Hidden Protected Area / Device Configuration Overlay detected. Standard sanitization may not reach these regions.',
      ));
    }

    return DeviceCapabilities(deviceId: deviceId, capabilities: caps);
  }
}
