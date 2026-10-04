enum MediaType {
  hdd,
  sataSsd,
  nvmeSsd,
  emmc,
  usbFlash,
  unknown,
}

/// User-facing drive type classification for Simple Mode UI.
/// Sorted by removable-first priority for display ordering.
enum DriveType {
  usb,
  sd,
  hdd,
  ssd,
  nvme,
  unknown,
}

extension DriveTypeExtension on DriveType {
  String get label {
    switch (this) {
      case DriveType.usb:
        return 'USB';
      case DriveType.sd:
        return 'SD';
      case DriveType.hdd:
        return 'HDD';
      case DriveType.ssd:
        return 'SSD';
      case DriveType.nvme:
        return 'NVMe';
      case DriveType.unknown:
        return 'Unknown';
    }
  }

  /// Whether this type is considered removable media.
  bool get isTypicallyRemovable {
    switch (this) {
      case DriveType.usb:
      case DriveType.sd:
        return true;
      case DriveType.hdd:
      case DriveType.ssd:
      case DriveType.nvme:
      case DriveType.unknown:
        return false;
    }
  }
}

extension MediaTypeExtension on MediaType {
  String get displayName {
    switch (this) {
      case MediaType.hdd:
        return 'HDD (Rotational)';
      case MediaType.sataSsd:
        return 'SATA SSD (Flash)';
      case MediaType.nvmeSsd:
        return 'NVMe SSD (PCIe)';
      case MediaType.emmc:
        return 'eMMC (Embedded Flash)';
      case MediaType.usbFlash:
        return 'USB Flash / Removable';
      case MediaType.unknown:
        return 'Unknown / Generic Media';
    }
  }

  String get shortTag {
    switch (this) {
      case MediaType.hdd:
        return 'HDD';
      case MediaType.sataSsd:
        return 'SATA SSD';
      case MediaType.nvmeSsd:
        return 'NVMe';
      case MediaType.emmc:
        return 'eMMC';
      case MediaType.usbFlash:
        return 'USB';
      case MediaType.unknown:
        return 'UNKNOWN';
    }
  }
}

class DeviceProfile {
  final String id;
  final String name;
  final String serialNumber;
  final MediaType mediaType;
  final String busType;
  final int capacityBytes;
  final int? rotationalRpm; // null or unknown for solid state / non-rotational
  final bool isHardwareEncrypted;
  final bool supportsAtaSecureErase;
  final bool supportsAtaSanitize;
  final bool supportsNvmeSanitize;
  final bool supportsEmmcSanitize;
  final bool supportsTrim;
  final bool hpaDcoPresent;
  final String? mountPoint;
  final bool isSystemDisk;
  final bool hasFilesystem;
  final String? fsType;
  final bool isWipedNoFilesystem;
  final String notes;

  /// Whether the device is removable (from sysfs RM/hotplug flags + bus type).
  /// Internal eMMC is NOT removable even though it's flash.
  final bool isRemovable;

  /// Reason this device is disabled in the UI, if any.
  /// Non-null for unsupported devices (RAID, optical, unknown).
  final String? disabledReason;

  const DeviceProfile({
    required this.id,
    required this.name,
    required this.serialNumber,
    required this.mediaType,
    required this.busType,
    required this.capacityBytes,
    this.rotationalRpm,
    this.isHardwareEncrypted = false,
    this.supportsAtaSecureErase = false,
    this.supportsAtaSanitize = false,
    this.supportsNvmeSanitize = false,
    this.supportsEmmcSanitize = false,
    this.supportsTrim = false,
    this.hpaDcoPresent = false,
    this.mountPoint,
    this.isSystemDisk = false,
    this.hasFilesystem = true,
    this.fsType,
    this.isWipedNoFilesystem = false,
    this.notes = '',
    this.isRemovable = false,
    this.disabledReason,
  });

  /// Derive the user-facing drive type from MediaType + bus.
  DriveType get driveType {
    switch (mediaType) {
      case MediaType.usbFlash:
        return DriveType.usb;
      case MediaType.emmc:
        // SD cards detected via SD/MMC bus; internal eMMC is NOT removable/SD.
        // It maps to DriveType.unknown and is never mapped to ssd.
        if (isRemovable || busType.toUpperCase().contains('SD')) {
          return DriveType.sd;
        }
        return DriveType.unknown;
      case MediaType.hdd:
        return DriveType.hdd;
      case MediaType.sataSsd:
        return DriveType.ssd;
      case MediaType.nvmeSsd:
        return DriveType.nvme;
      case MediaType.unknown:
        return DriveType.unknown;
    }
  }

  /// A stable ID for routing: prefer serial, fall back to device id.
  String get stableId {
    final serial = serialNumber.trim();
    if (serial.isNotEmpty && !serial.startsWith('S/N-')) {
      return serial;
    }
    return id;
  }

  /// Whether this device is selectable in Simple Mode.
  /// Returns null if selectable, or a human-readable reason if disabled.
  String? get simpleDisabledReason {
    if (isSystemDisk) return 'System drive – protected';
    if (disabledReason != null) return disabledReason;
    if (mediaType == MediaType.emmc && !isRemovable && !busType.toUpperCase().contains('SD')) {
      return 'Internal eMMC storage – not supported';
    }
    if (driveType == DriveType.unknown || mediaType == MediaType.unknown) {
      return 'Unknown or unsupported device type – cannot wipe safely';
    }
    return null;
  }

  String get formattedCapacity {
    double gb = capacityBytes / (1024 * 1024 * 1024);
    if (gb >= 1000) {
      double tb = gb / 1024;
      return '${tb.toStringAsFixed(1)} TB';
    }
    return '${gb.toStringAsFixed(0)} GB';
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'serialNumber': serialNumber,
        'mediaType': mediaType.name,
        'busType': busType,
        'capacityBytes': capacityBytes,
        'rotationalRpm': rotationalRpm,
        'isHardwareEncrypted': isHardwareEncrypted,
        'supportsAtaSecureErase': supportsAtaSecureErase,
        'supportsAtaSanitize': supportsAtaSanitize,
        'supportsNvmeSanitize': supportsNvmeSanitize,
        'supportsEmmcSanitize': supportsEmmcSanitize,
        'supportsTrim': supportsTrim,
        'hpaDcoPresent': hpaDcoPresent,
        'mountPoint': mountPoint,
        'isSystemDisk': isSystemDisk,
        'hasFilesystem': hasFilesystem,
        'fsType': fsType,
        'isWipedNoFilesystem': isWipedNoFilesystem,
        'notes': notes,
        'isRemovable': isRemovable,
        'disabledReason': disabledReason,
      };

  factory DeviceProfile.fromJson(Map<String, dynamic> json) {
    return DeviceProfile(
      id: json['id'] as String,
      name: json['name'] as String,
      serialNumber: json['serialNumber'] as String,
      mediaType: MediaType.values.firstWhere(
        (e) => e.name == json['mediaType'],
        orElse: () => MediaType.unknown,
      ),
      busType: json['busType'] as String,
      capacityBytes: json['capacityBytes'] as int,
      rotationalRpm: json['rotationalRpm'] as int?,
      isHardwareEncrypted: (json['isHardwareEncrypted'] as bool?) ?? false,
      supportsAtaSecureErase: (json['supportsAtaSecureErase'] as bool?) ?? false,
      supportsAtaSanitize: (json['supportsAtaSanitize'] as bool?) ?? false,
      supportsNvmeSanitize: (json['supportsNvmeSanitize'] as bool?) ?? false,
      supportsEmmcSanitize: (json['supportsEmmcSanitize'] as bool?) ?? false,
      supportsTrim: (json['supportsTrim'] as bool?) ?? false,
      hpaDcoPresent: (json['hpaDcoPresent'] as bool?) ?? false,
      mountPoint: json['mountPoint'] as String?,
      isSystemDisk: (json['isSystemDisk'] as bool?) ?? false,
      hasFilesystem: (json['hasFilesystem'] as bool?) ?? true,
      fsType: json['fsType'] as String?,
      isWipedNoFilesystem: (json['isWipedNoFilesystem'] as bool?) ?? false,
      notes: (json['notes'] as String?) ?? '',
      isRemovable: (json['isRemovable'] as bool?) ?? false,
      disabledReason: json['disabledReason'] as String?,
    );
  }
}
