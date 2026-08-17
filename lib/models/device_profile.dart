enum MediaType {
  hdd,
  sataSsd,
  nvmeSsd,
  emmc,
  usbFlash,
  unknown,
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
  final int rotationalRpm; // 0 for solid state
  final bool isHardwareEncrypted;
  final bool supportsAtaSecureErase;
  final bool supportsAtaSanitize;
  final bool supportsNvmeSanitize;
  final bool supportsEmmcSanitize;
  final bool supportsTrim;
  final bool hpaDcoPresent;
  final String? mountPoint;
  final bool isSystemDisk;
  final String notes;

  const DeviceProfile({
    required this.id,
    required this.name,
    required this.serialNumber,
    required this.mediaType,
    required this.busType,
    required this.capacityBytes,
    this.rotationalRpm = 0,
    this.isHardwareEncrypted = false,
    this.supportsAtaSecureErase = false,
    this.supportsAtaSanitize = false,
    this.supportsNvmeSanitize = false,
    this.supportsEmmcSanitize = false,
    this.supportsTrim = false,
    this.hpaDcoPresent = false,
    this.mountPoint,
    this.isSystemDisk = false,
    this.notes = '',
  });

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
        'notes': notes,
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
      rotationalRpm: (json['rotationalRpm'] as int?) ?? 0,
      isHardwareEncrypted: (json['isHardwareEncrypted'] as bool?) ?? false,
      supportsAtaSecureErase: (json['supportsAtaSecureErase'] as bool?) ?? false,
      supportsAtaSanitize: (json['supportsAtaSanitize'] as bool?) ?? false,
      supportsNvmeSanitize: (json['supportsNvmeSanitize'] as bool?) ?? false,
      supportsEmmcSanitize: (json['supportsEmmcSanitize'] as bool?) ?? false,
      supportsTrim: (json['supportsTrim'] as bool?) ?? false,
      hpaDcoPresent: (json['hpaDcoPresent'] as bool?) ?? false,
      mountPoint: json['mountPoint'] as String?,
      isSystemDisk: (json['isSystemDisk'] as bool?) ?? false,
      notes: (json['notes'] as String?) ?? '',
    );
  }
}
