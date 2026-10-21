import '../models/device_profile.dart';

class ClassificationResult {
  final MediaType mediaType;
  final bool isConfident;
  final Map<String, bool> capabilities;
  final String description;

  ClassificationResult({
    required this.mediaType,
    required this.isConfident,
    required this.capabilities,
    required this.description,
  });
}

/// A1: per-device capability matrix, mirroring the Rust engine's
/// `DeviceCapabilities` classification (`detect.rs`).
class DeviceCapabilityMatrix {
  /// One of: hdd, sata_ssd, nvme, sd, emmc, usb_flash, unknown.
  final String deviceClass;
  final bool supportsSecureErase;
  final bool supportsSanitize;
  final bool supportsDiscard;
  final bool supportsNvmeFormat;

  const DeviceCapabilityMatrix({
    required this.deviceClass,
    required this.supportsSecureErase,
    required this.supportsSanitize,
    required this.supportsDiscard,
    required this.supportsNvmeFormat,
  });

  /// A1 sanitization level for (device class, scope):
  /// "Purge" only when whole-device AND a hardware command is supported;
  /// everything else is "Clear" (NIST SP 800-88 Rev. 1 terms).
  String sanitizationLevel({required bool wholeDevice}) {
    final hwSupported =
        supportsSecureErase || supportsSanitize || supportsNvmeFormat;
    return (wholeDevice && hwSupported) ? 'Purge' : 'Clear';
  }

  Map<String, dynamic> toJson() => {
        'deviceClass': deviceClass,
        'supportsSecureErase': supportsSecureErase,
        'supportsSanitize': supportsSanitize,
        'supportsDiscard': supportsDiscard,
        'supportsNvmeFormat': supportsNvmeFormat,
      };
}

class ClassificationService {
  /// A1: capability matrix for a profile, using the same classification
  /// rules as the Rust engine (bus/media/removability).
  DeviceCapabilityMatrix capabilityMatrix(DeviceProfile profile) {
    return DeviceCapabilityMatrix(
      deviceClass: deviceClassOf(profile),
      supportsSecureErase: profile.supportsAtaSecureErase,
      supportsSanitize: profile.supportsAtaSanitize ||
          profile.supportsNvmeSanitize ||
          profile.supportsEmmcSanitize,
      supportsDiscard: profile.supportsTrim,
      supportsNvmeFormat: profile.supportsNvmeFormat,
    );
  }

  /// A1 device-class string, mirroring `detect.rs::classify_device_class`.
  static String deviceClassOf(DeviceProfile profile) {
    final bus = profile.busType.toUpperCase();
    final name = profile.name.toLowerCase();

    if (profile.mediaType == MediaType.nvmeSsd ||
        bus.contains('NVME') ||
        name.contains('nvme')) {
      return 'nvme';
    }
    if (name.contains('mmcblk') || profile.mediaType == MediaType.emmc) {
      // Removable MMC = SD card; soldered-down = eMMC.
      return profile.isRemovable || bus.contains('SD') ? 'sd' : 'emmc';
    }
    if (profile.mediaType == MediaType.usbFlash || bus.contains('USB')) {
      return 'usb_flash';
    }
    if (profile.mediaType == MediaType.hdd || profile.isRotational) {
      return 'hdd';
    }
    if (profile.mediaType == MediaType.sataSsd || bus.contains('SATA')) {
      return 'sata_ssd';
    }
    return 'unknown';
  }

  ClassificationResult classify(DeviceProfile profile) {
    if (profile.busType.isEmpty || profile.name.isEmpty) {
      return ClassificationResult(
        mediaType: MediaType.unknown,
        isConfident: false,
        capabilities: {},
        description: 'Failed safe: Ambiguous interface/bus metadata.',
      );
    }

    MediaType mappedType = profile.mediaType;
    
    // Validate mapping based on rotational & bus criteria
    if (profile.rotationalRpm != null && profile.rotationalRpm! > 0) {
      mappedType = MediaType.hdd;
    } else if (profile.busType.toUpperCase().contains('NVME')) {
      mappedType = MediaType.nvmeSsd;
    } else if (profile.busType.toUpperCase().contains('EMMC')) {
      mappedType = MediaType.emmc;
    } else if (profile.busType.toUpperCase().contains('USB')) {
      mappedType = MediaType.usbFlash;
    } else if (profile.busType.toUpperCase().contains('SATA') && (profile.rotationalRpm == null || profile.rotationalRpm == 0)) {
      mappedType = MediaType.sataSsd;
    }

    final capabilities = {
      'supportsAtaSecureErase': profile.supportsAtaSecureErase,
      'supportsAtaSanitize': profile.supportsAtaSanitize,
      'supportsNvmeSanitize': profile.supportsNvmeSanitize,
      'supportsEmmcSanitize': profile.supportsEmmcSanitize,
      'supportsTrim': profile.supportsTrim,
      'isHardwareEncrypted': profile.isHardwareEncrypted,
      'hpaDcoPresent': profile.hpaDcoPresent,
    };

    return ClassificationResult(
      mediaType: mappedType,
      isConfident: true,
      capabilities: capabilities,
      description: 'Identified as ${mappedType.displayName} over ${profile.busType}.',
    );
  }
}
