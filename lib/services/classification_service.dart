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

class ClassificationService {
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
