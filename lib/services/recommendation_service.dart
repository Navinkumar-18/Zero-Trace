import '../models/device_profile.dart';
import '../models/sanitization_job.dart';
import '../models/sanitization_support_level.dart';

class RecommendationResult {
  final SanitizationMethod method;
  final String standardReference;
  final String explanation;
  final String reason;

  RecommendationResult({
    required this.method,
    required this.standardReference,
    required this.explanation,
    this.reason = '',
  });
}

abstract class IRecommendationService {
  RecommendationResult selectMethod(
    DeviceProfile profile,
    double riskScore,
    NistCategory targetCategory, {
    DataSensitivity sensitivity = DataSensitivity.public,
  });
}

class RecommendationService implements IRecommendationService {
  @override
  RecommendationResult selectMethod(
    DeviceProfile profile,
    double riskScore,
    NistCategory targetCategory, {
    DataSensitivity sensitivity = DataSensitivity.public,
  }) {
    // 0. Flash-media Destroy guard:
    // If device is clearOnly AND data is high-sensitivity (confidential/restricted)
    // AND the device is flash media (not HDD), recommend physical destruction.
    final supportLevel = computeSupportLevel(profile);
    if (supportLevel == SanitizationSupportLevel.clearOnly &&
        (sensitivity == DataSensitivity.confidential || sensitivity == DataSensitivity.restricted)) {
      // Only apply to flash media — HDD overwrite is effective for magnetic media
      if (profile.mediaTechnology == MediaTechnology.flash) {
        final mediaLabel = profile.mediaType.displayName;
        return RecommendationResult(
          method: SanitizationMethod.physicalDestructionRecommended,
          standardReference: 'NIST SP 800-88r2 Destroy / IEEE 2883:2022 Physical Destruction',
          explanation:
              '$mediaLabel without firmware-level purge cannot be reliably purged. '
              'Overwrite cannot reach remapped or over-provisioned flash blocks. '
              'Physical destruction is recommended for ${sensitivity.name} data '
              'per NIST SP 800-88.',
          reason:
              'Clear-only flash media with ${sensitivity.name} data requires '
              'physical destruction (NIST SP 800-88).',
        );
      }
    }

    // Unsupported media → always Destroy
    if (supportLevel == SanitizationSupportLevel.unsupported) {
      return RecommendationResult(
        method: SanitizationMethod.unsupportedFlagForDestroy,
        standardReference: 'NIST SP 800-88r2 Destroy / IEEE 2883:2022 Unknown Media',
        explanation:
            'Media type and bus characteristics cannot be safely verified. '
            'Mandatory physical destruction required.',
        reason: 'Unknown/unsupported media type.',
      );
    }

    // 1. Mandatory Destroy branch
    if (targetCategory == NistCategory.destroy) {
      return RecommendationResult(
        method: SanitizationMethod.physicalDestructionRecommended,
        standardReference: 'NIST SP 800-88r2 Destroy / IEEE 2883:2022 Physical Destruction',
        explanation: 'High risk classification requires physical disintegration, incineration, or shredding of media.',
      );
    }

    // 2. Cryptographic Erase shortcut for hardware-encrypted drives under moderate risk
    if (profile.isHardwareEncrypted &&
        (targetCategory == NistCategory.clear || targetCategory == NistCategory.purge) &&
        riskScore < 0.85) {
      return RecommendationResult(
        method: SanitizationMethod.cryptographicErase,
        standardReference: 'NIST SP 800-88r2 Purge / IEEE 2883:2022 Cryptographic Erase',
        explanation: 'Drive features TCG OPAL/hardware encryption. Cryptographic key destruction instantly renders all stored ciphertext unrecoverable.',
      );
    }

    // 3. Media Specific Selection Matrix
    switch (profile.mediaType) {
      case MediaType.hdd:
        if (targetCategory == NistCategory.clear) {
          return RecommendationResult(
            method: SanitizationMethod.singlePassOverwrite,
            standardReference: 'NIST SP 800-88r2 Clear / IEEE 2883:2022 Logical Overwrite',
            explanation: 'Single-pass zero fill overwrite across all addressable logical block addresses (LBA).',
          );
        } else {
          // PURGE
          if (profile.supportsAtaSecureErase) {
            return RecommendationResult(
              method: SanitizationMethod.ataSecureErase,
              standardReference: 'NIST SP 800-88r2 Purge / IEEE 2883:2022 ATA Secure Erase',
              explanation: 'Hardware controller-level ATA Secure Erase command purges user data blocks including reallocated sector pools.',
            );
          } else {
            return RecommendationResult(
              method: SanitizationMethod.multiPassOverwrite,
              standardReference: 'NIST SP 800-88r2 Clear (3-pass legacy HDD fallback, exceeds minimum)',
              explanation: 'Multi-pass pattern overwrite across full storage capacity. Exceeds minimum NIST Clear requirement for magnetic media.',
            );
          }
        }

      case MediaType.sataSsd:
        if (profile.supportsAtaSanitize) {
          return RecommendationResult(
            method: SanitizationMethod.ataSanitizeBlockErase,
            standardReference: 'NIST SP 800-88r2 Purge / IEEE 2883:2022 ATA Sanitize Block Erase',
            explanation: 'ATA Sanitize Block Erase executes physical voltage reset across all NAND flash blocks.',
          );
        } else if (profile.supportsAtaSecureErase) {
          return RecommendationResult(
            method: SanitizationMethod.ataSecureErase,
            standardReference: 'NIST SP 800-88r2 Purge / IEEE 2883:2022 ATA Secure Erase',
            explanation: 'Firmware-driven ATA Secure Erase to reset flash storage blocks.',
          );
        } else if (profile.isHardwareEncrypted) {
          return RecommendationResult(
            method: SanitizationMethod.cryptographicErase,
            standardReference: 'NIST SP 800-88r2 Purge / IEEE 2883:2022 Cryptographic Erase',
            explanation: 'Cryptographic erase via key zeroization.',
          );
        } else {
          return RecommendationResult(
            method: SanitizationMethod.unsupportedFlagForDestroy,
            standardReference: 'NIST SP 800-88r2 Destroy / IEEE 2883:2022 Unsupported Device',
            explanation: 'SSD lacks verifiable firmware erase primitives. Flagged for physical destruction to prevent wear-leveling data leakage.',
          );
        }

      case MediaType.nvmeSsd:
        if (profile.supportsNvmeSanitize) {
          return RecommendationResult(
            method: SanitizationMethod.nvmeSanitize,
            standardReference: 'NIST SP 800-88r2 Purge / IEEE 2883:2022 NVMe Sanitize Block Erase',
            explanation: 'NVMe Sanitize command executes controller-level block erase across all namespaces and over-provisioned flash regions.',
          );
        } else if (profile.isHardwareEncrypted) {
          return RecommendationResult(
            method: SanitizationMethod.cryptographicErase,
            standardReference: 'NIST SP 800-88r2 Purge / IEEE 2883:2022 Cryptographic Erase',
            explanation: 'NVMe Cryptographic Erase destroying internal encryption keys.',
          );
        } else {
          return RecommendationResult(
            method: SanitizationMethod.singlePassOverwrite,
            standardReference: 'NIST SP 800-88r2 Clear / IEEE 2883:2022 NVMe Format',
            explanation: 'NVMe Format / Single-pass LBA zero fill.',
          );
        }

      case MediaType.emmc:
      case MediaType.usbFlash:
        if (profile.supportsEmmcSanitize) {
          return RecommendationResult(
            method: SanitizationMethod.emmcSanitize,
            standardReference: 'NIST SP 800-88r2 Purge / IEEE 2883:2022 eMMC Sanitize',
            explanation: 'eMMC controller sanitize erase operation targeting unmapped flash memory.',
          );
        } else {
          return RecommendationResult(
            method: SanitizationMethod.singlePassOverwrite,
            standardReference: 'NIST SP 800-88r2 Clear / IEEE 2883:2022 Logical Overwrite',
            explanation: 'No hardware sanitize primitive available. Single-pass zero overwrite achieves NIST Clear category. Note: wear-leveled flash may retain data in unmapped blocks — Clear is the maximum achievable assurance for this media type.',
          );
        }

      case MediaType.unknown:
        return RecommendationResult(
          method: SanitizationMethod.unsupportedFlagForDestroy,
          standardReference: 'NIST SP 800-88r2 Destroy / IEEE 2883:2022 Unknown Media',
          explanation: 'Media type and bus characteristics cannot be safely verified. Mandatory physical destruction required.',
          reason: 'Unknown/unsupported media type.',
        );
    }
  }
}
