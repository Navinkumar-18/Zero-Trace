import '../models/device_profile.dart';
import '../models/sanitization_job.dart';

class RecommendationResult {
  final SanitizationMethod method;
  final String standardReference;
  final String explanation;

  RecommendationResult({
    required this.method,
    required this.standardReference,
    required this.explanation,
  });
}

abstract class IRecommendationService {
  RecommendationResult selectMethod(DeviceProfile profile, double riskScore, NistCategory targetCategory);
}

class RecommendationService implements IRecommendationService {
  @override
  RecommendationResult selectMethod(DeviceProfile profile, double riskScore, NistCategory targetCategory) {
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
              standardReference: 'NIST SP 800-88r2 Purge / IEEE 2883:2022 Overwrite Pattern',
              explanation: 'Multi-pass pattern overwrite across full storage capacity.',
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
            method: SanitizationMethod.unsupportedFlagForDestroy,
            standardReference: 'NIST SP 800-88r2 Destroy / IEEE 2883:2022 Unsupported Removable Media',
            explanation: 'Flash media lacks firmware sanitize primitives. Flagged for physical destruction under Purge requirements.',
          );
        }

      case MediaType.unknown:
        return RecommendationResult(
          method: SanitizationMethod.unsupportedFlagForDestroy,
          standardReference: 'NIST SP 800-88r2 Destroy / IEEE 2883:2022 Unknown Media',
          explanation: 'Media type and bus characteristics cannot be safely verified. Mandatory physical destruction required.',
        );
    }
  }
}
