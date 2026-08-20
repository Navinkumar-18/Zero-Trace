import 'device_profile.dart';

enum DataSensitivity { public, internal, confidential, restricted }
enum DeviceCondition { functional, degraded, endOfLife }
enum DisposalPath { internalReuse, externalResale, recycling, physicalDestruction }

enum NistCategory { clear, purge, destroy }

extension NistCategoryExtension on NistCategory {
  String get displayName {
    switch (this) {
      case NistCategory.clear:
        return 'CLEAR (Logical Protection)';
      case NistCategory.purge:
        return 'PURGE (Physical & Controller Sanitization)';
      case NistCategory.destroy:
        return 'DESTROY (Physical Destruction Required)';
    }
  }
}

enum SanitizationMethod {
  cryptographicErase,
  ataSecureErase,
  ataSanitizeBlockErase,
  nvmeSanitize,
  emmcSanitize,
  singlePassOverwrite,
  multiPassOverwrite,
  physicalDestructionRecommended,
  unsupportedFlagForDestroy,
}

extension SanitizationMethodExtension on SanitizationMethod {
  String get displayName {
    switch (this) {
      case SanitizationMethod.cryptographicErase:
        return 'Cryptographic Erase (CE)';
      case SanitizationMethod.ataSecureErase:
        return 'ATA Secure Erase (Controller-Level)';
      case SanitizationMethod.ataSanitizeBlockErase:
        return 'ATA Sanitize Block Erase';
      case SanitizationMethod.nvmeSanitize:
        return 'NVMe Sanitize (Block / Crypto Erase)';
      case SanitizationMethod.emmcSanitize:
        return 'eMMC Sanitize / Secure Trim';
      case SanitizationMethod.singlePassOverwrite:
        return 'Single-Pass Zero Overwrite';
      case SanitizationMethod.multiPassOverwrite:
        return '3-Pass Overwrite (legacy HDD fallback, exceeds NIST Clear)';
      case SanitizationMethod.physicalDestructionRecommended:
        return 'Physical Destruction Recommended';
      case SanitizationMethod.unsupportedFlagForDestroy:
        return 'Unsupported Media (Flagged for Destruction)';
    }
  }

  bool get isWhitelisted {
    switch (this) {
      case SanitizationMethod.cryptographicErase:
      case SanitizationMethod.ataSecureErase:
      case SanitizationMethod.ataSanitizeBlockErase:
      case SanitizationMethod.nvmeSanitize:
      case SanitizationMethod.emmcSanitize:
      case SanitizationMethod.singlePassOverwrite:
      case SanitizationMethod.multiPassOverwrite:
        return true;
      case SanitizationMethod.physicalDestructionRecommended:
      case SanitizationMethod.unsupportedFlagForDestroy:
        return false;
    }
  }

  NistCategory get nistCategory {
    switch (this) {
      case SanitizationMethod.cryptographicErase:
      case SanitizationMethod.ataSecureErase:
      case SanitizationMethod.ataSanitizeBlockErase:
      case SanitizationMethod.nvmeSanitize:
      case SanitizationMethod.emmcSanitize:
        return NistCategory.purge;
      case SanitizationMethod.singlePassOverwrite:
      case SanitizationMethod.multiPassOverwrite:
        return NistCategory.clear;
      case SanitizationMethod.physicalDestructionRecommended:
      case SanitizationMethod.unsupportedFlagForDestroy:
        return NistCategory.destroy;
    }
  }
}

enum JobStatus {
  idle,
  detecting,
  unmounting,
  sanitizing,
  verifying,
  completed,
  failed,
}

class SanitizationJob {
  final String jobId;
  final DeviceProfile device;
  final DataSensitivity dataSensitivity;
  final DeviceCondition deviceCondition;
  final DisposalPath disposalPath;
  final double riskScore;
  final NistCategory targetCategory;
  final SanitizationMethod recommendedMethod;
  final String standardReference;
  final String explanationText;
  
  JobStatus status;
  double progress; // 0.0 to 1.0
  String currentStageDescription;
  DateTime? startTime;
  DateTime? endTime;
  List<String> logs;
  bool shouldSimulateFailure;

  SanitizationJob({
    required this.jobId,
    required this.device,
    required this.dataSensitivity,
    required this.deviceCondition,
    required this.disposalPath,
    required this.riskScore,
    required this.targetCategory,
    required this.recommendedMethod,
    required this.standardReference,
    required this.explanationText,
    this.status = JobStatus.idle,
    this.progress = 0.0,
    this.currentStageDescription = 'Ready to initiate sanitization pipeline',
    this.startTime,
    this.endTime,
    List<String>? logs,
    this.shouldSimulateFailure = false,
  }) : logs = logs ?? [];

  /// The effective NIST category achieved by the recommended sanitization method.
  NistCategory get effectiveNistCategory {
    final ref = standardReference.toLowerCase();
    if (ref.contains('destroy')) return NistCategory.destroy;
    if (ref.contains('purge')) return NistCategory.purge;
    if (ref.contains('clear')) return NistCategory.clear;
    return recommendedMethod.nistCategory;
  }

  /// Display name of the effective NIST category (e.g. "CLEAR (Logical Protection)").
  String get effectiveNistCategoryDisplayName => effectiveNistCategory.displayName;

  /// Short badge string of the effective NIST category (e.g. "CLEAR", "PURGE", "DESTROY").
  String get effectiveNistCategoryShort => effectiveNistCategory.name.toUpperCase();
}
