/// Sanitization support level model for Zero Trace 2.0
///
/// Provides a single source of truth for computing device sanitization
/// assurance from capability flags. Replaces the misleading "risk level"
/// badge with honest assurance terminology.
library;

import 'package:flutter/material.dart';
import 'device_profile.dart';

/// Describes what level of sanitization assurance a device can provide.
enum SanitizationSupportLevel {
  /// Device has firmware-level sanitize, secure erase, or hardware encryption
  /// (crypto erase). A NIST Purge-grade operation is available.
  full,

  /// Only logical overwrite is available (e.g. HDD without secure erase,
  /// flash media without firmware purge). Overwrite is the best available
  /// method but cannot reach remapped / over-provisioned flash blocks.
  clearOnly,

  /// Device is detected but its bus/media type is unknown or it is a virtual
  /// or RAID volume that cannot be safely sanitized through this tool.
  unsupported,
}

extension SanitizationSupportLevelExtension on SanitizationSupportLevel {
  String get displayName {
    switch (this) {
      case SanitizationSupportLevel.full:
        return 'Full support';
      case SanitizationSupportLevel.clearOnly:
        return 'Clear-only';
      case SanitizationSupportLevel.unsupported:
        return 'Unsupported';
    }
  }

  /// Short uppercase tag for compact badges.
  String get badgeLabel {
    switch (this) {
      case SanitizationSupportLevel.full:
        return 'FULL SUPPORT';
      case SanitizationSupportLevel.clearOnly:
        return 'CLEAR-ONLY';
      case SanitizationSupportLevel.unsupported:
        return 'UNSUPPORTED';
    }
  }

  /// Semantic color for the badge.
  Color get badgeColor {
    switch (this) {
      case SanitizationSupportLevel.full:
        return const Color(0xFF0F9360); // emerald
      case SanitizationSupportLevel.clearOnly:
        return const Color(0xFFDB8414); // amber
      case SanitizationSupportLevel.unsupported:
        return const Color(0xFFD11E28); // rose
    }
  }

  /// Serialization name for certificates and JSON.
  String get serializedName => name;
}

/// Computes the [SanitizationSupportLevel] for a given [DeviceProfile].
///
/// This is the single source of truth — call this instead of duplicating
/// capability-flag logic in widgets or services.
///
/// Note: system-disk protection is handled separately (the device stays
/// PROTECTED as before); this function does not return a "protected" level.
SanitizationSupportLevel computeSupportLevel(DeviceProfile device) {
  // DriveType.unknown or unidentifiable bus with unknown media → unsupported
  // USB or SATA with unknown media is clearOnly (cautious Clear-only wording per Item 4)
  if (device.mediaType == MediaType.unknown &&
      device.driveType != DriveType.usb &&
      !device.busType.toUpperCase().contains('SATA')) {
    return SanitizationSupportLevel.unsupported;
  }

  // Check for any firmware-level purge or crypto-erase capability
  final bool hasFirmwarePurge = device.supportsAtaSanitize ||
      device.supportsNvmeSanitize ||
      device.supportsEmmcSanitize ||
      device.supportsAtaSecureErase ||
      device.isHardwareEncrypted;

  if (hasFirmwarePurge) {
    return SanitizationSupportLevel.full;
  }

  // HDD without secure erase: overwrite is effective for magnetic media
  // (NIST Clear is achievable), so it's clearOnly.
  // Flash media without firmware purge: overwrite cannot reach remapped
  // or over-provisioned blocks, so also clearOnly.
  return SanitizationSupportLevel.clearOnly;
}

/// Returns a one-line human-readable reason for the support level.
String supportLevelReason(DeviceProfile device) {
  final level = computeSupportLevel(device);

  switch (level) {
    case SanitizationSupportLevel.full:
      if (device.isHardwareEncrypted) {
        return 'Hardware encryption available; cryptographic erase can render data unrecoverable.';
      }
      if (device.supportsAtaSanitize || device.supportsNvmeSanitize || device.supportsEmmcSanitize) {
        return 'Firmware-level sanitize command available; can reach over-provisioned and remapped blocks.';
      }
      return 'ATA Secure Erase available; controller-level erase reaches all user data blocks.';

    case SanitizationSupportLevel.clearOnly:
      if (device.mediaTechnology == MediaTechnology.rotational) {
        return 'No firmware purge available; logical overwrite is effective for magnetic media.';
      } else if (device.mediaTechnology == MediaTechnology.flash) {
        return 'No firmware purge available; overwrite cannot reach remapped or over-provisioned flash blocks.';
      } else {
        return 'No firmware purge available; logical overwrite provides Clear-level assurance.';
      }

    case SanitizationSupportLevel.unsupported:
      return 'Unknown media type or bus; sanitization capability cannot be determined.';
  }
}
