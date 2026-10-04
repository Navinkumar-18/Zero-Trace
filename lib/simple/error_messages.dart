import '../models/sanitization_error_code.dart';

/// Maps engine/controller error messages to plain-language user messages.
class SimpleErrorMessages {
  /// Convert a raw error string to a plain-language message with one action.
  static String fromError(String rawError, {String platform = 'Linux'}) {
    final code = SanitizationErrorCode.fromRawString(rawError);
    if (code == SanitizationErrorCode.unknown) {
      final short = rawError.length > 120 ? '${rawError.substring(0, 120)}...' : rawError;
      return 'Something went wrong: $short';
    }
    return code.toSimpleUserMessage(platform: platform);
  }

  /// Badge text for a completed job based on method class and support level.
  static String wipeBadgeText({
    required String sanitizationCategory,
    required bool isFlashMedia,
    required bool verificationPassed,
  }) {
    if (!verificationPassed) return 'WIPE FAILED';

    final cat = sanitizationCategory.toUpperCase();
    if (cat.contains('PURGE')) return 'Wiped (Purge)';
    if (cat.contains('DESTROY')) return 'Wiped (Destroy)';
    if (isFlashMedia) return 'Wiped (Clear) ⚠';
    return 'Wiped (Clear)';
  }

  /// Flash media caveat text for certificates and UI.
  static String? flashCaveat({required bool isFlashMedia, required String sanitizationCategory}) {
    if (!isFlashMedia) return null;
    final cat = sanitizationCategory.toUpperCase();
    if (cat.contains('CLEAR')) {
      return 'Flash media cannot be guaranteed purged by overwrite. '
          'Wear-leveled blocks may retain data. '
          'For highly sensitive data, physical destruction is recommended.';
    }
    return null;
  }
}
