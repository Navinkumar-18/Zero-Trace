/// Maps engine/controller error messages to plain-language user messages.
class SimpleErrorMessages {
  /// Convert a raw error string to a plain-language message with one action.
  static String fromError(String rawError) {
    final lower = rawError.toLowerCase();

    if (lower.contains('not found') || lower.contains('removed') || lower.contains('no such')) {
      return 'Drive was unplugged. Reconnect and try again.';
    }
    if (lower.contains('frozen') || lower.contains('security freeze')) {
      return 'Drive is locked/frozen. Unplug and replug it, then try again.';
    }
    if (lower.contains('permission') || lower.contains('eacces') || lower.contains('elevated')) {
      return 'Needs administrator permission. Run with elevated privileges.';
    }
    if (lower.contains('system') || lower.contains('boot') || lower.contains('protected')) {
      return 'This is your system drive. It cannot be wiped.';
    }
    if (lower.contains('mount') || lower.contains('busy') || lower.contains('in use')) {
      return 'Drive is in use. Close any files on it and try again.';
    }
    if (lower.contains('timeout') || lower.contains('timed out')) {
      return 'The drive stopped responding. Unplug it and try again.';
    }
    if (lower.contains('interrupted') || lower.contains('cancelled')) {
      return 'Wipe was interrupted. The drive may contain partial data.';
    }

    // Truncate long errors
    final short = rawError.length > 120 ? '${rawError.substring(0, 120)}...' : rawError;
    return 'Something went wrong: $short';
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
