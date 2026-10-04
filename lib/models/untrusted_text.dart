/// A string wrapper for hardware-, log-, or user-derived text that has not yet
/// been vetted by the prompt-injection sanitizer or privacy redactor.
///
/// SAFETY:
/// Prevents AI assistant code from treating raw external strings as trusted data.
/// Always access [sanitized] when interpolating into prompts or displaying in UI.
library;

class UntrustedText {
  final String rawValue;

  const UntrustedText(this.rawValue);

  /// Returns a sanitized representation:
  /// - Strips non-printable ASCII / control characters (0x00 - 0x1F, 0x7F)
  /// - Collapses multiple spaces/newlines
  /// - Enforces a 120-character maximum length cap
  String get sanitized {
    if (rawValue.isEmpty) return '';
    // Strip control characters
    final cleaned = rawValue.replaceAll(RegExp(r'[\x00-\x1F\x7F]'), ' ').trim();
    // Collapse whitespace
    final normalized = cleaned.replaceAll(RegExp(r'\s+'), ' ');
    if (normalized.length > 120) {
      return normalized.substring(0, 120).trim();
    }
    return normalized;
  }

  @override
  String toString() => sanitized;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is UntrustedText && runtimeType == other.runtimeType && rawValue == other.rawValue;

  @override
  int get hashCode => rawValue.hashCode;
}
