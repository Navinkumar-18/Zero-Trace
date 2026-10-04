import '../../models/device_profile.dart';
import '../../models/sanitization_error_code.dart';
import 'knowledge_entry.dart';

class LintIssue {
  final String rule;
  final String message;
  final int? lineNumber;

  const LintIssue({
    required this.rule,
    required this.message,
    this.lineNumber,
  });

  @override
  String toString() => lineNumber != null ? 'Line $lineNumber [$rule]: $message' : '[$rule]: $message';
}

class LintResult {
  final bool isValid;
  final List<LintIssue> issues;

  const LintResult({required this.isValid, required this.issues});

  bool get hasIssues => issues.isNotEmpty;
}

class KnowledgeLint {
  static const int defaultWordCap = 300;

  static final List<RegExp> forbiddenCommandPatterns = [
    RegExp(r'\bdd\b', caseSensitive: false),
    RegExp(r'\bhdparm\b', caseSensitive: false),
    RegExp(r'\bnvme\s+format\b', caseSensitive: false),
    RegExp(r'\bmkfs\b', caseSensitive: false),
    RegExp(r'\bwipefs\b', caseSensitive: false),
    RegExp(r'\bblkdiscard\b', caseSensitive: false),
    RegExp(r'\bshred\b', caseSensitive: false),
    RegExp(r'\bsudo\b', caseSensitive: false),
  ];

  static const List<String> overclaimWords = [
    'guaranteed',
    'unrecoverable',
    'military-grade',
    '100% secure',
  ];

  static final List<RegExp> forbiddenCitationPatterns = [
    RegExp(r'\bSection\s+\d+(\.\d+)*\b', caseSensitive: false),
    RegExp(r'§\s*\d+(\.\d+)*'),
    RegExp(r'\bTable\s+[A-Za-z0-9\.\-]+\b', caseSensitive: false),
    RegExp(r'\bClause\s+\d+(\.\d+)*\b', caseSensitive: false),
    RegExp(r'\bAppendix\s+[A-Za-z0-9]+\b', caseSensitive: false),
  ];

  static const Set<String> allowedAppliesWhenKeys = {
    'media_type',
    'drive_type',
    'platform',
    'is_flash',
    'is_rotational',
    'is_security_frozen',
    'has_hpa_dco',
  };

  static const Set<String> allowedPlatforms = {
    'linux',
    'windows',
    'android',
    'macos',
    'unknown',
  };

  /// Lints a parsed [KnowledgeEntry] or raw markdown text.
  static LintResult lintEntry(KnowledgeEntry entry, {int wordCap = defaultWordCap}) {
    final issues = <LintIssue>[];

    // 1. Schema & Metadata Validation
    if (entry.topics.isEmpty) {
      issues.add(const LintIssue(rule: 'topics_required', message: 'topics list must not be empty'));
    }
    if (entry.keywords.isEmpty) {
      issues.add(const LintIssue(rule: 'keywords_required', message: 'keywords list must not be empty'));
    }

    // Validate raw error codes against SanitizationErrorCode
    final rawErrorCodes = entry.rawMetadata['error_codes'];
    if (rawErrorCodes != null) {
      final codeList = rawErrorCodes is List ? rawErrorCodes : [rawErrorCodes];
      final validNames = SanitizationErrorCode.values.map((c) => c.name.toLowerCase()).toSet();
      for (final code in codeList) {
        if (!validNames.contains(code.toString().toLowerCase())) {
          issues.add(LintIssue(
            rule: 'invalid_error_code',
            message: 'Error code "$code" is not a valid SanitizationErrorCode.',
          ));
        }
      }
    }

    // Validate applies_when keys and platform values
    for (final key in entry.appliesWhen.keys) {
      if (!allowedAppliesWhenKeys.contains(key.toLowerCase())) {
        issues.add(LintIssue(
          rule: 'invalid_applies_when_key',
          message: 'Key "$key" in applies_when is not allowed. Allowed: $allowedAppliesWhenKeys',
        ));
      }
    }

    if (entry.appliesWhen.containsKey('platform')) {
      final platformVal = entry.appliesWhen['platform']?.toString().toLowerCase();
      if (!allowedPlatforms.contains(platformVal)) {
        issues.add(LintIssue(
          rule: 'invalid_platform',
          message: 'Platform "$platformVal" in applies_when is not allowed. Allowed: $allowedPlatforms',
        ));
      }
    }

    if (entry.appliesWhen.containsKey('media_type')) {
      final mt = entry.appliesWhen['media_type']?.toString().toLowerCase();
      final validMediaTypes = MediaType.values.map((m) => m.name.toLowerCase()).toSet();
      if (!validMediaTypes.contains(mt)) {
        issues.add(LintIssue(
          rule: 'invalid_media_type',
          message: 'MediaType "$mt" in applies_when is not a valid MediaType.',
        ));
      }
    }

    if (entry.appliesWhen.containsKey('drive_type')) {
      final dt = entry.appliesWhen['drive_type']?.toString().toLowerCase();
      final validDriveTypes = DriveType.values.map((d) => d.name.toLowerCase()).toSet();
      if (!validDriveTypes.contains(dt)) {
        issues.add(LintIssue(
          rule: 'invalid_drive_type',
          message: 'DriveType "$dt" in applies_when is not a valid DriveType.',
        ));
      }
    }

    // 2. Word cap per entry
    if (entry.wordCount > wordCap) {
      issues.add(LintIssue(
        rule: 'word_cap_exceeded',
        message: 'Entry exceeds maximum word cap: ${entry.wordCount} words (max $wordCap).',
      ));
    }

    // 3. Body Content Analysis (Line by line)
    final lines = entry.content.split('\n');
    bool inCodeFence = false;

    for (int i = 0; i < lines.length; i++) {
      final line = lines[i];
      final lineNumber = i + 1;

      // Ban code fences
      if (line.contains('```')) {
        inCodeFence = !inCodeFence;
        issues.add(LintIssue(
          rule: 'code_fence_forbidden',
          message: 'Code fences (```) are forbidden in knowledge base entries.',
          lineNumber: lineNumber,
        ));
      }

      // Ban inline code
      if (RegExp(r'`[^`]+`').hasMatch(line)) {
        issues.add(LintIssue(
          rule: 'inline_code_forbidden',
          message: 'Inline code (`) is forbidden in knowledge base entries.',
          lineNumber: lineNumber,
        ));
      }

      // Forbidden commands with word boundaries
      for (final pattern in forbiddenCommandPatterns) {
        if (pattern.hasMatch(line)) {
          issues.add(LintIssue(
            rule: 'forbidden_command',
            message: 'Forbidden tool/command detected matching pattern "${pattern.pattern}".',
            lineNumber: lineNumber,
          ));
        }
      }

      // Overclaiming words (unless allowed by inline comment)
      for (final word in overclaimWords) {
        final wordPattern = RegExp(r'\b' + RegExp.escape(word) + r'\b', caseSensitive: false);
        if (wordPattern.hasMatch(line)) {
          final allowMarker = '<!-- lint-allow: $word -->'.toLowerCase();
          final isAllowedInLine = line.toLowerCase().contains(allowMarker);
          final isAllowedInDoc = entry.content.toLowerCase().contains(allowMarker);

          if (!isAllowedInLine && !isAllowedInDoc) {
            issues.add(LintIssue(
              rule: 'overclaim_word',
              message: 'Overclaiming term "$word" found without inline allowance <!-- lint-allow: $word -->.',
              lineNumber: lineNumber,
            ));
          }
        }
      }

      // Block citations to specific sections, tables, clauses
      for (final pattern in forbiddenCitationPatterns) {
        final match = pattern.firstMatch(line);
        if (match != null) {
          issues.add(LintIssue(
            rule: 'brittle_citation_forbidden',
            message: 'Brittle section/table citation "${match.group(0)}" is forbidden.',
            lineNumber: lineNumber,
          ));
        }
      }
    }

    return LintResult(
      isValid: issues.isEmpty,
      issues: issues,
    );
  }
}
