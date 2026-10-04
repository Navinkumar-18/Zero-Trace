import '../../models/sanitization_error_code.dart';

/// Review status for a knowledge base entry.
enum KnowledgeReviewStatus {
  reviewed,
  draft,
  placeholder,
}

/// A structured knowledge base entry parsed from Markdown with YAML front matter.
class KnowledgeEntry {
  final String id;
  final String title;
  final KnowledgeReviewStatus reviewStatus;
  final DateTime lastReviewed;
  final List<String> topics;
  final List<String> keywords;
  final Map<String, dynamic> appliesWhen;
  final List<SanitizationErrorCode> errorCodes;
  final String content;
  final String? sourcePath;
  final Map<String, dynamic> rawMetadata;

  const KnowledgeEntry({
    required this.id,
    required this.title,
    required this.reviewStatus,
    required this.lastReviewed,
    required this.topics,
    required this.keywords,
    required this.appliesWhen,
    required this.errorCodes,
    required this.content,
    this.sourcePath,
    this.rawMetadata = const {},
  });

  /// Approximate word count of the body content.
  int get wordCount {
    if (content.trim().isEmpty) return 0;
    return content.trim().split(RegExp(r'\s+')).length;
  }

  /// Parses a markdown string with YAML front matter into a [KnowledgeEntry].
  /// Throws [FormatException] if front matter is missing or unparseable.
  static KnowledgeEntry parse(String rawText, {String? sourcePath}) {
    final trimmed = rawText.trim();
    if (!trimmed.startsWith('---')) {
      throw const FormatException('KnowledgeEntry must start with YAML front matter (---)');
    }

    final endFrontMatter = trimmed.indexOf('\n---', 3);
    if (endFrontMatter == -1) {
      throw const FormatException('Unterminated front matter: missing closing ---');
    }

    final yamlString = trimmed.substring(3, endFrontMatter).trim();
    final bodyContent = trimmed.substring(endFrontMatter + 4).trim();

    final metadata = _parseSimpleYaml(yamlString);

    final id = metadata['id']?.toString().trim();
    if (id == null || id.isEmpty) {
      throw const FormatException('Missing required front matter field: id');
    }

    final title = metadata['title']?.toString().trim();
    if (title == null || title.isEmpty) {
      throw const FormatException('Missing required front matter field: title');
    }

    final statusStr = metadata['review_status']?.toString().toLowerCase().trim() ?? 'placeholder';
    final reviewStatus = KnowledgeReviewStatus.values.firstWhere(
      (s) => s.name.toLowerCase() == statusStr,
      orElse: () => KnowledgeReviewStatus.placeholder,
    );

    final dateStr = metadata['last_reviewed']?.toString().trim();
    final lastReviewed = dateStr != null ? DateTime.tryParse(dateStr) : null;
    if (lastReviewed == null) {
      throw FormatException('Invalid or missing last_reviewed date: $dateStr');
    }

    final topics = _toStringList(metadata['topics']);
    final keywords = _toStringList(metadata['keywords']);

    final appliesWhen = (metadata['applies_when'] is Map)
        ? Map<String, dynamic>.from(metadata['applies_when'] as Map)
        : <String, dynamic>{};

    final rawErrorCodes = _toStringList(metadata['error_codes']);
    final errorCodes = <SanitizationErrorCode>[];
    for (final rawCode in rawErrorCodes) {
      final matched = SanitizationErrorCode.values.cast<SanitizationErrorCode?>().firstWhere(
            (c) => c!.name.toLowerCase() == rawCode.toLowerCase(),
            orElse: () => null,
          );
      if (matched != null) {
        errorCodes.add(matched);
      }
    }

    return KnowledgeEntry(
      id: id,
      title: title,
      reviewStatus: reviewStatus,
      lastReviewed: lastReviewed,
      topics: List.unmodifiable(topics),
      keywords: List.unmodifiable(keywords),
      appliesWhen: Map.unmodifiable(appliesWhen),
      errorCodes: List.unmodifiable(errorCodes),
      content: bodyContent,
      sourcePath: sourcePath,
      rawMetadata: Map.unmodifiable(metadata),
    );
  }

  static List<String> _toStringList(dynamic val) {
    if (val == null) return [];
    if (val is List) {
      return val.map((e) => e.toString().trim()).where((s) => s.isNotEmpty).toList();
    }
    if (val is String) {
      return val.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
    }
    return [];
  }

  /// Lightweight parser for YAML key-value pairs, nested maps, and string lists.
  static Map<String, dynamic> _parseSimpleYaml(String yaml) {
    final result = <String, dynamic>{};
    final lines = yaml.split('\n');

    String? currentKey;
    String? currentSection;
    Map<String, dynamic>? subMap;
    List<String>? currentList;

    void flushCurrent() {
      if (currentSection != null && subMap != null) {
        result[currentSection!] = subMap;
        subMap = null;
        currentSection = null;
      } else if (currentKey != null && currentList != null) {
        result[currentKey!] = currentList;
        currentList = null;
        currentKey = null;
      }
    }

    for (var rawLine in lines) {
      final line = rawLine.trimRight();
      final trimmed = line.trim();

      if (trimmed.isEmpty || trimmed.startsWith('#')) continue;

      // List item
      if (trimmed.startsWith('- ')) {
        final item = trimmed.substring(2).trim();
        currentList ??= [];
        currentList!.add(_stripQuotes(item));
        continue;
      }

      // Check indentation
      final indent = line.length - line.trimLeft().length;

      if (indent >= 2 && currentSection != null) {
        // Sub-key in map
        final colonIdx = trimmed.indexOf(':');
        if (colonIdx != -1) {
          final subKey = trimmed.substring(0, colonIdx).trim();
          final subVal = trimmed.substring(colonIdx + 1).trim();
          subMap ??= {};
          subMap![subKey] = _parseScalar(subVal);
        }
        continue;
      }

      // Root level key
      flushCurrent();

      final colonIdx = trimmed.indexOf(':');
      if (colonIdx != -1) {
        final key = trimmed.substring(0, colonIdx).trim();
        final val = trimmed.substring(colonIdx + 1).trim();

        if (val.isEmpty) {
          // May be starting a list or a map
          currentKey = key;
          currentSection = key;
        } else {
          result[key] = _parseScalar(val);
        }
      }
    }

    flushCurrent();
    return result;
  }

  static dynamic _parseScalar(String raw) {
    final stripped = _stripQuotes(raw);
    if (stripped.toLowerCase() == 'true') return true;
    if (stripped.toLowerCase() == 'false') return false;
    final intVal = int.tryParse(stripped);
    if (intVal != null) return intVal;
    return stripped;
  }

  static String _stripQuotes(String val) {
    var s = val.trim();
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
      if (s.length >= 2) {
        s = s.substring(1, s.length - 1);
      }
    }
    return s;
  }
}
