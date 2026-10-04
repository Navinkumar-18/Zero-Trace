import 'dart:io';
import 'knowledge_entry.dart';
import 'knowledge_lint.dart';

class KnowledgeLoader {
  final bool isRelease;
  final bool autoLint;
  final int wordCap;

  const KnowledgeLoader({
    this.isRelease = false,
    this.autoLint = true,
    this.wordCap = KnowledgeLint.defaultWordCap,
  });

  /// Loads and parses all markdown knowledge base entries from a directory.
  /// If [isRelease] is true, excludes any entries with reviewStatus != reviewed.
  List<KnowledgeEntry> loadFromDirectory(Directory dir) {
    if (!dir.existsSync()) {
      return [];
    }

    final entries = <KnowledgeEntry>[];
    final files = dir.listSync().whereType<File>().where((f) => f.path.endsWith('.md'));

    for (final file in files) {
      final text = file.readAsStringSync();
      try {
        final entry = KnowledgeEntry.parse(text, sourcePath: file.path);

        if (autoLint) {
          final lintResult = KnowledgeLint.lintEntry(entry, wordCap: wordCap);
          if (!lintResult.isValid) {
            throw FormatException(
              'Lint failed for ${file.path}:\n${lintResult.issues.map((i) => i.toString()).join('\n')}',
            );
          }
        }

        // Release guard: exclude placeholder/draft entries in release mode
        if (isRelease && entry.reviewStatus != KnowledgeReviewStatus.reviewed) {
          continue;
        }

        entries.add(entry);
      } catch (e) {
        if (autoLint) rethrow;
      }
    }

    // Deterministic ordering by entry ID
    entries.sort((a, b) => a.id.compareTo(b.id));
    return entries;
  }
}
