import 'dart:io';

import 'package:flutter/foundation.dart' show kReleaseMode;
import 'package:flutter/services.dart' show AssetBundle, AssetManifest, rootBundle;

import 'knowledge_entry.dart';
import 'knowledge_lint.dart';

class KnowledgeLoader {
  final bool isRelease;
  final bool autoLint;

  /// Maximum body word count enforced by [KnowledgeLint] when [autoLint] is on.
  final int wordCap;

  const KnowledgeLoader({
    this.isRelease = false,
    this.autoLint = true,
    this.wordCap = KnowledgeLint.defaultWordCap,
  });

  /// Production loader: release guard follows `kReleaseMode`.
  factory KnowledgeLoader.production({bool autoLint = false}) {
    return KnowledgeLoader(isRelease: kReleaseMode, autoLint: autoLint);
  }

  /// Loads every `.md` entry from a filesystem directory, sorted by id.
  ///
  /// If [isRelease] is true, entries whose review status is not
  /// [KnowledgeReviewStatus.reviewed] are excluded.
  List<KnowledgeEntry> loadFromDirectory(Directory dir) {
    if (!dir.existsSync()) return [];

    final files = dir
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith('.md'))
        .toList()
      ..sort((a, b) => a.path.compareTo(b.path));

    final entries = <KnowledgeEntry>[];
    for (final file in files) {
      try {
        final entry = _ingest(file.readAsStringSync(), file.path);
        if (isServable(entry)) entries.add(entry);
      } catch (_) {
        if (autoLint) rethrow;
      }
    }
    entries.sort((a, b) => a.id.compareTo(b.id));
    return entries;
  }

  /// Loads every `.md` entry bundled under [assetDir] using [bundle]
  /// (defaults to `rootBundle`). Non-markdown assets are skipped.
  ///
  /// Applies the same release guard and optional linting as
  /// [loadFromDirectory].
  Future<List<KnowledgeEntry>> loadFromAssets({
    AssetBundle? bundle,
    String assetDir = 'assets/knowledge/',
  }) async {
    final resolved = bundle ?? rootBundle;
    final manifest = await AssetManifest.loadFromAssetBundle(resolved);
    final keys = manifest
        .listAssets()
        .where((k) => k.startsWith(assetDir) && k.endsWith('.md'))
        .toList()
      ..sort();

    final entries = <KnowledgeEntry>[];
    for (final key in keys) {
      try {
        final entry = _ingest(await resolved.loadString(key), key);
        if (isServable(entry)) entries.add(entry);
      } catch (_) {
        if (autoLint) rethrow;
      }
    }
    entries.sort((a, b) => a.id.compareTo(b.id));
    return entries;
  }

  /// Parses and optionally lints a single raw entry. Parse/lint failures
  /// propagate to the caller.
  KnowledgeEntry _ingest(String rawText, String sourcePath) {
    final entry = KnowledgeEntry.parse(rawText, sourcePath: sourcePath);

    if (autoLint) {
      final lintResult = KnowledgeLint.lintEntry(entry, wordCap: wordCap);
      if (!lintResult.isValid) {
        throw FormatException(
          'Lint failed for $sourcePath:\n'
          '${lintResult.issues.map((i) => i.toString()).join('\n')}',
        );
      }
    }

    return entry;
  }

  /// True when [entry] is allowed to be served in the current build.
  bool isServable(KnowledgeEntry entry) =>
      !isRelease || entry.reviewStatus == KnowledgeReviewStatus.reviewed;
}
