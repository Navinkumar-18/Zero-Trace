// Task 3e wiring tests: loading the bundled knowledge base once at startup,
// skipping non-markdown assets, enforcing the release review guard, and
// falling back to the built-in handlers when no reviewed entry exists.

import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/services/knowledge/knowledge_base.dart';
import 'package:zero_trace/services/knowledge/knowledge_entry.dart';
import 'package:zero_trace/services/knowledge/knowledge_loader.dart';

/// An in-memory [AssetBundle] that serves a hand-built `AssetManifest.bin`
/// plus a set of string assets, so asset loading can be exercised in tests.
class _FakeAssetBundle extends CachingAssetBundle {
  final Map<String, String> assets;
  final List<String> manifest;

  _FakeAssetBundle({required this.assets, required this.manifest});

  @override
  Future<ByteData> load(String key) async {
    if (key == 'AssetManifest.bin') {
      final data = <String, Object?>{
        for (final a in manifest)
          a: <Object?>[
            <Object?, Object?>{'asset': a},
          ],
      };
      return const StandardMessageCodec().encodeMessage(data)!;
    }
    final text = assets[key];
    if (text == null) {
      throw Exception('Asset not found: $key');
    }
    return ByteData.sublistView(Uint8List.fromList(utf8.encode(text)));
  }
}

String _doc({
  required String id,
  required String title,
  required String status,
  required List<String> keywords,
  required String content,
}) {
  final kw = keywords.map((k) => '  - $k').join('\n');
  return '---\n'
      'id: $id\n'
      'title: $title\n'
      'review_status: $status\n'
      'last_reviewed: 2026-10-04\n'
      'topics:\n'
      '  - sanitization\n'
      'keywords:\n'
      '$kw\n'
      '---\n'
      '$content\n';
}

void main() {
  final reviewedBundle = _FakeAssetBundle(
    assets: {
      'assets/knowledge/.gitkeep': '',
      'assets/knowledge/crypto.md': _doc(
        id: 'kb_reviewed_crypto',
        title: 'Cryptographic Erase',
        status: 'reviewed',
        keywords: ['cryptographic', 'erase', 'crypto'],
        content: 'Cryptographic erase destroys the encryption key.',
      ),
      'assets/knowledge/draft.md': _doc(
        id: 'kb_placeholder_crypto',
        title: 'Cryptographic Erase Draft',
        status: 'placeholder',
        keywords: ['cryptographic', 'erase', 'crypto'],
        content: 'Draft cryptographic erase notes.',
      ),
      'assets/knowledge/partition.md': _doc(
        id: 'kb_reviewed_partition',
        title: 'Partition Table',
        status: 'reviewed',
        keywords: ['partition', 'table'],
        content: 'The partition table describes the drive layout.',
      ),
    },
    manifest: [
      'assets/knowledge/.gitkeep',
      'assets/knowledge/crypto.md',
      'assets/knowledge/draft.md',
      'assets/knowledge/partition.md',
    ],
  );

  group('KnowledgeLoader.loadFromAssets', () {
    test('loads .md entries and skips non-markdown assets', () async {
      final loader = const KnowledgeLoader(isRelease: false, autoLint: false);
      final entries = await loader.loadFromAssets(bundle: reviewedBundle);

      expect(
        entries.map((e) => e.id),
        ['kb_placeholder_crypto', 'kb_reviewed_crypto', 'kb_reviewed_partition'],
      );
      expect(entries.first.sourcePath, contains('assets/knowledge/'));
    });

    test('release mode excludes non-reviewed entries', () async {
      final loader = const KnowledgeLoader(isRelease: true, autoLint: false);
      final entries = await loader.loadFromAssets(bundle: reviewedBundle);

      expect(entries.map((e) => e.id), ['kb_reviewed_crypto', 'kb_reviewed_partition']);
      expect(entries.every((e) => e.reviewStatus == KnowledgeReviewStatus.reviewed), true);
    });

    test('missing asset dir yields an empty list', () async {
      final loader = const KnowledgeLoader(isRelease: false, autoLint: false);
      final entries = await loader.loadFromAssets(
        bundle: reviewedBundle,
        assetDir: 'assets/does_not_exist/',
      );
      expect(entries, isEmpty);
    });
  });

  group('KnowledgeBase startup wiring', () {
    tearDown(KnowledgeBase.reset);

    test('initialize() serves a reviewed entry through AiService', () async {
      KnowledgeBase.reset();
      await KnowledgeBase.initialize(bundle: reviewedBundle);

      final response = KnowledgeBase.service.processQuery('What is cryptographic erase?');
      expect(response.handlerId, 'kb');
      expect(response.kbEntryIds, contains('kb_reviewed_crypto'));
      expect(response.researchBasis, contains('Based on: Cryptographic Erase'));
    });

    test('empty/unregistered assets fall back to built-in handlers', () async {
      final emptyBundle = _FakeAssetBundle(
        assets: {'assets/knowledge/.gitkeep': ''},
        manifest: ['assets/knowledge/.gitkeep'],
      );
      KnowledgeBase.reset();
      await KnowledgeBase.initialize(bundle: emptyBundle);

      final response = KnowledgeBase.service.processQuery('What is cryptographic erase?');
      expect(response.handlerId, 'crypto_erase');
      expect(response.kbEntryIds, isEmpty);
      expect(response.researchBasis?.contains('Based on:'), isNot(true));
    });

    test('a failing bundle does not prevent startup', () async {
      final brokenBundle = _FakeAssetBundle(assets: const {}, manifest: const []);
      KnowledgeBase.reset();
      await KnowledgeBase.initialize(bundle: brokenBundle);

      final response = KnowledgeBase.service.processQuery('What is PALES research?');
      expect(response.handlerId, 'pales_research');
      expect(response.answer, isNotEmpty);
    });

    test('default service (uninitialized) answers from built-in handlers', () {
      KnowledgeBase.reset();
      final response = KnowledgeBase.service.processQuery('What is cryptographic erase?');
      expect(response.handlerId, 'crypto_erase');
      expect(response.kbEntryIds, isEmpty);
    });
  });
}
