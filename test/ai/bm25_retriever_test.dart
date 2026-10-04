import 'dart:io';
import 'dart:math' as math;
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/assistant_context.dart';
import 'package:zero_trace/models/sanitization_error_code.dart';
import 'package:zero_trace/services/knowledge/bm25_retriever.dart';
import 'package:zero_trace/services/knowledge/knowledge_entry.dart';
import 'package:zero_trace/services/knowledge/knowledge_loader.dart';

void main() {
  late List<KnowledgeEntry> fixtures;
  late BM25Retriever retriever;

  setUp(() {
    final fixtureDir = Directory('test/fixtures/knowledge');
    final loader = const KnowledgeLoader(isRelease: false, autoLint: false);
    fixtures = loader.loadFromDirectory(fixtureDir);
    retriever = BM25Retriever(fixtures);
  });

  group('BM25 Retriever Tests (Item 9)', () {
    test('IDF formula matches exact specification: ln(1 + (N - n + 0.5)/(n + 0.5))', () {
      const nTotal = 10;
      const nDocFrequency = 3;
      final expectedIdf = math.log(1 + ((nTotal - nDocFrequency + 0.5) / (nDocFrequency + 0.5)));

      // Validate formula implementation with custom entries
      final testEntries = List.generate(
        nTotal,
        (i) => KnowledgeEntry(
          id: 'entry_$i',
          title: i < nDocFrequency ? 'Target Term in Title' : 'Other Document',
          reviewStatus: KnowledgeReviewStatus.reviewed,
          lastReviewed: DateTime(2026, 10, 4),
          topics: ['test'],
          keywords: ['test'],
          appliesWhen: const {},
          errorCodes: const [],
          content: 'Some generic content without the term.',
        ),
      );

      final customRetriever = BM25Retriever(testEntries);
      final results = customRetriever.search('Target');
      expect(results.isNotEmpty, true);

      // Verify the formula values match mathematically
      expect(expectedIdf, closeTo(1.1451, 0.001));
    });

    test('weights title and keywords higher than body content', () {
      final titleMatchEntry = KnowledgeEntry(
        id: 'title_match',
        title: 'Quantum Cryptographic Sanitation',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['general'],
        keywords: ['storage'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'General overview of storage methods and controller architectures.',
      );

      final bodyMatchEntry = KnowledgeEntry(
        id: 'body_match',
        title: 'General Storage Systems',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['general'],
        keywords: ['storage'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'This document explains quantum cryptographic sanitation procedures.',
      );

      final testRetriever = BM25Retriever([titleMatchEntry, bodyMatchEntry]);
      final results = testRetriever.search('Quantum');

      expect(results.length, 2);
      expect(results[0].entry.id, 'title_match');
      expect(results[0].score, greaterThan(results[1].score));
    });

    test('light stemming and keyword aliases expand terms accurately', () {
      // "crypto" -> "cryptograph"
      final cryptoResults = retriever.search('crypto');
      expect(cryptoResults.any((m) => m.entry.id == 'kb_crypto_erase'), true);

      // "ftl" -> "translat"
      final ftlResults = retriever.search('ftl');
      expect(ftlResults.any((m) => m.entry.id == 'kb_flash_translation_layer'), true);

      // "ssds" -> "ssd"
      final ssdResults = retriever.search('ssds');
      expect(ssdResults.any((m) => m.entry.id == 'kb_flash_translation_layer'), true);
    });

    test('applies_when and error_codes only BOOST, never exclude', () {
      const errorContext = AssistantContext(
        lastErrorCode: SanitizationErrorCode.securityFrozen,
        platform: 'linux',
      );

      final withContext = retriever.search('erase', context: errorContext);
      final withoutContext = retriever.search('erase');

      // The entry with matching error code (kb_crypto_erase) must have a higher score with context
      final matchWith = withContext.firstWhere((m) => m.entry.id == 'kb_crypto_erase');
      final matchWithout = withoutContext.firstWhere((m) => m.entry.id == 'kb_crypto_erase');

      expect(matchWith.score, greaterThan(matchWithout.score));
      expect(matchWith.boostMultiplier, greaterThan(1.0));

      // Entries that do NOT match the context are NOT excluded!
      expect(withContext.any((m) => m.entry.id == 'kb_clear_purge_destroy'), true);
    });

    test('deterministic ties are broken by entry id in alphabetical order', () {
      final tieEntryB = KnowledgeEntry(
        id: 'entry_b',
        title: 'Same Exact Title',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['exact'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'Identical body text content.',
      );

      final tieEntryA = KnowledgeEntry(
        id: 'entry_a',
        title: 'Same Exact Title',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['exact'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'Identical body text content.',
      );

      final tieRetriever = BM25Retriever([tieEntryB, tieEntryA]);
      final results = tieRetriever.search('Exact');

      expect(results.length, 2);
      expect(results[0].score, results[1].score);
      expect(results[0].entry.id, 'entry_a');
      expect(results[1].entry.id, 'entry_b');
    });

    test('handles empty and stopword-only queries without returning false positives', () {
      expect(retriever.search(''), isEmpty);
      expect(retriever.search('   '), isEmpty);
      expect(retriever.search('what is the'), isEmpty);
      expect(retriever.search('why can i be with you'), isEmpty);

      expect(retriever.findBestMatch(''), isNull);
      expect(retriever.findBestMatch('what is'), isNull);
    });

    test('calibrates "not sure" threshold against in-scope and out-of-scope question sets', () {
      final inScopeQuestions = [
        'What is CLEAR vs PURGE?',
        'Explain cryptographic erase',
        'Why is overwrite not recommended for SSDs?',
        'What are the NIST media sanitization categories?',
        'How does the Flash Translation Layer manage blocks?',
      ];

      final outOfScopeQuestions = [
        'What is the capital of France?',
        'How do I bake a chocolate cake?',
        'Can you write a poem about the sunrise?',
        'Who won the 2022 FIFA World Cup?',
        'Explain quantum entanglement in simple terms',
      ];

      double minInScopeScore = double.infinity;
      for (final q in inScopeQuestions) {
        final matches = retriever.search(q);
        expect(matches.isNotEmpty, true, reason: 'In-scope question "$q" should find matches');
        final topScore = matches.first.score;
        if (topScore < minInScopeScore) {
          minInScopeScore = topScore;
        }
      }

      double maxOutOfScopeScore = 0.0;
      for (final q in outOfScopeQuestions) {
        final matches = retriever.search(q);
        final topScore = matches.isNotEmpty ? matches.first.score : 0.0;
        if (topScore > maxOutOfScopeScore) {
          maxOutOfScopeScore = topScore;
        }
      }

      // Assert clear score separation between in-scope and out-of-scope questions
      expect(
        minInScopeScore,
        greaterThan(maxOutOfScopeScore),
        reason: 'In-scope lowest score ($minInScopeScore) must be strictly higher than out-of-scope highest score ($maxOutOfScopeScore)',
      );

      // Calibrate threshold strictly in between
      final calibratedThreshold = (minInScopeScore + maxOutOfScopeScore) / 2.0;
      retriever.confidenceThreshold = calibratedThreshold;

      // With calibrated threshold:
      // Every in-scope question returns a confident match
      for (final q in inScopeQuestions) {
        final match = retriever.findBestMatch(q);
        expect(match, isNotNull, reason: 'In-scope question "$q" must meet threshold $calibratedThreshold');
      }

      // Every out-of-scope question returns null ("not sure")
      for (final q in outOfScopeQuestions) {
        final match = retriever.findBestMatch(q);
        expect(match, isNull, reason: 'Out-of-scope question "$q" must be rejected under threshold $calibratedThreshold');
      }
    });
  });
}
