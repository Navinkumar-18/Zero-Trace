import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/assistant_context.dart';
import 'package:zero_trace/models/sanitization_error_code.dart';
import 'package:zero_trace/services/ai_service.dart';
import 'package:zero_trace/services/knowledge/bm25_retriever.dart';
import 'package:zero_trace/services/knowledge/knowledge_entry.dart';
import 'package:zero_trace/services/knowledge/knowledge_loader.dart';

void main() {
  final fixtureDir = Directory('test/fixtures/knowledge');

  group('Release Guard Tests (Item 11)', () {
    test('excludes placeholder and draft entries when release flag is true', () {
      final releaseLoader = const KnowledgeLoader(isRelease: true, autoLint: false);
      final releaseEntries = releaseLoader.loadFromDirectory(fixtureDir);

      // The fixtures in test/fixtures/knowledge are all review_status: placeholder
      expect(
        releaseEntries.isEmpty,
        true,
        reason: 'In release mode, all placeholder entries must be excluded',
      );
    });

    test('includes placeholder entries when release flag is false', () {
      final devLoader = const KnowledgeLoader(isRelease: false, autoLint: false);
      final devEntries = devLoader.loadFromDirectory(fixtureDir);

      expect(
        devEntries.length,
        greaterThanOrEqualTo(3),
        reason: 'In dev/test mode, placeholder entries must be loaded',
      );
      expect(
        devEntries.every((e) => e.reviewStatus == KnowledgeReviewStatus.placeholder),
        true,
      );
    });
  });

  group('Precedence and Integration Tests (Item 10)', () {
    late KnowledgeEntry reviewedEntry;
    late KnowledgeEntry placeholderEntry;
    late BM25Retriever mixedRetriever;

    setUp(() {
      reviewedEntry = KnowledgeEntry(
        id: 'kb_reviewed_clear_purge',
        title: 'NIST SP 800-88 Clear and Purge Guidelines',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['sanitization', 'nist'],
        keywords: ['clear', 'purge', 'guidelines'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'Reviewed explanation of clear vs purge sanitization standards.',
      );

      placeholderEntry = KnowledgeEntry(
        id: 'kb_placeholder_crypto',
        title: 'Cryptographic Erase Guidance',
        reviewStatus: KnowledgeReviewStatus.placeholder,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['encryption'],
        keywords: ['crypto', 'cryptographic', 'erase'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'Draft/placeholder explanation of cryptographic erase.',
      );

      mixedRetriever = BM25Retriever(
        [reviewedEntry, placeholderEntry],
        confidenceThreshold: 0.1,
      );
    });

    test('state handlers always answer from AssistantContext (KB adds explanation only)', () {
      final aiService = AiService(retriever: mixedRetriever);
      const errorContext = AssistantContext(
        lastErrorCode: SanitizationErrorCode.permissionDenied,
        platform: 'Linux',
      );

      final response = aiService.processQuery(
        'Explain this error: permissionDenied',
        context: errorContext,
      );

      // State handler takes precedence
      expect(response.handlerId, 'error_explanation');
      expect(response.answer, contains('elevated administrative authority'));
      expect(response.kbEntryIds, isEmpty);
    });

    test('conceptual handler uses KB entry ONLY if a reviewed entry matches', () {
      final aiService = AiService(retriever: mixedRetriever);

      // Query that matches the reviewed entry
      final reviewedResponse = aiService.processQuery('Explain CLEAR vs PURGE');

      expect(reviewedResponse.handlerId, 'kb');
      expect(reviewedResponse.kbEntryIds, contains('kb_reviewed_clear_purge'));
      expect(reviewedResponse.researchBasis, contains('Based on: NIST SP 800-88 Clear and Purge Guidelines'));
      expect(reviewedResponse.answer, reviewedEntry.content);
    });

    test('conceptual handler falls back to legacy handler with NO "Based on" line if only placeholder matches', () {
      final aiService = AiService(retriever: mixedRetriever);

      // Query that matches placeholderEntry ('crypto erase')
      // Since placeholderEntry is reviewStatus == placeholder, it must NOT be used
      final legacyResponse = aiService.processQuery('What is cryptographic erase?');

      expect(
        legacyResponse.handlerId,
        'crypto_erase',
        reason: 'Must fall back to legacy handler when matched KB entry is not reviewed',
      );
      expect(legacyResponse.kbEntryIds, isEmpty);
      expect(
        legacyResponse.researchBasis?.contains('Based on:'),
        isNot(true),
        reason: 'Legacy handler response must NOT contain a "Based on" line',
      );
      expect(legacyResponse.answer, contains('Cryptographic Erase destroys the encryption key'));
    });

    test('exactly one answer is returned for all queries', () {
      final aiService = AiService(retriever: mixedRetriever);

      final queries = [
        'Explain CLEAR vs PURGE',
        'What does cryptographic erase mean?',
        'Why did verification fail?',
        'Why did the sanitization fail?',
        'What is PALES research?',
      ];

      for (final q in queries) {
        final response = aiService.processQuery(q);
        expect(response.answer, isNotEmpty);
        // Ensure no duplicated concatenation of multiple handlers
        expect(
          response.answer.split('Based on:').length,
          lessThanOrEqualTo(2),
        );
      }
    });

    test('simulated-mode disclaimers still apply to KB answers', () {
      final aiService = AiService(retriever: mixedRetriever);
      const simContext = AssistantContext(isSimulated: true);

      final response = aiService.processQuery(
        'Explain CLEAR vs PURGE',
        context: simContext,
      );

      expect(response.handlerId, 'kb');
      expect(response.isSimulated, true);
      expect(response.answer, contains('[SIMULATION MODE]'));
      expect(response.warnings.any((w) => w.contains('[SIMULATION MODE]')), true);
    });
  });
}
