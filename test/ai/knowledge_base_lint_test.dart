import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/sanitization_error_code.dart';
import 'package:zero_trace/services/knowledge/knowledge_entry.dart';
import 'package:zero_trace/services/knowledge/knowledge_lint.dart';
import 'package:zero_trace/services/knowledge/knowledge_loader.dart';

void main() {
  group('Knowledge Base Lint Tests (Item 8)', () {
    test('all placeholder fixtures in test/fixtures/knowledge/ pass linting', () {
      final fixtureDir = Directory('test/fixtures/knowledge');
      expect(fixtureDir.existsSync(), true, reason: 'test/fixtures/knowledge directory must exist');

      final loader = const KnowledgeLoader(isRelease: false, autoLint: true);
      final entries = loader.loadFromDirectory(fixtureDir);

      expect(entries.length, greaterThanOrEqualTo(3));
      for (final entry in entries) {
        final result = KnowledgeLint.lintEntry(entry);
        expect(
          result.isValid,
          true,
          reason: 'Entry ${entry.id} failed linting:\n${result.issues.map((i) => i.toString()).join('\n')}',
        );
      }
    });

    test('flags forbidden commands with word boundary checks', () {
      final forbiddenCommands = [
        'dd',
        'hdparm',
        'nvme format',
        'mkfs',
        'wipefs',
        'blkdiscard',
        'shred',
        'sudo',
      ];

      for (final cmd in forbiddenCommands) {
        final badEntry = KnowledgeEntry(
          id: 'bad_cmd_$cmd',
          title: 'Testing Command $cmd',
          reviewStatus: KnowledgeReviewStatus.reviewed,
          lastReviewed: DateTime(2026, 10, 4),
          topics: ['test'],
          keywords: ['command'],
          appliesWhen: const {},
          errorCodes: const [],
          content: 'You should run $cmd to clean the drive.',
        );

        final result = KnowledgeLint.lintEntry(badEntry);
        expect(
          result.issues.any((i) => i.rule == 'forbidden_command'),
          true,
          reason: 'Command "$cmd" must be caught by word-boundary regex linter',
        );
      }

      // Word boundary negative test: "shredded", "padded", "pseudo" must not trigger false positives
      final benignEntry = KnowledgeEntry(
        id: 'benign_words',
        title: 'Benign Words',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'The document was shredded and padded with pseudo numbers.',
      );
      final benignResult = KnowledgeLint.lintEntry(benignEntry);
      expect(benignResult.issues.any((i) => i.rule == 'forbidden_command'), false);
    });

    test('bans code fences and inline code', () {
      final codeFenceEntry = KnowledgeEntry(
        id: 'code_fence',
        title: 'Code Fence Entry',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'Run this:\n```bash\necho hello\n```',
      );
      expect(
        KnowledgeLint.lintEntry(codeFenceEntry).issues.any((i) => i.rule == 'code_fence_forbidden'),
        true,
      );

      final inlineCodeEntry = KnowledgeEntry(
        id: 'inline_code',
        title: 'Inline Code Entry',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'Use `blkdiscard` or similar tools.',
      );
      expect(
        KnowledgeLint.lintEntry(inlineCodeEntry).issues.any((i) => i.rule == 'inline_code_forbidden'),
        true,
      );
    });

    test('flags overclaim words unless inline marker <!-- lint-allow: <word> --> is present in the same paragraph', () {
      final overclaims = ['guaranteed', 'unrecoverable', 'military-grade', '100% secure'];

      for (final word in overclaims) {
        final unapprovedEntry = KnowledgeEntry(
          id: 'unapproved_$word',
          title: 'Unapproved Claim',
          reviewStatus: KnowledgeReviewStatus.reviewed,
          lastReviewed: DateTime(2026, 10, 4),
          topics: ['test'],
          keywords: ['test'],
          appliesWhen: const {},
          errorCodes: const [],
          content: 'This method is $word for all storage.',
        );

        expect(
          KnowledgeLint.lintEntry(unapprovedEntry).issues.any((i) => i.rule == 'overclaim_word'),
          true,
          reason: 'Word "$word" must be flagged as an overclaim without inline allowance marker',
        );

        final approvedEntry = KnowledgeEntry(
          id: 'approved_$word',
          title: 'Approved Claim',
          reviewStatus: KnowledgeReviewStatus.reviewed,
          lastReviewed: DateTime(2026, 10, 4),
          topics: ['test'],
          keywords: ['test'],
          appliesWhen: const {},
          errorCodes: const [],
          content: 'This method is $word <!-- lint-allow: $word --> under controlled settings.',
        );

        expect(
          KnowledgeLint.lintEntry(approvedEntry).issues.any((i) => i.rule == 'overclaim_word'),
          false,
          reason: 'Word "$word" must be permitted when <!-- lint-allow: $word --> is present',
        );
      }
    });

    test('lint-allow must name exact word and does not silence a different overclaim word (Item 7)', () {
      // One marker (<!-- lint-allow: guaranteed -->) must NOT silence "military-grade"
      final mismatchedEntry = KnowledgeEntry(
        id: 'mismatched_marker',
        title: 'Mismatched Marker Entry',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'This erasure is military-grade <!-- lint-allow: guaranteed --> under testing.',
      );

      final result = KnowledgeLint.lintEntry(mismatchedEntry);
      expect(
        result.issues.any((i) => i.rule == 'overclaim_word' && i.message.contains('military-grade')),
        true,
        reason: 'Marker for "guaranteed" must NOT silence "military-grade"',
      );
    });

    test('lint-allow marker in one paragraph does NOT silence word in a different paragraph (Item 7)', () {
      final multiParagraphEntry = KnowledgeEntry(
        id: 'cross_paragraph_marker',
        title: 'Cross Paragraph Marker Entry',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'Paragraph 1: Sanitization is guaranteed <!-- lint-allow: guaranteed --> in lab conditions.\n\n'
            'Paragraph 2: Media erasure is guaranteed on magnetic media.',
      );

      final result = KnowledgeLint.lintEntry(multiParagraphEntry);
      expect(
        result.issues.any((i) => i.rule == 'overclaim_word'),
        true,
        reason: 'Marker in paragraph 1 must NOT silence "guaranteed" in paragraph 2',
      );
    });

    test('blocks Section/§/Table/Clause/Appendix + number', () {
      final badCitations = [
        'See Section 2.4.1 for details',
        'Complies with § 3',
        'Refer to Table A-1',
        'Under Clause 5.2',
        'As defined in Appendix B',
      ];

      for (final citation in badCitations) {
        final entry = KnowledgeEntry(
          id: 'bad_citation',
          title: 'Brittle Citation',
          reviewStatus: KnowledgeReviewStatus.reviewed,
          lastReviewed: DateTime(2026, 10, 4),
          topics: ['test'],
          keywords: ['test'],
          appliesWhen: const {},
          errorCodes: const [],
          content: 'Media sanitization guidance: $citation.',
        );

        expect(
          KnowledgeLint.lintEntry(entry).issues.any((i) => i.rule == 'brittle_citation_forbidden'),
          true,
          reason: 'Citation "$citation" must be blocked',
        );
      }
    });

    test('validates error_codes against SanitizationErrorCode', () {
      final badErrorCodeEntry = KnowledgeEntry(
        id: 'bad_error_code',
        title: 'Bad Error Code',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {},
        errorCodes: const [],
        content: 'Some content.',
        rawMetadata: const {
          'error_codes': ['nonExistentErrorCodeXYZ'],
        },
      );

      final result = KnowledgeLint.lintEntry(badErrorCodeEntry);
      expect(result.issues.any((i) => i.rule == 'invalid_error_code'), true);

      final validErrorCodeEntry = KnowledgeEntry(
        id: 'valid_error_code',
        title: 'Valid Error Code',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {},
        errorCodes: [SanitizationErrorCode.permissionDenied],
        content: 'Some content.',
        rawMetadata: const {
          'error_codes': ['permissionDenied'],
        },
      );
      expect(KnowledgeLint.lintEntry(validErrorCodeEntry).issues.any((i) => i.rule == 'invalid_error_code'), false);
    });

    test('validates applies_when keys and platform values', () {
      final badKeyEntry = KnowledgeEntry(
        id: 'bad_key',
        title: 'Bad Key',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {'unauthorized_key': 'value'},
        errorCodes: const [],
        content: 'Content',
      );
      expect(KnowledgeLint.lintEntry(badKeyEntry).issues.any((i) => i.rule == 'invalid_applies_when_key'), true);

      final badPlatformEntry = KnowledgeEntry(
        id: 'bad_platform',
        title: 'Bad Platform',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {'platform': 'solaris_bsd'},
        errorCodes: const [],
        content: 'Content',
      );
      expect(KnowledgeLint.lintEntry(badPlatformEntry).issues.any((i) => i.rule == 'invalid_platform'), true);
    });

    test('enforces word cap per entry', () {
      final longContent = List.generate(350, (i) => 'word$i').join(' ');
      final longEntry = KnowledgeEntry(
        id: 'long_entry',
        title: 'Long Entry',
        reviewStatus: KnowledgeReviewStatus.reviewed,
        lastReviewed: DateTime(2026, 10, 4),
        topics: ['test'],
        keywords: ['test'],
        appliesWhen: const {},
        errorCodes: const [],
        content: longContent,
      );

      final result = KnowledgeLint.lintEntry(longEntry, wordCap: 300);
      expect(result.issues.any((i) => i.rule == 'word_cap_exceeded'), true);
    });
  });
}
