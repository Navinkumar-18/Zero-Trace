import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/storage_capability.dart';
import 'package:zero_trace/services/ai_service.dart';
import 'package:zero_trace/services/knowledge/bm25_retriever.dart';
import 'package:zero_trace/services/knowledge/knowledge_entry.dart';
import 'package:zero_trace/services/knowledge/knowledge_lint.dart';
import 'package:zero_trace/services/knowledge/knowledge_loader.dart';

/// P4: the six reviewed knowledge entries must lint, be reachable through
/// the assistant router from real sample questions, and agree with the
/// capability matrix the UI shows.
void main() {
  List<KnowledgeEntry> loadEntries() {
    final loader = const KnowledgeLoader(isRelease: false, autoLint: true);
    return loader.loadFromDirectory(Directory('assets/knowledge'));
  }

  Map<String, KnowledgeEntry> byId(List<KnowledgeEntry> entries) =>
      {for (final e in entries) e.id: e};

  const requiredIds = [
    'clear_vs_purge',
    'nist_standards',
    'crypto_erase',
    'pales_research',
    'ssd_overwrite',
    'partition_overwrite',
  ];

  group('P4 required knowledge entries', () {
    test('all six entries ship, are reviewed and pass lint', () {
      final entries = loadEntries();
      final map = byId(entries);
      for (final id in requiredIds) {
        final entry = map[id];
        expect(entry, isNotNull, reason: 'missing knowledge entry $id');
        expect(entry!.reviewStatus, KnowledgeReviewStatus.reviewed,
            reason: '$id must be reviewed to be served in release builds');
        final lint = KnowledgeLint.lintEntry(entry);
        expect(
          lint.isValid,
          true,
          reason: '$id failed lint:\n${lint.issues.map((i) => i.toString()).join('\n')}',
        );
        expect(entry.wordCount, lessThanOrEqualTo(KnowledgeLint.defaultWordCap));
      }
    });

    test('each entry is reachable by the assistant for two sample questions',
        () {
      final retriever = BM25Retriever(loadEntries());
      final ai = AiService(retriever: retriever);

      const samples = <String, List<String>>{
        'clear_vs_purge': [
          'Explain clear vs purge assurance levels',
          'How does clear differ from purge sanitization?',
        ],
        'nist_standards': [
          'What are NIST standards?',
          'Explain the NIST SP 800-88 sanitization categories',
        ],
        'crypto_erase': [
          'What is cryptographic erase?',
          'How does crypto erase destroy the encryption key?',
        ],
        'pales_research': [
          'What is PALES research?',
          'How does the FTL affect secure deletion on flash?',
        ],
        'ssd_overwrite': [
          'Why is overwriting an SSD not reliable?',
          'Is a logical overwrite enough to purge flash storage?',
        ],
        'partition_overwrite': [
          'Explain overwriting a partition',
          'Does a partition overwrite leave other partitions untouched?',
        ],
      };

      for (final id in requiredIds) {
        final questions = samples[id]!;
        expect(questions.length, greaterThanOrEqualTo(2));
        for (final question in questions) {
          final response = ai.processQuery(question);
          expect(
            response.handlerId,
            'kb',
            reason: '"$question" did not reach the knowledge base (got '
                '${response.handlerId})',
          );
          expect(
            response.kbEntryIds,
            contains(id),
            reason: '"$question" should answer from $id, got '
                '${response.kbEntryIds}',
          );
          expect(response.researchBasis, startsWith('Based on:'));
        }
      }
    });

    test('entries agree with the capability matrix and real wipe levels', () {
      final entries = byId(loadEntries());

      CapabilityStatus statusOf(DeviceCapabilities caps, String name) =>
          caps.capabilities.firstWhere((c) => c.name == name).status;

      DeviceCapabilities caps({
        required String mediaType,
        bool hwEncrypted = false,
        bool nvme = false,
        bool ataSe = false,
        bool trim = false,
      }) =>
          DeviceCapabilities.fromDeviceFlags(
            deviceId: 'test',
            mediaType: mediaType,
            supportsAtaSecureErase: ataSe,
            supportsAtaSanitize: false,
            supportsNvmeSanitize: nvme,
            supportsEmmcSanitize: false,
            supportsTrim: trim,
            isHardwareEncrypted: hwEncrypted,
            hpaDcoPresent: false,
          );

      // Matrix: logical overwrite is not available for SSDs, available for HDDs.
      expect(
        statusOf(caps(mediaType: 'nvmeSsd', nvme: true), 'Logical Overwrite'),
        CapabilityStatus.notAvailable,
      );
      expect(
        statusOf(caps(mediaType: 'hdd', ataSe: true), 'Logical Overwrite'),
        CapabilityStatus.available,
      );

      final ssd = entries['ssd_overwrite']!.content.toLowerCase();
      expect(ssd, contains('not available'));
      expect(ssd, contains('trim'));
      expect(ssd, contains('insufficient'));
      expect(ssd, contains('clear'));

      // Matrix: cryptographic erase only when hardware encryption is detected.
      expect(
        statusOf(caps(mediaType: 'nvmeSsd', nvme: true), 'Cryptographic Erase'),
        CapabilityStatus.notAvailable,
      );
      expect(
        statusOf(
          caps(mediaType: 'nvmeSsd', nvme: true, hwEncrypted: true),
          'Cryptographic Erase',
        ),
        CapabilityStatus.available,
      );
      final crypto = entries['crypto_erase']!.content.toLowerCase();
      expect(crypto, contains('hardware encryption is detected'));
      expect(crypto, contains('purge'));

      // Clear-level behavior: partition and flash wipes are Clear, and Purge
      // needs a hardware command on the whole device.
      final clear = entries['clear_vs_purge']!.content.toLowerCase();
      expect(clear, contains('hardware command'));
      expect(clear, contains('whole device'));
      final part = entries['partition_overwrite']!.content.toLowerCase();
      expect(part, contains('partition table'));
      expect(part, contains('not a purge'));
      expect(part, contains('clear'));

      for (final id in [
        'ssd_overwrite',
        'partition_overwrite',
        'clear_vs_purge',
      ]) {
        final body = entries[id]!.content.toLowerCase();
        expect(
          RegExp(r'(achieves|reaches|provides|satisfies)\s+purge').hasMatch(body),
          isFalse,
          reason: '$id must not claim a Clear-level wipe achieves Purge',
        );
      }
    });
  });
}
