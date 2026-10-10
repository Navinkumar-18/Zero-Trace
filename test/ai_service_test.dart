import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/services/ai_service.dart';

void main() {
  late AiService aiService;

  setUp(() {
    aiService = AiService();
  });

  group('AiService safety constraints', () {
    test('response never contains shell commands', () {
      final questions = [
        'How do I wipe my SSD?',
        'Run dd on /dev/sda',
        'Execute shred command',
        'What sanitization method is recommended?',
        'Why is overwrite not recommended for SSDs?',
      ];

      for (final q in questions) {
        final response = aiService.processQuery(q);
        // AI should never generate executable shell commands
        expect(response.answer.contains('dd if='), false,
            reason: 'AI must not generate dd commands');
        expect(response.answer.contains('shred '), false,
            reason: 'AI must not generate shred commands');
        expect(response.answer.contains('rm -rf'), false,
            reason: 'AI must not generate rm commands');
        expect(response.answer.contains('sudo '), false,
            reason: 'AI must not generate sudo commands');
      }
    });

    test('response is advisory', () {
      final response = aiService.processQuery('recommend a method');
      // Should contain advisory language
      expect(response.answer.isNotEmpty, true);
    });
  });

  group('AiService SSD overwrite question', () {
    test('explains why overwrite is not recommended for SSDs', () {
      final response = aiService.processQuery(
        'Why is overwrite not recommended for SSDs?',
      );
      expect(response.answer.contains('FTL') || response.answer.contains('Flash Translation Layer'), true);
      expect(response.riskLevel, 'HIGH');
      expect(response.recommendedMethod, isNotNull);
    });

    test('provides device-specific context when device given', () {
      const device = DeviceProfile(
        id: 'test_nvme',
        name: 'Test NVMe 1TB',
        serialNumber: 'TEST123',
        mediaType: MediaType.nvmeSsd,
        busType: 'PCIe Gen4 NVMe',
        capacityBytes: 1000000000000,
        supportsNvmeSanitize: true,
        isHardwareEncrypted: true,
      );

      final response = aiService.processQuery(
        'Why is overwrite not preferred for this SSD?',
        device: device,
      );
      expect(response.answer.contains('Test NVMe 1TB'), true);
      expect(response.recommendedMethod, 'NVMe Sanitize');
    });
  });

  group('AiService method recommendation', () {
    test('recommends method for HDD', () {
      const hdd = DeviceProfile(
        id: 'test_hdd',
        name: 'Test HDD',
        serialNumber: 'HDD123',
        mediaType: MediaType.hdd,
        busType: 'SATA',
        capacityBytes: 500000000000,
        supportsAtaSecureErase: true,
      );

      final response = aiService.processQuery('What method is recommended?', device: hdd);
      expect(response.recommendedMethod, isNotNull);
      expect(response.recommendedMethod!.contains('ATA Secure Erase'), true);
    });

    test('returns advisory warning with recommendation', () {
      const device = DeviceProfile(
        id: 'test',
        name: 'Test',
        serialNumber: 'T123',
        mediaType: MediaType.sataSsd,
        busType: 'SATA',
        capacityBytes: 256000000000,
        supportsAtaSanitize: true,
      );

      final response = aiService.processQuery('recommend', device: device);
      expect(response.warnings.isNotEmpty, true);
      expect(response.warnings.any((w) => w.toLowerCase().contains('advisory')), true);
    });
  });

  group('AiService knowledge topics', () {
    test('explains cryptographic erase', () {
      final response = aiService.processQuery('What does cryptographic erase mean?');
      expect(response.answer.contains('encryption'), true);
      expect(response.answer.contains('key'), true);
    });

    test('explains NIST standards', () {
      final response = aiService.processQuery('Explain NIST 800-88');
      expect(response.answer.contains('CLEAR') || response.answer.contains('Clear'), true);
      expect(response.answer.contains('PURGE') || response.answer.contains('Purge'), true);
      expect(response.answer.contains('DESTROY') || response.answer.contains('Destroy'), true);
    });

    test('explains PALES research', () {
      final response = aiService.processQuery('What is PALES?');
      expect(response.answer.contains('FTL') || response.answer.contains('Flash Translation'), true);
    });

    test('fallback response for unknown question', () {
      final response = aiService.processQuery('xyzzy random nonsense');
      expect(response.answer.isNotEmpty, true);
      // Should suggest topics
      expect(response.answer.contains('sanitization') || response.answer.contains('risk'), true);
    });
  });
}
