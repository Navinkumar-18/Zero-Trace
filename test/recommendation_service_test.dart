import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/recommendation_service.dart';

void main() {
  group('Algorithm 2 — RecommendationService Tests', () {
    final service = RecommendationService();

    test('High risk targetCategory DESTROY returns PHYSICAL_DESTRUCTION_RECOMMENDED', () {
      const dev = DeviceProfile(
        id: '1',
        name: 'SSD',
        serialNumber: 'S1',
        mediaType: MediaType.sataSsd,
        busType: 'SATA',
        capacityBytes: 500000000,
      );

      final rec = service.selectMethod(dev, 0.95, NistCategory.destroy);
      expect(rec.method, SanitizationMethod.physicalDestructionRecommended);
      expect(rec.standardReference, contains('NIST SP 800-88r2 Destroy'));
    });

    test('Hardware encrypted SSD under PURGE recommends CRYPTOGRAPHIC_ERASE', () {
      const dev = DeviceProfile(
        id: '2',
        name: 'OPAL SSD',
        serialNumber: 'S2',
        mediaType: MediaType.sataSsd,
        busType: 'SATA',
        capacityBytes: 500000000,
        isHardwareEncrypted: true,
      );

      final rec = service.selectMethod(dev, 0.60, NistCategory.purge);
      expect(rec.method, SanitizationMethod.cryptographicErase);
    });

    test('NVMe SSD with Sanitize capability returns NVME_SANITIZE', () {
      const dev = DeviceProfile(
        id: '3',
        name: 'NVMe Drive',
        serialNumber: 'S3',
        mediaType: MediaType.nvmeSsd,
        busType: 'NVMe',
        capacityBytes: 1000000000,
        supportsNvmeSanitize: true,
      );

      final rec = service.selectMethod(dev, 0.60, NistCategory.purge);
      expect(rec.method, SanitizationMethod.nvmeSanitize);
    });

    test('USB flash under PURGE without hardware sanitize falls back to singlePassOverwrite (NIST Clear)', () {
      const dev = DeviceProfile(
        id: '4',
        name: 'Legacy USB',
        serialNumber: 'S4',
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        capacityBytes: 1600000000,
        supportsEmmcSanitize: false,
      );

      final rec = service.selectMethod(dev, 0.65, NistCategory.purge);
      expect(rec.method, SanitizationMethod.singlePassOverwrite);
    });
  });
}
