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

      // With public sensitivity, allows overwrite
      final rec = service.selectMethod(dev, 0.65, NistCategory.purge,
          sensitivity: DataSensitivity.public);
      expect(rec.method, SanitizationMethod.singlePassOverwrite);
    });
  });

  group('Support Level × Sensitivity Matrix — Flash media (USB)', () {
    final service = RecommendationService();

    // USB flash without firmware purge = clearOnly
    const usbFlash = DeviceProfile(
      id: 'usb1',
      name: 'USB Flash',
      serialNumber: 'USB-001',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
    );

    test('clearOnly USB + public → allows overwrite (singlePassOverwrite)', () {
      final rec = service.selectMethod(usbFlash, 0.10, NistCategory.clear,
          sensitivity: DataSensitivity.public);
      expect(rec.method, SanitizationMethod.singlePassOverwrite);
    });

    test('clearOnly USB + internal → allows overwrite', () {
      final rec = service.selectMethod(usbFlash, 0.20, NistCategory.clear,
          sensitivity: DataSensitivity.internal);
      expect(rec.method, SanitizationMethod.singlePassOverwrite);
    });

    test('clearOnly USB + confidential → Destroy (physical destruction)', () {
      final rec = service.selectMethod(usbFlash, 0.60, NistCategory.purge,
          sensitivity: DataSensitivity.confidential);
      expect(rec.method, SanitizationMethod.physicalDestructionRecommended);
      expect(rec.explanation, contains('flash blocks'));
      expect(rec.reason, contains('confidential'));
    });

    test('clearOnly USB + restricted → Destroy (physical destruction)', () {
      final rec = service.selectMethod(usbFlash, 0.80, NistCategory.destroy,
          sensitivity: DataSensitivity.restricted);
      expect(rec.method, SanitizationMethod.physicalDestructionRecommended);
      expect(rec.reason, contains('restricted'));
    });
  });

  group('Support Level × Sensitivity Matrix — Flash media (eMMC)', () {
    final service = RecommendationService();

    // eMMC without eMMC sanitize = clearOnly
    const emmc = DeviceProfile(
      id: 'emmc1',
      name: 'eMMC',
      serialNumber: 'EMMC-001',
      mediaType: MediaType.emmc,
      busType: 'eMMC',
      capacityBytes: 64000000000,
    );

    test('clearOnly eMMC + confidential → Destroy', () {
      final rec = service.selectMethod(emmc, 0.60, NistCategory.purge,
          sensitivity: DataSensitivity.confidential);
      expect(rec.method, SanitizationMethod.physicalDestructionRecommended);
    });

    test('clearOnly eMMC + public → allows overwrite', () {
      final rec = service.selectMethod(emmc, 0.10, NistCategory.clear,
          sensitivity: DataSensitivity.public);
      expect(rec.method, SanitizationMethod.singlePassOverwrite);
    });
  });

  group('Support Level × Sensitivity Matrix — SATA SSD without purge', () {
    final service = RecommendationService();

    const ssd = DeviceProfile(
      id: 'ssd1',
      name: 'SATA SSD no purge',
      serialNumber: 'SSD-001',
      mediaType: MediaType.sataSsd,
      busType: 'SATA',
      capacityBytes: 500000000,
    );

    test('clearOnly SATA SSD + confidential → Destroy', () {
      final rec = service.selectMethod(ssd, 0.60, NistCategory.purge,
          sensitivity: DataSensitivity.confidential);
      expect(rec.method, SanitizationMethod.physicalDestructionRecommended);
    });

    test('clearOnly SATA SSD + internal → existing logic (unsupported flag for destroy since no purge available)', () {
      final rec = service.selectMethod(ssd, 0.40, NistCategory.purge,
          sensitivity: DataSensitivity.internal);
      // The existing media-specific matrix for SATA SSD without sanitize/erase/encryption
      // returns unsupportedFlagForDestroy
      expect(rec.method, SanitizationMethod.unsupportedFlagForDestroy);
    });
  });

  group('Support Level × Sensitivity Matrix — HDD clearOnly (no secure erase)', () {
    final service = RecommendationService();

    const hdd = DeviceProfile(
      id: 'hdd1',
      name: 'HDD no SE',
      serialNumber: 'HDD-001',
      mediaType: MediaType.hdd,
      busType: 'SATA',
      capacityBytes: 1000000000000,
    );

    test('clearOnly HDD + confidential → NOT Destroy (overwrite is effective for magnetic media)', () {
      final rec = service.selectMethod(hdd, 0.60, NistCategory.purge,
          sensitivity: DataSensitivity.confidential);
      // HDD without secure erase under PURGE falls back to multiPassOverwrite
      expect(rec.method, SanitizationMethod.multiPassOverwrite);
      expect(rec.method, isNot(SanitizationMethod.physicalDestructionRecommended));
    });

    test('clearOnly HDD + restricted → NOT Destroy (keeps existing HDD logic)', () {
      final rec = service.selectMethod(hdd, 0.80, NistCategory.purge,
          sensitivity: DataSensitivity.restricted);
      expect(rec.method, SanitizationMethod.multiPassOverwrite);
    });

    test('clearOnly HDD + public → singlePassOverwrite under CLEAR', () {
      final rec = service.selectMethod(hdd, 0.10, NistCategory.clear,
          sensitivity: DataSensitivity.public);
      expect(rec.method, SanitizationMethod.singlePassOverwrite);
    });
  });

  group('Support Level × Sensitivity Matrix — Full support devices', () {
    final service = RecommendationService();

    const ssdFull = DeviceProfile(
      id: 'ssd_full',
      name: 'Samsung SSD',
      serialNumber: 'SSD-FULL',
      mediaType: MediaType.sataSsd,
      busType: 'SATA',
      capacityBytes: 500000000,
      supportsAtaSanitize: true,
      isHardwareEncrypted: true,
    );

    test('full SSD + public → existing logic (cryptoErase for encrypted under moderate risk)', () {
      final rec = service.selectMethod(ssdFull, 0.10, NistCategory.clear,
          sensitivity: DataSensitivity.public);
      expect(rec.method, SanitizationMethod.cryptographicErase);
    });

    test('full SSD + confidential → existing logic (cryptoErase)', () {
      final rec = service.selectMethod(ssdFull, 0.60, NistCategory.purge,
          sensitivity: DataSensitivity.confidential);
      expect(rec.method, SanitizationMethod.cryptographicErase);
    });

    test('full SSD + restricted → existing logic (cryptoErase under moderate risk)', () {
      final rec = service.selectMethod(ssdFull, 0.60, NistCategory.purge,
          sensitivity: DataSensitivity.restricted);
      expect(rec.method, SanitizationMethod.cryptographicErase);
    });
  });

  group('Unsupported media', () {
    final service = RecommendationService();

    const unknown = DeviceProfile(
      id: 'unk1',
      name: 'Unknown',
      serialNumber: 'UNK-001',
      mediaType: MediaType.unknown,
      busType: 'Unknown',
      capacityBytes: 100000000,
    );

    test('unknown media → unsupportedFlagForDestroy regardless of sensitivity', () {
      for (final sens in DataSensitivity.values) {
        final rec = service.selectMethod(unknown, 0.50, NistCategory.purge,
            sensitivity: sens);
        expect(rec.method, SanitizationMethod.unsupportedFlagForDestroy);
      }
    });
  });
}
