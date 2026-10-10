import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_support_level.dart';

void main() {
  group('SanitizationSupportLevel.computeSupportLevel', () {
    test('HDD with ATA Secure Erase → full', () {
      const dev = DeviceProfile(
        id: '1', name: 'HDD', serialNumber: 'S1',
        mediaType: MediaType.hdd, busType: 'SATA',
        capacityBytes: 500000000,
        supportsAtaSecureErase: true,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.full);
    });

    test('HDD without any firmware support → clearOnly', () {
      const dev = DeviceProfile(
        id: '2', name: 'HDD', serialNumber: 'S2',
        mediaType: MediaType.hdd, busType: 'SATA',
        capacityBytes: 500000000,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.clearOnly);
    });

    test('SATA SSD with ATA Sanitize → full', () {
      const dev = DeviceProfile(
        id: '3', name: 'SSD', serialNumber: 'S3',
        mediaType: MediaType.sataSsd, busType: 'SATA',
        capacityBytes: 500000000,
        supportsAtaSanitize: true,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.full);
    });

    test('SATA SSD with hardware encryption only → full', () {
      const dev = DeviceProfile(
        id: '4', name: 'SSD', serialNumber: 'S4',
        mediaType: MediaType.sataSsd, busType: 'SATA',
        capacityBytes: 500000000,
        isHardwareEncrypted: true,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.full);
    });

    test('SATA SSD without any purge capability → clearOnly', () {
      const dev = DeviceProfile(
        id: '5', name: 'SSD', serialNumber: 'S5',
        mediaType: MediaType.sataSsd, busType: 'SATA',
        capacityBytes: 500000000,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.clearOnly);
    });

    test('NVMe SSD with NVMe Sanitize → full', () {
      const dev = DeviceProfile(
        id: '6', name: 'NVMe', serialNumber: 'S6',
        mediaType: MediaType.nvmeSsd, busType: 'NVMe',
        capacityBytes: 1000000000,
        supportsNvmeSanitize: true,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.full);
    });

    test('NVMe SSD without any purge → clearOnly', () {
      const dev = DeviceProfile(
        id: '7', name: 'NVMe', serialNumber: 'S7',
        mediaType: MediaType.nvmeSsd, busType: 'NVMe',
        capacityBytes: 1000000000,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.clearOnly);
    });

    test('eMMC with eMMC Sanitize → full', () {
      const dev = DeviceProfile(
        id: '8', name: 'eMMC', serialNumber: 'S8',
        mediaType: MediaType.emmc, busType: 'eMMC',
        capacityBytes: 64000000000,
        supportsEmmcSanitize: true,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.full);
    });

    test('eMMC without sanitize → clearOnly', () {
      const dev = DeviceProfile(
        id: '9', name: 'eMMC', serialNumber: 'S9',
        mediaType: MediaType.emmc, busType: 'eMMC',
        capacityBytes: 64000000000,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.clearOnly);
    });

    test('USB flash without any firmware support → clearOnly', () {
      const dev = DeviceProfile(
        id: '10', name: 'USB', serialNumber: 'S10',
        mediaType: MediaType.usbFlash, busType: 'USB',
        capacityBytes: 16000000000,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.clearOnly);
    });

    test('Unknown media type → unsupported', () {
      const dev = DeviceProfile(
        id: '11', name: 'Unknown', serialNumber: 'S11',
        mediaType: MediaType.unknown, busType: 'Unknown',
        capacityBytes: 100000000,
      );
      expect(computeSupportLevel(dev), SanitizationSupportLevel.unsupported);
    });
  });

  group('supportLevelReason', () {
    test('HDD clearOnly mentions magnetic media', () {
      const dev = DeviceProfile(
        id: '1', name: 'HDD', serialNumber: 'S1',
        mediaType: MediaType.hdd, busType: 'SATA',
        capacityBytes: 500000000,
      );
      final reason = supportLevelReason(dev);
      expect(reason, contains('magnetic media'));
    });

    test('USB flash clearOnly mentions flash blocks', () {
      const dev = DeviceProfile(
        id: '2', name: 'USB', serialNumber: 'S2',
        mediaType: MediaType.usbFlash, busType: 'USB',
        capacityBytes: 16000000000,
      );
      final reason = supportLevelReason(dev);
      expect(reason, contains('flash blocks'));
    });

    test('Full support with encryption mentions cryptographic', () {
      const dev = DeviceProfile(
        id: '3', name: 'SSD', serialNumber: 'S3',
        mediaType: MediaType.sataSsd, busType: 'SATA',
        capacityBytes: 500000000,
        isHardwareEncrypted: true,
      );
      final reason = supportLevelReason(dev);
      expect(reason, contains('cryptographic'));
    });

    test('Full support with sanitize mentions firmware', () {
      const dev = DeviceProfile(
        id: '4', name: 'NVMe', serialNumber: 'S4',
        mediaType: MediaType.nvmeSsd, busType: 'NVMe',
        capacityBytes: 1000000000,
        supportsNvmeSanitize: true,
      );
      final reason = supportLevelReason(dev);
      expect(reason, contains('Firmware'));
    });

    test('Unknown device mentions capability cannot be determined', () {
      const dev = DeviceProfile(
        id: '5', name: 'Unknown', serialNumber: 'S5',
        mediaType: MediaType.unknown, busType: 'Unknown',
        capacityBytes: 100000000,
      );
      final reason = supportLevelReason(dev);
      expect(reason, contains('cannot be determined'));
    });
  });

  group('SanitizationSupportLevel extension', () {
    test('displayName values are correct', () {
      expect(SanitizationSupportLevel.full.displayName, 'Full support');
      expect(SanitizationSupportLevel.clearOnly.displayName, 'Clear-only');
      expect(SanitizationSupportLevel.unsupported.displayName, 'Unsupported');
    });

    test('badgeLabel values are correct', () {
      expect(SanitizationSupportLevel.full.badgeLabel, 'FULL SUPPORT');
      expect(SanitizationSupportLevel.clearOnly.badgeLabel, 'CLEAR-ONLY');
      expect(SanitizationSupportLevel.unsupported.badgeLabel, 'UNSUPPORTED');
    });

    test('serializedName returns enum name', () {
      expect(SanitizationSupportLevel.full.serializedName, 'full');
      expect(SanitizationSupportLevel.clearOnly.serializedName, 'clearOnly');
      expect(SanitizationSupportLevel.unsupported.serializedName, 'unsupported');
    });
  });
}
