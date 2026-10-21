import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/services/classification_service.dart';

void main() {
  group('Algorithm 1 — ClassificationService Tests', () {
    final service = ClassificationService();

    test('Classifies HDD properly based on rotational RPM', () {
      const hdd = DeviceProfile(
        id: '1',
        name: 'Seagate HDD',
        serialNumber: '123',
        mediaType: MediaType.hdd,
        busType: 'SATA',
        capacityBytes: 1000000000,
        rotationalRpm: 7200,
      );

      final result = service.classify(hdd);
      expect(result.mediaType, MediaType.hdd);
      expect(result.isConfident, isTrue);
    });

    test('Classifies NVMe SSD based on bus type string', () {
      const nvme = DeviceProfile(
        id: '2',
        name: 'WD NVMe',
        serialNumber: '456',
        mediaType: MediaType.nvmeSsd,
        busType: 'PCIe NVMe 1.4',
        capacityBytes: 1000000000,
        rotationalRpm: 0,
        supportsNvmeSanitize: true,
      );

      final result = service.classify(nvme);
      expect(result.mediaType, MediaType.nvmeSsd);
      expect(result.capabilities['supportsNvmeSanitize'], isTrue);
    });

    test('Returns fail safe UNKNOWN for missing device bus metadata', () {
      const emptyDevice = DeviceProfile(
        id: '3',
        name: '',
        serialNumber: '',
        mediaType: MediaType.unknown,
        busType: '',
        capacityBytes: 0,
      );

      final result = service.classify(emptyDevice);
      expect(result.mediaType, MediaType.unknown);
      expect(result.isConfident, isFalse);
    });
  });

  group('A8 — capability matrix & NIST level assignment', () {
    final service = ClassificationService();

    const hddDevice = DeviceProfile(
      id: 'sda',
      name: 'Seagate Barracuda',
      serialNumber: 'HDD-1',
      mediaType: MediaType.hdd,
      busType: 'SATA',
      capacityBytes: 1000000000000,
      rotationalRpm: 7200,
    );

    const sataPurgeDevice = DeviceProfile(
      id: 'sdb',
      name: 'Crucial MX500',
      serialNumber: 'SSD-1',
      mediaType: MediaType.sataSsd,
      busType: 'SATA',
      capacityBytes: 500000000000,
      supportsAtaSecureErase: true,
      supportsAtaSanitize: true,
    );

    const nvmePurgeDevice = DeviceProfile(
      id: 'nvme0n1',
      name: 'Samsung 990 PRO',
      serialNumber: 'NVME-1',
      mediaType: MediaType.nvmeSsd,
      busType: 'NVMe',
      capacityBytes: 1000204886016,
      supportsNvmeSanitize: true,
    );

    const usbFlashDevice = DeviceProfile(
      id: 'sdc',
      name: 'SanDisk Cruzer',
      serialNumber: 'USB-1',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
      supportsTrim: true,
    );

    const unknownDevice = DeviceProfile(
      id: 'sdd',
      name: 'Mystery Brick',
      serialNumber: 'UNK-1',
      mediaType: MediaType.unknown,
      busType: 'IDE',
      capacityBytes: 8000000000,
    );

    test('deviceClassOf mirrors the engine classification', () {
      expect(ClassificationService.deviceClassOf(hddDevice), 'hdd');
      expect(ClassificationService.deviceClassOf(sataPurgeDevice), 'sata_ssd');
      expect(ClassificationService.deviceClassOf(nvmePurgeDevice), 'nvme');
      expect(ClassificationService.deviceClassOf(usbFlashDevice), 'usb_flash');
      expect(ClassificationService.deviceClassOf(unknownDevice), 'unknown');
    });

    test('capabilityMatrix reports engine capability flags', () {
      final m = service.capabilityMatrix(sataPurgeDevice);
      expect(m.deviceClass, 'sata_ssd');
      expect(m.supportsSecureErase, isTrue);
      expect(m.supportsSanitize, isTrue);
      expect(m.supportsDiscard, isFalse);

      final usb = service.capabilityMatrix(usbFlashDevice);
      expect(usb.deviceClass, 'usb_flash');
      expect(usb.supportsDiscard, isTrue);
      expect(usb.supportsSanitize, isFalse);
    });

    test('Purge requires whole-device scope AND a hardware command', () {
      expect(
        service.capabilityMatrix(sataPurgeDevice).sanitizationLevel(wholeDevice: true),
        'Purge',
      );
      expect(
        service.capabilityMatrix(sataPurgeDevice).sanitizationLevel(wholeDevice: false),
        'Clear',
      );

      expect(
        service.capabilityMatrix(nvmePurgeDevice).sanitizationLevel(wholeDevice: true),
        'Purge',
      );
      expect(
        service.capabilityMatrix(nvmePurgeDevice).sanitizationLevel(wholeDevice: false),
        'Clear',
      );
    });

    test('no hardware command caps the level at Clear for every scope', () {
      expect(
        service.capabilityMatrix(hddDevice).sanitizationLevel(wholeDevice: true),
        'Clear',
      );
      expect(
        service.capabilityMatrix(usbFlashDevice).sanitizationLevel(wholeDevice: true),
        'Clear',
      );
      expect(
        service.capabilityMatrix(unknownDevice).sanitizationLevel(wholeDevice: true),
        'Clear',
      );
      expect(
        service.capabilityMatrix(unknownDevice).sanitizationLevel(wholeDevice: false),
        'Clear',
      );
    });
  });
}
