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
}
