import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/services/device_intelligence_service.dart';

void main() {
  group('DeviceIntelligenceService Tests', () {
    final service = DeviceIntelligenceService();

    test('discoverDevices returns simulated profiles in simulated mode', () async {
      final devices = await service.discoverDevices(realMode: false);
      expect(devices, isNotEmpty);
      expect(devices.any((d) => d.mediaType == MediaType.hdd), isTrue);
      expect(devices.any((d) => d.mediaType == MediaType.nvmeSsd), isTrue);
    });

    test('discoverDevices returns physical devices in real mode on Linux', () async {
      final devices = await service.discoverDevices(realMode: true);
      // Should return at least 1 disk profile on Linux host or empty list if no disks
      expect(devices, isA<List<DeviceProfile>>());
      for (final dev in devices) {
        expect(dev.id.startsWith('real_'), isTrue);
      }
    });
  });
}
