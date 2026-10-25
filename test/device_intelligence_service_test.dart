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

  group('B1/B2 parseBlockDevices partition typing', () {
    final service = DeviceIntelligenceService();

    Map<String, dynamic> windowsDisk() => {
          'name': 'sda',
          'model': 'Windows Laptop SSD',
          'serial': 'ABC123',
          'size': 512000000000,
          'rota': false,
          'tran': 'sata',
          'type': 'disk',
          'rm': false,
          'hotplug': false,
          'children': [
            {
              'name': 'sda1',
              'type': 'part',
              'size': 100000000,
              'start': 2048,
              'partn': 1,
              'fstype': null,
              'label': '',
              'parttype': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b',
            },
            {
              'name': 'sda2',
              'type': 'part',
              'size': 254000000000,
              'start': 4200448,
              'partn': 2,
              'fstype': 'ntfs',
              'label': 'OS',
              'parttype': 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7',
              'fsused': 123456789000,
            },
            {
              'name': 'sda3',
              'type': 'part',
              'size': 1000000000,
              'start': 500000000,
              'partn': 3,
              'fstype': 'crypto_LUKS',
              'label': 'vault',
              'parttype': 'ca7d7ccb-63ed-4c53-861c-1742536059cc',
            },
            {
              'name': 'sda4',
              'type': 'part',
              'size': 500000000,
              'start': 600000000,
              'partn': 4,
              'fstype': 'bitlocker',
              'label': '',
              'parttype': null,
            },
          ],
        };

    test('GPT type GUIDs and FSTYPE map to names, roles and encryption', () {
      final profiles = service.parseBlockDevices([windowsDisk()]);
      expect(profiles, hasLength(1));
      final parts = profiles.first.partitions;
      expect(parts, hasLength(4));

      final esp = parts[0];
      expect(esp.role, 'efi_system');
      expect(esp.partTypeName, 'EFI System');
      expect(esp.friendlyDisplayName, 'EFI System');

      final os = parts[1];
      expect(os.role, 'windows_data');
      expect(os.partTypeName, 'Microsoft Basic Data');
      expect(os.usedBytes, 123456789000);
      expect(os.friendlyDisplayName, startsWith('NTFS volume'));

      final vault = parts[2];
      expect(vault.role, 'luks');
      expect(vault.encryptionKind, 'LUKS',
          reason: 'B2: LUKS FSTYPE labels the volume');
      expect(vault.friendlyDisplayName, startsWith('Encrypted volume (LUKS'));

      final bl = parts[3];
      expect(bl.encryptionKind, 'BitLocker',
          reason: 'B2: bitlocker FSTYPE labels the volume');
      expect(bl.role, 'windows_data');
    });

    test('legacy lsblk output without PARTTYPE/FSUSED still parses', () {
      final profiles = service.parseBlockDevices([
        {
          'name': 'sdb',
          'model': 'Old USB',
          'serial': 'XYZ789',
          'size': 8000000000,
          'rota': false,
          'tran': 'usb',
          'type': 'disk',
          'rm': true,
          'hotplug': true,
          'children': [
            {
              'name': 'sdb1',
              'type': 'part',
              'size': 7900000000,
              'start': 2048,
              'partn': 1,
              'fstype': 'vfat',
              'label': 'USBSTICK',
            },
          ],
        },
      ]);
      final p = profiles.first.partitions.single;
      expect(p.partTypeGuid, isNull);
      expect(p.partTypeName, isNull);
      expect(p.encryptionKind, isNull);
      expect(p.usedBytes, isNull);
      // fs-only fallback still gives a friendly row.
      expect(p.friendlyDisplayName, 'USBSTICK');
    });

    test('MBR type bytes classify from PARTTYPE token', () {
      final profiles = service.parseBlockDevices([
        {
          'name': 'sdc',
          'model': 'Old Laptop HDD',
          'serial': 'DEF456',
          'size': 320000000000,
          'rota': true,
          'tran': 'sata',
          'type': 'disk',
          'rm': false,
          'hotplug': false,
          'children': [
            {
              'name': 'sdc1',
              'type': 'part',
              'size': 319000000000,
              'start': 2048,
              'partn': 1,
              'fstype': 'ntfs',
              'label': 'DATA',
              'parttype': '0x7',
            },
          ],
        },
      ]);
      final p = profiles.first.partitions.single;
      expect(p.partTypeName, 'Windows NTFS/exFAT');
      expect(p.role, 'windows_data');
      expect(p.friendlyDisplayName, startsWith('NTFS volume'));
    });
  });
}
