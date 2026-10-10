import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/services/device_intelligence_service.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/drive_detail_screen.dart';

class TestSanitizationController extends SanitizationController {
  final List<DeviceProfile> testDevices;

  TestSanitizationController(this.testDevices);

  @override
  List<DeviceProfile> get devices => testDevices;
}

void main() {
  group('DeviceProfile RPM defaults and detection tests', () {
    test('DeviceProfile rotationalRpm defaults to null when omitted', () {
      const profile = DeviceProfile(
        id: 'test_dev',
        name: 'Generic Device',
        serialNumber: '12345',
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        capacityBytes: 8000000000,
      );

      expect(profile.rotationalRpm, isNull);
    });

    test('DeviceIntelligenceService parses Cruzer Blade with rota:true as null RPM, not 5400', () {
      final service = DeviceIntelligenceService();

      // Real fixture from user's `lsblk -J` output
      final cruzerBladeFixture = [
        {
          "name": "sda",
          "model": "Cruzer Blade",
          "serial": "4C530000151121111494",
          "size": 7798784000,
          "rota": true,
          "tran": "usb",
          "mountpoint": null,
          "type": "disk",
          "rm": true,
          "hotplug": true,
          "fstype": null,
          "children": [
            {
              "name": "sda1",
              "model": null,
              "serial": null,
              "size": 7797735424,
              "rota": true,
              "tran": null,
              "mountpoint": null,
              "type": "part",
              "rm": true,
              "hotplug": true,
              "fstype": "vfat"
            }
          ]
        }
      ];

      final devices = service.parseBlockDevices(cruzerBladeFixture);
      expect(devices.length, equals(1));

      final dev = devices.first;
      expect(dev.name, equals('Cruzer Blade'));
      expect(dev.mediaType, equals(MediaType.usbFlash));
      expect(dev.rotationalRpm, isNull);
    });

    testWidgets('Cruzer Blade with rota:true does not show RPM chip on DriveDetailScreen', (tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;

      const cruzerBlade = DeviceProfile(
        id: 'sda',
        name: 'Cruzer Blade',
        serialNumber: '4C530000151121111494',
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        capacityBytes: 7798784000,
        rotationalRpm: null,
      );

      final controller = TestSanitizationController([cruzerBlade]);

      await tester.pumpWidget(
        ChangeNotifierProvider<SanitizationController>.value(
          value: controller,
          child: const MaterialApp(
            home: DriveDetailScreen(deviceId: 'sda'),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Verify device details are shown
      expect(find.text('Cruzer Blade'), findsOneWidget);

      // Verify RPM is NOT shown for flash media
      expect(find.text('RPM:'), findsNothing);
      expect(find.text('5400'), findsNothing);

      controller.dispose();
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });
    });

    testWidgets('HDD with detected RPM displays the RPM chip', (tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;

      const hddWithRpm = DeviceProfile(
        id: 'sdb',
        name: 'Seagate Barracuda',
        serialNumber: 'W1234567',
        mediaType: MediaType.hdd,
        busType: 'SATA',
        capacityBytes: 1000000000000,
        rotationalRpm: 7200,
      );

      final controller = TestSanitizationController([hddWithRpm]);

      await tester.pumpWidget(
        ChangeNotifierProvider<SanitizationController>.value(
          value: controller,
          child: const MaterialApp(
            home: DriveDetailScreen(deviceId: 'sdb'),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Verify RPM is displayed for HDD
      expect(find.text('RPM:'), findsOneWidget);
      expect(find.text('7200'), findsOneWidget);

      controller.dispose();
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });
    });

    testWidgets('HDD without detected RPM hides the RPM chip', (tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;

      const hddUnknownRpm = DeviceProfile(
        id: 'sdc',
        name: 'Unknown HDD',
        serialNumber: 'U9999999',
        mediaType: MediaType.hdd,
        busType: 'SATA',
        capacityBytes: 500000000000,
        rotationalRpm: null,
      );

      final controller = TestSanitizationController([hddUnknownRpm]);

      await tester.pumpWidget(
        ChangeNotifierProvider<SanitizationController>.value(
          value: controller,
          child: const MaterialApp(
            home: DriveDetailScreen(deviceId: 'sdc'),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Verify RPM is hidden when not detected
      expect(find.text('RPM:'), findsNothing);

      controller.dispose();
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });
    });
  });
}
