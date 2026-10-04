@Tags(['linux'])
library;

import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/drive_list_screen.dart';

/// Custom golden file comparator with pixel diff tolerance (default 5%)
class ToleranceGoldenComparator extends LocalFileComparator {
  final double tolerance;

  ToleranceGoldenComparator(super.testFile, {this.tolerance = 0.05});

  File _getGoldenFile(Uri golden) {
    return File.fromUri(basedir.resolveUri(golden));
  }

  @override
  Future<bool> compare(Uint8List imageBytes, Uri golden) async {
    final File goldenFile = _getGoldenFile(golden);
    if (!goldenFile.existsSync()) {
      // Golden doesn't exist yet; write it on first run
      await goldenFile.parent.create(recursive: true);
      await goldenFile.writeAsBytes(imageBytes, flush: true);
      return true;
    }

    final ComparisonResult result = await GoldenFileComparator.compareLists(
      imageBytes,
      await goldenFile.readAsBytes(),
    );

    if (!result.passed && result.diffPercent <= tolerance) {
      return true;
    }
    return result.passed;
  }
}

void main() {
  const usbDevice = DeviceProfile(
    id: 'sdb',
    name: 'SanDisk Cruzer Blade 16GB',
    serialNumber: '4C530000151121111494',
    mediaType: MediaType.usbFlash,
    busType: 'USB',
    capacityBytes: 16000000000,
    isRemovable: true,
  );

  const internalSsd = DeviceProfile(
    id: 'sda',
    name: 'Samsung 870 EVO 500GB',
    serialNumber: 'S5Y2NJ0N123456',
    mediaType: MediaType.sataSsd,
    busType: 'SATA',
    capacityBytes: 500000000000,
    isRemovable: false,
  );

  setUp(() {
    final testUri = Uri.parse('test/simple/golden_drive_list_test.dart');
    goldenFileComparator = ToleranceGoldenComparator(testUri, tolerance: 0.05);
  });

  testWidgets('Golden: Simple drive list screen renders consistently', (tester) async {
    tester.view.physicalSize = const Size(1024, 768);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice, internalSsd]);

    await tester.pumpWidget(
      ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: const MaterialApp(
          home: Scaffold(
            body: DriveListScreen(),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await expectLater(
      find.byType(DriveListScreen),
      matchesGoldenFile('goldens/drive_list_screen.png'),
    );
  });
}
