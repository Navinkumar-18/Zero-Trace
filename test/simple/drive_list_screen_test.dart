import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/services/job_state_file.dart';
import 'package:zero_trace/services/orphaned_process_checker.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/drive_list_screen.dart';

void main() {
  const usbDevice = DeviceProfile(
    id: 'sdb',
    name: 'SanDisk Cruzer Blade',
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

  const systemDrive = DeviceProfile(
    id: 'nvme0n1',
    name: 'KIOXIA NVMe 512GB (Root)',
    serialNumber: 'NVME12345678',
    mediaType: MediaType.nvmeSsd,
    busType: 'NVMe',
    capacityBytes: 512000000000,
    isSystemDisk: true,
    isRemovable: false,
  );

  const unsupportedRaid = DeviceProfile(
    id: 'md0',
    name: 'Linux Software RAID',
    serialNumber: 'RAID-001',
    mediaType: MediaType.unknown,
    busType: 'Virtual',
    capacityBytes: 1000000000000,
    isRemovable: false,
    disabledReason: 'Hardware or software RAID array – not supported',
  );

  Widget createSubject(SanitizationController controller) {
    return ChangeNotifierProvider<SanitizationController>.value(
      value: controller,
      child: const MaterialApp(
        home: Scaffold(
          body: DriveListScreen(),
        ),
      ),
    );
  }

  testWidgets('Screen 1 shows removable drives by default, hides internal drives unless toggled', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice, internalSsd]);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // USB device should be visible
    expect(find.text('SanDisk Cruzer Blade'), findsOneWidget);
    // Internal SSD should be hidden by default
    expect(find.text('Samsung 870 EVO 500GB'), findsNothing);

    // Tap "Show internal drives"
    final toggleFinder = find.text('Show internal drives');
    expect(toggleFinder, findsOneWidget);
    await tester.tap(toggleFinder);
    await tester.pumpAndSettle();

    // Now internal SSD should be visible
    expect(find.text('Samsung 870 EVO 500GB'), findsOneWidget);
    expect(find.text('Hide internal drives'), findsOneWidget);
  });

  testWidgets('System drive displays disabled badge and reason', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([systemDrive]);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Internal drives are hidden initially, tap to show
    await tester.tap(find.text('Show internal drives'));
    await tester.pumpAndSettle();

    expect(find.text('KIOXIA NVMe 512GB (Root)'), findsOneWidget);
    expect(find.text('System drive – protected'), findsOneWidget);
  });

  testWidgets('Unsupported device displays custom disabled reason', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([unsupportedRaid]);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Show internal drives'));
    await tester.pumpAndSettle();

    expect(find.text('Linux Software RAID'), findsOneWidget);
    expect(find.text('Hardware or software RAID array – not supported'), findsOneWidget);
  });

  testWidgets('Simulation mode banner is displayed when in simulated mode', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    await controller.toggleRealMode(false);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    expect(find.text('SIMULATION MODE — No real drives will be modified'), findsOneWidget);
  });

  testWidgets('Orphan detection displays active wipe with PID, target, method and Attach button', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);
    controller.setMockOrphanResult(OrphanCheckResult(
      status: OrphanCheckStatus.processActive,
      pid: '4281',
      activeJobState: ActiveJobState(
        jobId: 'JOB-999',
        deviceSerial: '4C530000151121111494',
        devicePath: '/dev/sdb',
        deviceName: 'SanDisk Cruzer Blade',
        method: 'Single-Pass Overwrite',
        startedAt: DateTime.now().toIso8601String(),
      ),
    ));

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    expect(find.text('A wipe is already in progress'), findsOneWidget);
    expect(find.textContaining('PID: 4281'), findsOneWidget);
    expect(find.textContaining('SanDisk Cruzer Blade'), findsWidgets);
    expect(find.textContaining('Single-Pass Overwrite'), findsOneWidget);
    expect(find.text('Attach'), findsOneWidget);
  });

  testWidgets('Orphan detection displays interrupted wipe and Dismiss button', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);
    controller.setMockOrphanResult(OrphanCheckResult(
      status: OrphanCheckStatus.interrupted,
      activeJobState: ActiveJobState(
        jobId: 'JOB-888',
        deviceSerial: '4C530000151121111494',
        devicePath: '/dev/sdb',
        deviceName: 'SanDisk Cruzer Blade',
        method: 'Single-Pass Overwrite',
        startedAt: DateTime.now().toIso8601String(),
      ),
    ));

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    expect(find.text('Interrupted wipe detected'), findsOneWidget);
    expect(find.text('Dismiss'), findsOneWidget);

    await tester.tap(find.text('Dismiss'));
    await tester.pumpAndSettle();

    expect(find.text('Interrupted wipe detected'), findsNothing);
  });
}
