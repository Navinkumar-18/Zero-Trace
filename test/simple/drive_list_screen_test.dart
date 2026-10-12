import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/services/job_state_file.dart';
import 'package:zero_trace/services/orphaned_process_checker.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/drive_list_screen.dart';

void main() {
  late Directory tempDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('zt_drive_list_');
  });

  tearDown(() {
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
  });

  AppPaths tempPaths() => AppPaths(
        baseDir: tempDir,
        checkpointDir: Directory('${tempDir.path}/checkpoints'),
      );

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

    final controller = SanitizationController(appPaths: tempPaths(), enableAutoPolling: false);
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

    final controller = SanitizationController(appPaths: tempPaths(), enableAutoPolling: false);
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

    final controller = SanitizationController(appPaths: tempPaths(), enableAutoPolling: false);
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

    final controller = SanitizationController(appPaths: tempPaths(), enableAutoPolling: false);
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

    final controller = SanitizationController(appPaths: tempPaths(), enableAutoPolling: false);
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

    final controller = SanitizationController(appPaths: tempPaths(), enableAutoPolling: false);
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

  testWidgets('DriveType.unknown disabled with reason (Item 5)', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    const unknownDriveType = DeviceProfile(
      id: 'loop0',
      name: 'Loop / Virtual Device',
      serialNumber: 'UNKNOWN-LOOP-1',
      mediaType: MediaType.unknown,
      busType: 'Virtual',
      capacityBytes: 1000000000,
      isRemovable: false,
      disabledReason: 'Unknown drive type – sanitization unsupported',
    );

    final controller = SanitizationController(appPaths: tempPaths(), enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([unknownDriveType]);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Toggle internal drives to see non-removable virtual drive
    await tester.tap(find.text('Show internal drives'));
    await tester.pumpAndSettle();

    expect(find.text('Loop / Virtual Device'), findsOneWidget);
    expect(find.text('Unknown drive type – sanitization unsupported'), findsOneWidget);

    // Verify DriveType.unknown
    expect(unknownDriveType.driveType, DriveType.unknown);
    expect(unknownDriveType.simpleDisabledReason, 'Unknown drive type – sanitization unsupported');
  });

  group('Internal eMMC Qualification (Moved to drive-list tests per Item 5)', () {
    test('internal eMMC is non-removable, not typed SD, and not disabled by default', () {
      const emmc = DeviceProfile(
        id: 'mmcblk0',
        name: 'SanDisk DF4064 eMMC 64GB',
        serialNumber: 'EMMC64G-99A1',
        mediaType: MediaType.emmc,
        busType: 'eMMC 5.1',
        capacityBytes: 64424509440,
        rotationalRpm: 0,
        isRemovable: false,
        isSystemDisk: false,
      );

      expect(emmc.isRemovable, false, reason: 'Internal eMMC must be non-removable');
      expect(emmc.driveType != DriveType.sd, true, reason: 'Internal eMMC must NOT be typed SD');
      expect(emmc.driveType, isNot(DriveType.sd));
      expect(emmc.simpleDisabledReason, isNull, reason: 'Internal eMMC must NOT be disabled by default');
      expect(emmc.mediaTechnology, MediaTechnology.flash);
    });

    test('internal eMMC is disabled ONLY if it is the system drive or unsupported', () {
      const emmcSys = DeviceProfile(
        id: 'mmcblk0',
        name: 'System Board eMMC',
        serialNumber: 'EMMC-SYS-1',
        mediaType: MediaType.emmc,
        busType: 'eMMC',
        capacityBytes: 64424509440,
        rotationalRpm: 0,
        isRemovable: false,
        isSystemDisk: true,
      );
      expect(emmcSys.simpleDisabledReason, 'System drive – protected');

      const emmcDisabled = DeviceProfile(
        id: 'mmcblk0',
        name: 'Faulty eMMC',
        serialNumber: 'EMMC-FAULT',
        mediaType: MediaType.emmc,
        busType: 'eMMC',
        capacityBytes: 64424509440,
        rotationalRpm: 0,
        isRemovable: false,
        isSystemDisk: false,
        disabledReason: 'Hardware write-protection active',
      );
      expect(emmcDisabled.simpleDisabledReason, 'Hardware write-protection active');
    });

    testWidgets('internal eMMC is hidden by default and selectable when internal drives shown', (tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      const emmc = DeviceProfile(
        id: 'mmcblk0',
        name: 'SanDisk DF4064 eMMC 64GB',
        serialNumber: 'EMMC64G-99A1',
        mediaType: MediaType.emmc,
        busType: 'eMMC 5.1',
        capacityBytes: 64424509440,
        rotationalRpm: 0,
        isRemovable: false,
        isSystemDisk: false,
      );

      final controller = SanitizationController(appPaths: tempPaths(), enableAutoPolling: false);
      addTearDown(() => controller.dispose());
      controller.setMockDevices([usbDevice, emmc]);

      await tester.pumpWidget(createSubject(controller));
      await tester.pumpAndSettle();

      // eMMC hidden by default
      expect(find.text('SanDisk DF4064 eMMC 64GB'), findsNothing);

      // Toggle internal drives
      await tester.tap(find.text('Show internal drives'));
      await tester.pumpAndSettle();

      // Visible and selectable
      expect(find.text('SanDisk DF4064 eMMC 64GB'), findsOneWidget);
      final inkWellFinder = find.widgetWithText(InkWell, 'SanDisk DF4064 eMMC 64GB');
      expect(inkWellFinder, findsOneWidget);
      final inkWell = tester.widget<InkWell>(inkWellFinder);
      expect(inkWell.onTap, isNotNull);
      expect(find.text('System drive – protected'), findsNothing);
      expect(find.text('Unknown or unsupported device type – cannot wipe safely'), findsNothing);
    });
  });
}
