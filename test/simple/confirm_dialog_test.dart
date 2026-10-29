import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/partition_info.dart';
import 'package:zero_trace/models/untrusted_text.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/confirm_wipe_dialog.dart';

void main() {
  const usbDevice = DeviceProfile(
    id: 'sdb',
    name: 'SanDisk Cruzer Blade',
    serialNumber: '4C530000151121111494', // last 4: 1494
    mediaType: MediaType.usbFlash,
    busType: 'USB',
    capacityBytes: 16000000000,
    isRemovable: true,
  );

  Widget createSubject(SanitizationController controller) {
    return ChangeNotifierProvider<SanitizationController>.value(
      value: controller,
      child: const MaterialApp(
        home: Scaffold(
          body: SimpleConfirmDialog(device: usbDevice),
        ),
      ),
    );
  }

  testWidgets('Confirm dialog gates SECURE WIPE button behind last-4-of-serial', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Dialog title and drive info
    expect(find.text('Wipe SanDisk Cruzer Blade?'), findsOneWidget);
    expect(find.text('SanDisk Cruzer Blade'), findsOneWidget);
    expect(find.text('4C530000151121111494'), findsOneWidget);

    // Button should initially be disabled
    final wipeButtonFinder = find.widgetWithText(ElevatedButton, 'SECURE WIPE');
    expect(wipeButtonFinder, findsOneWidget);
    expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNull);

    // Type wrong serial
    final textFieldFinder = find.byType(TextField);
    await tester.enterText(textFieldFinder, '0000');
    await tester.pumpAndSettle();
    expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNull);

    // Type correct last 4 characters ('1494')
    await tester.enterText(textFieldFinder, '1494');
    await tester.pumpAndSettle();
    expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNotNull);
  });

  testWidgets('Confirm dialog updates method and warnings when disposal intent changes', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Initial intent is "Reuse myself"
    expect(find.text('Reuse myself'), findsOneWidget);

    // Change disposal dropdown to "Dispose / recycle"
    await tester.tap(find.text('Reuse myself'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Dispose / recycle').last);
    await tester.pumpAndSettle();

    expect(find.text('Dispose / recycle'), findsOneWidget);
  });

  testWidgets('Fallback confirmation match with path + size succeeds for unique drive', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    const genericDevice = DeviceProfile(
      id: 'sdb',
      name: 'Generic Flash Disk',
      serialNumber: 'S/N-sdb', // Generic serial triggers fallback match
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 8000000000,
      isRemovable: true,
    );

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([genericDevice]);

    await tester.pumpWidget(
      ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: const MaterialApp(
          home: Scaffold(
            body: SimpleConfirmDialog(device: genericDevice),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Prompts for device model and size
    expect(find.textContaining('Type device model and size to confirm'), findsOneWidget);

    final wipeButtonFinder = find.widgetWithText(ElevatedButton, 'SECURE WIPE');
    expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNull);

    // Enter matching fallback token: model + size ('Generic Flash Disk 8000000000')
    final textFieldFinder = find.byType(TextField);
    await tester.enterText(textFieldFinder, 'Generic Flash Disk 8000000000');
    await tester.pumpAndSettle();

    expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNotNull);
  });

  testWidgets('Fallback confirmation match blocks wipe when two drives share model and size', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    const driveA = DeviceProfile(
      id: 'sdb',
      name: 'Generic Flash Disk',
      serialNumber: 'S/N-sdb',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 8000000000,
      isRemovable: true,
    );

    const driveB = DeviceProfile(
      id: 'sdc',
      name: 'Generic Flash Disk',
      serialNumber: 'S/N-sdb-dup',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 8000000000,
      isRemovable: true,
    );

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    // Both drives have identical id ('sdb') and size (8000000000)
    controller.setMockDevices([driveA, driveB]);

    await tester.pumpWidget(
      ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: const MaterialApp(
          home: Scaffold(
            body: SimpleConfirmDialog(device: driveA),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Ambiguous match warning banner is displayed
    expect(find.textContaining('Ambiguous device match: Multiple drives match this fallback signature'), findsOneWidget);

    // Even if user types exact fallback match, button MUST remain disabled
    final textFieldFinder = find.byType(TextField);
    await tester.enterText(textFieldFinder, 'Generic Flash Disk 8000000000');
    await tester.pumpAndSettle();

    final wipeButtonFinder = find.widgetWithText(ElevatedButton, 'SECURE WIPE');
    expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNull);
  });

  testWidgets('serial+size re-check aborts at confirm (Item 5)', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    const originalDevice = DeviceProfile(
      id: 'sdb',
      name: 'SanDisk Blade',
      serialNumber: 'SN-PINNED-1234',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
    );

    // Controller has swapped or resized drive under same stable id
    const modifiedDevice = DeviceProfile(
      id: 'sdb',
      name: 'SanDisk Blade (Swapped)',
      serialNumber: 'SN-PINNED-1234',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 32000000000, // Size changed!
      isRemovable: true,
    );

    final controller = SanitizationController(
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(() => controller.dispose());
    controller.setMockDevices([modifiedDevice]);

    ConfirmWipeResult? result;

    await tester.pumpWidget(
      ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: MaterialApp(
          home: Scaffold(
            body: Builder(
              builder: (ctx) => ElevatedButton(
                onPressed: () async {
                  result = await showDialog<ConfirmWipeResult>(
                    context: ctx,
                    builder: (_) => const SimpleConfirmDialog(device: originalDevice),
                  );
                },
                child: const Text('Open Dialog'),
              ),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Open dialog
    await tester.tap(find.text('Open Dialog'));
    await tester.pumpAndSettle();

    // Enter last 4 digits of original device serial: '1234'
    final textFieldFinder = find.byType(TextField);
    await tester.enterText(textFieldFinder, '1234');
    await tester.pumpAndSettle();

    // SECURE WIPE button is enabled
    final wipeButtonFinder = find.widgetWithText(ElevatedButton, 'SECURE WIPE');
    expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNotNull);

    // Click SECURE WIPE
    await tester.tap(wipeButtonFinder);
    await tester.pumpAndSettle();

    // Wipe must be aborted due to serial/size mismatch at confirm
    expect(result, isNull);
    expect(find.text('Drive identity changed or disconnected.'), findsOneWidget);
  });

  testWidgets('Confirm dialog mints a WipeAuthorization pinning identity, typed confirmation and timestamp', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    ConfirmWipeResult? result;
    final before = DateTime.now();

    await tester.pumpWidget(
      ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: MaterialApp(
          home: Scaffold(
            body: Builder(
              builder: (ctx) => ElevatedButton(
                onPressed: () async {
                  result = await showDialog<ConfirmWipeResult>(
                    context: ctx,
                    builder: (_) => const SimpleConfirmDialog(device: usbDevice),
                  );
                },
                child: const Text('Open Dialog'),
              ),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Open Dialog'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), '1494');
    await tester.pumpAndSettle();

    await tester.tap(find.widgetWithText(ElevatedButton, 'SECURE WIPE'));
    await tester.pumpAndSettle();

    final after = DateTime.now();
    expect(result, isNotNull);
    final auth = result!.authorization;
    expect(auth.deviceSerial, usbDevice.serialNumber);
    expect(auth.typedConfirmation, '1494');
    expect(auth.authorizedAt.isBefore(before), isFalse);
    expect(auth.authorizedAt.isAfter(after), isFalse);
  });

  testWidgets('SIMULATION banner is displayed in confirm dialog (Item 5)', (tester) async {
    const simDevice = DeviceProfile(
      id: 'sdb',
      name: 'Simulated USB Drive',
      serialNumber: 'SIM-9999',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
    );

    final controller = SanitizationController(
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(() => controller.dispose());
    controller.setMockDevices([simDevice]);
    controller.isSimulated = true;

    await tester.pumpWidget(
      ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: const MaterialApp(
          home: Scaffold(
            body: SimpleConfirmDialog(device: simDevice),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Verify SIMULATION banner in confirm dialog
    expect(find.text('SIMULATION MODE — Virtual Wipe'), findsOneWidget);
  });

  group('A5 confirmation hardening', () {
    const partition = PartitionInfo(
      partitionNumber: 1,
      name: 'sda1',
      devicePath: '/dev/sda1',
      startSector: 2048,
      sizeSectors: 1000000,
      sizeBytes: 512000000,
      label: UntrustedText('DATA'),
      fsType: 'ext4',
    );

    const internalDisk = DeviceProfile(
      id: 'sda',
      name: 'Internal SATA SSD',
      serialNumber: 'ABCDEF123456', // last-4: 3456
      mediaType: MediaType.sataSsd,
      busType: 'SATA',
      capacityBytes: 512000000000,
      isRemovable: false,
      supportsAtaSanitize: true, // support level = full
      partitions: [partition],
    );

    Future<SanitizationController> pumpDialog(WidgetTester tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      final controller = SanitizationController(
        enableAutoPolling: false,
        deferInitialDiscovery: true,
      );
      addTearDown(() => controller.dispose());
      controller.setMockDevices([internalDisk]);
      controller.togglePartitionSelection(partition);

      await tester.pumpWidget(
        ChangeNotifierProvider<SanitizationController>.value(
          value: controller,
          child: const MaterialApp(
            home: Scaffold(
              body: SimpleConfirmDialog(device: internalDisk),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      return controller;
    }

    testWidgets(
        'internal disk partition wipe requires serial last-4 PLUS partition name',
        (tester) async {
      await pumpDialog(tester);

      // Scope row shows the exact partition + size; partition scope caps at Clear.
      expect(find.textContaining('sda1 ('), findsOneWidget);
      expect(
          find.textContaining('partition scope never reaches Purge'), findsOneWidget);

      // Prompt demands serial last-4 followed by partition name(s).
      expect(
          find.textContaining('followed by the partition name(s)'), findsOneWidget);

      final wipeButtonFinder = find.widgetWithText(ElevatedButton, 'SECURE WIPE');
      expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNull);

      // Serial last-4 alone is NOT enough when a partition is selected.
      await tester.enterText(find.byType(TextField), '3456');
      await tester.pumpAndSettle();
      expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNull);

      // Serial last-4 + partition name enables the wipe.
      await tester.enterText(find.byType(TextField), '3456sda1');
      await tester.pumpAndSettle();
      expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNotNull);
    });

    testWidgets('internal disk whole-device wipe only needs serial last-4',
        (tester) async {
      final controller = await pumpDialog(tester);

      // Back to whole-device scope: deselect the partition.
      controller.clearPartitionSelection();
      await tester.pumpAndSettle();

      expect(find.textContaining('Entire device ('), findsOneWidget);
      expect(find.textContaining('Type the last 4 characters of the serial'),
          findsOneWidget);

      final wipeButtonFinder = find.widgetWithText(ElevatedButton, 'SECURE WIPE');
      await tester.enterText(find.byType(TextField), '3456');
      await tester.pumpAndSettle();
      expect(tester.widget<ElevatedButton>(wipeButtonFinder).onPressed, isNotNull);
    });
  });

  group('Phase G: pre-wipe "After wiping" choice', () {
    const dataPartition = PartitionInfo(
      partitionNumber: 1,
      name: 'sdb1',
      devicePath: '/dev/sdb1',
      startSector: 2048,
      sizeSectors: 1000000,
      sizeBytes: 512000000,
      label: UntrustedText('DATA'),
      fsType: 'ext4',
    );

    const partitionDevice = DeviceProfile(
      id: 'sdb',
      name: 'SanDisk Cruzer Blade',
      serialNumber: '4C530000151121111494',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
      partitions: [dataPartition],
      partitionTableType: 'gpt',
    );

    const photosPartition = PartitionInfo(
      partitionNumber: 2,
      name: 'sdb2',
      devicePath: '/dev/sdb2',
      startSector: 1002048,
      sizeSectors: 1000000,
      sizeBytes: 512000000,
      label: UntrustedText('PHOTOS'),
      fsType: 'vfat',
    );

    const twoPartitionDevice = DeviceProfile(
      id: 'sdb',
      name: 'SanDisk Cruzer Blade',
      serialNumber: '4C530000151121111494',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
      partitions: [dataPartition, photosPartition],
      partitionTableType: 'gpt',
    );

    Future<Future<ConfirmWipeResult?> Function()> pumpHost(
      WidgetTester tester,
      SanitizationController controller,
      DeviceProfile device,
    ) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      ConfirmWipeResult? result;
      await tester.pumpWidget(
        ChangeNotifierProvider<SanitizationController>.value(
          value: controller,
          child: MaterialApp(
            home: Builder(
              builder: (context) => Scaffold(
                body: Center(
                  child: ElevatedButton(
                    onPressed: () async {
                      result = await SimpleConfirmDialog.show(context, device);
                    },
                    child: const Text('open dialog'),
                  ),
                ),
              ),
            ),
          ),
        ),
      );
      return () async => result;
    }

    testWidgets('removable media defaults to "Restore as an empty drive" and '
        'captures the first partition fs/label', (tester) async {
      final controller = SanitizationController(enableAutoPolling: false);
      addTearDown(controller.dispose);
      controller.setMockDevices([partitionDevice]);

      final readResult = await pumpHost(tester, controller, partitionDevice);
      await tester.pumpAndSettle();
      await tester.tap(find.text('open dialog'));
      await tester.pumpAndSettle();

      final group = tester.widget<RadioGroup<bool>>(
        find.byType(RadioGroup<bool>),
      );
      expect(group.groupValue, isTrue);

      await tester.enterText(find.byType(TextField), '1494');
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(ElevatedButton, 'SECURE WIPE'));
      await tester.pumpAndSettle();

      final result = await readResult();
      expect(result, isNotNull);
      expect(result!.authorization.restoreFilesystem, isTrue);
      expect(result.authorization.restoreFsType, 'ext4');
      expect(result.authorization.restoreLabel, 'DATA');
    });

    testWidgets('captures a separate fs/label for every selected partition', (
      tester,
    ) async {
      final controller = SanitizationController(enableAutoPolling: false);
      addTearDown(controller.dispose);
      controller.setMockDevices([twoPartitionDevice]);
      controller.togglePartitionSelection(dataPartition);
      controller.togglePartitionSelection(photosPartition);

      final readResult = await pumpHost(tester, controller, twoPartitionDevice);
      await tester.pumpAndSettle();
      await tester.tap(find.text('open dialog'));
      await tester.pumpAndSettle();

      await tester.enterText(find.byType(TextField), '1494');
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(ElevatedButton, 'SECURE WIPE'));
      await tester.pumpAndSettle();

      final result = await readResult();
      expect(result, isNotNull);
      final specs = result!.authorization.partitionRestoreSpecs;
      expect(specs, hasLength(2));
      expect(specs['/dev/sdb1']!.fsType, 'ext4');
      expect(specs['/dev/sdb1']!.label, 'DATA');
      expect(specs['/dev/sdb2']!.fsType, 'vfat');
      expect(specs['/dev/sdb2']!.label, 'PHOTOS');
    });

    testWidgets('"Leave blank" is carried on the authorization', (tester) async {
      final controller = SanitizationController(enableAutoPolling: false);
      addTearDown(controller.dispose);
      controller.setMockDevices([partitionDevice]);

      final readResult = await pumpHost(tester, controller, partitionDevice);
      await tester.pumpAndSettle();
      await tester.tap(find.text('open dialog'));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('after-wipe-leave-blank')));
      await tester.pumpAndSettle();
      expect(
        tester
            .widget<RadioGroup<bool>>(find.byType(RadioGroup<bool>))
            .groupValue,
        isFalse,
      );

      await tester.enterText(find.byType(TextField), '1494');
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(ElevatedButton, 'SECURE WIPE'));
      await tester.pumpAndSettle();

      final result = await readResult();
      expect(result, isNotNull);
      expect(result!.authorization.restoreFilesystem, isFalse);
      // The captured values stay recorded even when the choice is "blank".
      expect(result.authorization.restoreFsType, 'ext4');
      expect(result.authorization.restoreLabel, 'DATA');
    });

    testWidgets('non-removable media defaults to "Leave blank"', (tester) async {
      const internalSsd = DeviceProfile(
        id: 'sda',
        name: 'Internal SATA SSD',
        serialNumber: 'ABCDEF123456',
        mediaType: MediaType.sataSsd,
        busType: 'SATA',
        capacityBytes: 512000000000,
        isRemovable: false,
        supportsAtaSanitize: true,
      );

      final controller = SanitizationController(enableAutoPolling: false);
      addTearDown(controller.dispose);
      controller.setMockDevices([internalSsd]);

      await pumpHost(tester, controller, internalSsd);
      await tester.pumpAndSettle();
      await tester.tap(find.text('open dialog'));
      await tester.pumpAndSettle();

      expect(
        tester
            .widget<RadioGroup<bool>>(find.byType(RadioGroup<bool>))
            .groupValue,
        isFalse,
      );
    });
  });
}

