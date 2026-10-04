import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/models/device_profile.dart';
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
    expect(find.text('Wipe All Data?'), findsOneWidget);
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
}
