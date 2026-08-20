import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/widgets/confirmation_dialog.dart';

void main() {
  testWidgets('ConfirmationDialog displays serial number text field with white background', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    const device = DeviceProfile(
      id: 'sda',
      name: 'Cruzer Blade',
      serialNumber: '4C530000151121111494',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 8000000000,
    );

    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: ConfirmationDialog(
            device: device,
            method: SanitizationMethod.singlePassOverwrite,
            nistCategory: 'PURGE (Physical & Controller Sanitization)',
          ),
        ),
      ),
    );

    final textFieldFinder = find.byType(TextField);
    expect(textFieldFinder, findsOneWidget);

    final textField = tester.widget<TextField>(textFieldFinder);
    expect(textField.decoration?.fillColor, Colors.white);
    expect(textField.decoration?.filled, isTrue);
  });
}
