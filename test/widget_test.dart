import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/main.dart';

void main() {
  testWidgets('ZeroTraceApp loads simple mode drive list screen by default', (WidgetTester tester) async {
    // Set a large screen size to avoid overflow in test environment
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;

    await tester.pumpWidget(const ZeroTraceApp());
    await tester.pumpAndSettle();

    // Simple shell should show Zero Trace header and subtitle
    expect(find.text('Zero Trace'), findsWidgets);
    expect(find.text('Secure Data Wiping'), findsOneWidget);

    // Screen 1 should show the selection banner and Available Drives
    expect(find.text('Select a drive to securely wipe all data'), findsOneWidget);
    expect(find.text('Available Drives'), findsOneWidget);

    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  });
}
