import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/main.dart';

void main() {
  testWidgets('ZeroTraceApp loads dashboard screen', (WidgetTester tester) async {
    // Set a large screen size to avoid overflow in test environment
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;

    await tester.pumpWidget(const ZeroTraceApp());
    await tester.pumpAndSettle();

    // The sidebar should show ZERO TRACE branding
    expect(find.text('ZERO TRACE'), findsOneWidget);
    // Dashboard should be the initial screen
    expect(find.text('Dashboard'), findsWidgets);

    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  });
}
