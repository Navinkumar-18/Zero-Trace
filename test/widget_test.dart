import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/main.dart';

void main() {
  testWidgets('ZeroTraceApp loads inventory screen', (WidgetTester tester) async {
    await tester.pumpWidget(const ZeroTraceApp());
    await tester.pumpAndSettle();

    expect(find.text('ZERO TRACE 2.0'), findsOneWidget);
    expect(find.text('Inventory'), findsWidgets);
  });
}
