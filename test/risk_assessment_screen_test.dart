import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/screens/risk_assessment_screen.dart';
import 'package:zero_trace/services/sanitization_controller.dart';

void main() {
  const usbFlashDevice = DeviceProfile(
    id: 'sdb',
    name: 'SanDisk Cruzer 16GB',
    serialNumber: 'USB12345678',
    mediaType: MediaType.usbFlash,
    busType: 'USB',
    capacityBytes: 16000000000,
  );

  const nvmeDevice = DeviceProfile(
    id: 'nvme0n1',
    name: 'Samsung 980 PRO 1TB',
    serialNumber: 'S5GXNF0R123456',
    mediaType: MediaType.nvmeSsd,
    busType: 'NVMe',
    capacityBytes: 1000000000000,
    supportsNvmeSanitize: true,
  );

  testWidgets('RiskAssessmentScreen displays Data Exposure Score, caption, support level and reason', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;

    final controller = SanitizationController();
    controller.selectDevice(usbFlashDevice);
    controller.setRiskInputs(sensitivity: DataSensitivity.confidential);

    await tester.pumpWidget(
      ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: const MaterialApp(
          home: RiskAssessmentScreen(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // 1. Verify "Data Exposure Score" is shown and "Risk Score:" is gone
    expect(find.textContaining('Data Exposure Score:'), findsOneWidget);
    expect(find.textContaining('Risk Score:'), findsNothing);

    // 2. Verify the small caption is shown
    expect(
      find.text('Based on data sensitivity, device condition and disposal channel. Independent of device type.'),
      findsOneWidget,
    );

    // 3. Verify support level badge is displayed
    expect(find.text('Clear-only'), findsOneWidget);

    // 4. Verify recommendation badge and the one-line reason
    expect(find.text('DESTROY'), findsOneWidget);
    expect(
      find.text('Recommendation also considers device support level.'),
      findsOneWidget,
    );

    // 5. Verify input card subtitles
    expect(find.textContaining('Weighted 50% of data exposure score'), findsOneWidget);

    controller.dispose();
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  });

  testWidgets('RiskAssessmentScreen shows Full support badge for firmware-capable NVMe SSD', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;

    final controller = SanitizationController();
    controller.selectDevice(nvmeDevice);
    controller.setRiskInputs(sensitivity: DataSensitivity.confidential);

    await tester.pumpWidget(
      ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: const MaterialApp(
          home: RiskAssessmentScreen(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.textContaining('Data Exposure Score:'), findsOneWidget);
    expect(find.text('Full'), findsOneWidget);
    expect(find.text('PURGE'), findsOneWidget);
    expect(
      find.text('Recommendation also considers device support level.'),
      findsOneWidget,
    );

    controller.dispose();
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  });
}
