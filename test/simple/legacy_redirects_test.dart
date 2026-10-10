import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/core/routing/app_router.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/sanitization_controller.dart';

void main() {
  group('Legacy Route Redirect Tests', () {
    const activeDevice = DeviceProfile(
      id: 'sda',
      name: 'Active Wipe Drive',
      serialNumber: 'ACTIVE-12345',
      mediaType: MediaType.sataSsd,
      busType: 'SATA',
      capacityBytes: 500000000000,
    );

    testWidgets('Idle redirects send legacy paths to / or /history', (tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;

      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());

      await tester.pumpWidget(
        ChangeNotifierProvider<SanitizationController>.value(
          value: controller,
          child: MaterialApp.router(
            routerConfig: appRouter,
          ),
        ),
      );
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));

      // Navigate to /advanced/dashboard -> redirects to /history
      appRouter.go('/advanced/dashboard');
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));
      expect(find.text('Operation History'), findsOneWidget);

      // Navigate to /advanced/audit -> redirects to /history
      appRouter.go('/advanced/audit');
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));
      expect(find.text('Operation History'), findsOneWidget);

      // Navigate to /advanced/devices -> redirects to /
      appRouter.go('/advanced/devices');
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));
      expect(find.text('Zero Trace'), findsWidgets);

      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });
    });

    testWidgets('Running job redirects legacy paths to /drive/:deviceId', (tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;

      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());
      controller.setMockDevices([activeDevice]);

      // Set mock active running job
      final job = SanitizationJob(
        jobId: 'JOB-RUNNING-001',
        device: activeDevice,
        dataSensitivity: DataSensitivity.internal,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.25,
        targetCategory: NistCategory.purge,
        recommendedMethod: SanitizationMethod.ataSecureErase,
        standardReference: 'NIST',
        explanationText: 'Wiping...',
      );
      job.status = JobStatus.sanitizing;
      controller.setMockJob(job);

      await tester.pumpWidget(
        ChangeNotifierProvider<SanitizationController>.value(
          value: controller,
          child: MaterialApp.router(
            routerConfig: appRouter,
          ),
        ),
      );
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));

      // Navigating to /advanced/sanitize or /sanitize while a job is running redirects to the active drive
      appRouter.go('/sanitize');
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));

      expect(find.text('Active Wipe Drive'), findsOneWidget);

      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });
    });
  });
}
