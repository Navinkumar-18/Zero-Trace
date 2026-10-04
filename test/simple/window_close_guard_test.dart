import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/widgets/window_close_guard.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const testDevice = DeviceProfile(
    id: 'sdb',
    name: 'SanDisk Flash Drive',
    serialNumber: 'SN-TEST-1234',
    mediaType: MediaType.usbFlash,
    busType: 'USB',
    capacityBytes: 16000000000,
    isRemovable: true,
  );

  group('WindowCloseGuard - AppLifecycleListener(onExitRequested)', () {
    testWidgets('allows exit when no wipe is running', (tester) async {
      final controller = SanitizationController(
        enableAutoPolling: false,
        deferInitialDiscovery: true,
      );
      addTearDown(() => controller.dispose());
      controller.setMockDevices([testDevice]);

      await tester.pumpWidget(
        MaterialApp(
          home: WindowCloseGuard(
            controller: controller,
            child: const Scaffold(body: Text('Idle State')),
          ),
        ),
      );
      await tester.pump();

      // Trigger exit request via platform lifecycle handler
      final response = await ServicesBinding.instance.handleRequestAppExit();
      expect(response, AppExitResponse.exit);
    });

    testWidgets('cancels exit when a wipe is running and user declines confirmation', (tester) async {
      final controller = SanitizationController(
        enableAutoPolling: false,
        deferInitialDiscovery: true,
      );
      addTearDown(() => controller.dispose());
      controller.setMockDevices([testDevice]);

      // Set running job
      final job = SanitizationJob(
        jobId: 'job-1',
        device: testDevice,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 0.5,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88 Clear',
        explanationText: 'Single-Pass Zero Overwrite',
        status: JobStatus.sanitizing,
        progress: 0.45,
        currentStageDescription: 'Overwriting sectors (45%)',
        startTime: DateTime.now(),
      );
      controller.setMockJob(job);

      await tester.pumpWidget(
        MaterialApp(
          home: WindowCloseGuard(
            controller: controller,
            child: const Scaffold(body: Text('Wipe In Progress')),
          ),
        ),
      );
      await tester.pump();

      // Initiate exit request asynchronously
      final exitFuture = ServicesBinding.instance.handleRequestAppExit();
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 300)); // Render dialog

      expect(find.text('Sanitization in Progress'), findsOneWidget);
      expect(find.text('Continue Wipe'), findsOneWidget);
      expect(find.text('Stop Wipe & Exit'), findsOneWidget);

      // Tap 'Continue Wipe' (decline exit)
      await tester.tap(find.text('Continue Wipe'));
      await tester.pumpAndSettle();

      final response = await exitFuture;
      expect(response, AppExitResponse.cancel);
      expect(controller.currentJob?.status, JobStatus.sanitizing);
    });

    testWidgets('cancels wipe and allows exit when user confirms exit during running wipe', (tester) async {
      final controller = SanitizationController(
        enableAutoPolling: false,
        deferInitialDiscovery: true,
      );
      addTearDown(() => controller.dispose());
      controller.setMockDevices([testDevice]);

      // Set running job
      final job = SanitizationJob(
        jobId: 'job-2',
        device: testDevice,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 0.5,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88 Clear',
        explanationText: 'Single-Pass Zero Overwrite',
        status: JobStatus.sanitizing,
        progress: 0.60,
        currentStageDescription: 'Overwriting sectors (60%)',
        startTime: DateTime.now(),
      );
      controller.setMockJob(job);

      await tester.pumpWidget(
        MaterialApp(
          home: WindowCloseGuard(
            controller: controller,
            child: const Scaffold(body: Text('Wipe In Progress')),
          ),
        ),
      );
      await tester.pump();

      final exitFuture = ServicesBinding.instance.handleRequestAppExit();
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 300)); // Render dialog

      expect(find.text('Sanitization in Progress'), findsOneWidget);

      // Tap 'Stop Wipe & Exit'
      await tester.tap(find.text('Stop Wipe & Exit'));
      await tester.pumpAndSettle();

      final response = await exitFuture;
      expect(response, AppExitResponse.exit);
      expect(controller.currentJob?.status, JobStatus.failed);
      expect(controller.currentJob?.currentStageDescription, contains('Cancelled'));
    });
  });
}
