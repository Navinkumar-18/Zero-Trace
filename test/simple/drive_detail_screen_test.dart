import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/drive_detail_screen.dart';

void main() {
  const usbDevice = DeviceProfile(
    id: 'sdb',
    name: 'SanDisk Cruzer Blade',
    serialNumber: '4C530000151121111494',
    mediaType: MediaType.usbFlash,
    busType: 'USB',
    capacityBytes: 16000000000,
    isRemovable: true,
  );

  Widget createSubject(SanitizationController controller, {String deviceId = '4C530000151121111494'}) {
    return ChangeNotifierProvider<SanitizationController>.value(
      value: controller,
      child: MaterialApp(
        home: Scaffold(
          body: DriveDetailScreen(deviceId: deviceId),
        ),
      ),
    );
  }

  testWidgets('Idle state shows Method: Decided at confirmation, Wipe enabled, Verify and Certificate disabled', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Verify info card contents
    expect(find.text('SanDisk Cruzer Blade'), findsOneWidget);
    expect(find.text('Decided at confirmation'), findsOneWidget);
    expect(find.textContaining('Flash media: Clear level only'), findsOneWidget);

    // Verify button states
    final wipeButton = tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Secure Wipe'));
    expect(wipeButton.onPressed, isNotNull);

    final verifyButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Verify'));
    expect(verifyButton.onPressed, isNull);

    final certButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Certificate'));
    expect(certButton.onPressed, isNull);
  });

  testWidgets('Running/Sanitizing state shows progress and disables all 3 buttons', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    final runningJob = SanitizationJob(
      jobId: 'JOB-TEST-1',
      device: usbDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 50,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
      explanationText: 'Sanitizing USB flash device',
      status: JobStatus.sanitizing,
      progress: 0.45,
      currentStageDescription: 'Writing zeros to sector 1420000...',
    );
    controller.setMockJob(runningJob);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Progress percentage and message should appear
    expect(find.text('45%'), findsOneWidget);
    expect(find.text('Writing zeros to sector 1420000...'), findsOneWidget);

    // Wipe button should show "Wiping..." and be disabled
    final wipeButton = tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Wiping...'));
    expect(wipeButton.onPressed, isNull);

    final verifyButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Verify'));
    expect(verifyButton.onPressed, isNull);

    final certButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Certificate'));
    expect(certButton.onPressed, isNull);
  });

  testWidgets('Completed and passed state enables Verify and Certificate, shows success badge', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    final completedJob = SanitizationJob(
      jobId: 'JOB-TEST-2',
      device: usbDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 50,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
      explanationText: 'Sanitizing USB flash device',
      status: JobStatus.completed,
      progress: 1.0,
      currentStageDescription: 'Verification passed',
    );
    controller.setMockJob(completedJob);

    final cert = SanitizationCertificate(
      certificateId: 'CERT-001',
      jobId: 'JOB-TEST-2',
      deviceSerial: '4C530000151121111494',
      deviceModel: 'SanDisk Cruzer Blade',
      mediaType: 'USB Flash',
      capacity: '16 GB',
      method: 'Single-Pass Overwrite',
      sanitizationCategory: 'CLEAR',
      standardReference: 'NIST SP 800-88 Rev. 1',
      startTime: DateTime.now().subtract(const Duration(minutes: 5)),
      endTime: DateTime.now(),
      result: 'PASSED',
      verificationSummary: 'Verified 50 samples',
      softwareVersion: '2.0.0',
      signature: 'MOCK-SIG',
      publicKeyPem: 'MOCK-KEY',
      evidence: VerificationEvidence(
        statusCode: 0,
        controllerConfirmation: 'Confirmed',
        sampleOffsets: [0, 512, 1024],
        sampleHashes: {0: 'hash0'},
        evidenceHash: 'evidence-hash',
        limitations: 'None',
        verifiedPassed: true,
      ),
    );
    controller.setMockCompletedCertificate(cert);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Success badge showing Wiped (Clear) ⚠
    expect(find.text('Wiped (Clear) ⚠'), findsOneWidget);

    // Wipe disabled, Verify enabled, Certificate enabled
    final wipeButton = tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Secure Wipe'));
    expect(wipeButton.onPressed, isNull);

    final verifyButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Verify'));
    expect(verifyButton.onPressed, isNotNull);

    final certButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Certificate'));
    expect(certButton.onPressed, isNotNull);
  });

  testWidgets('Device not found state when ID does not match', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    await tester.pumpWidget(createSubject(controller, deviceId: 'NON_EXISTENT_ID'));
    await tester.pumpAndSettle();

    expect(find.text('Drive not found'), findsOneWidget);
    expect(find.text('It may have been unplugged.'), findsOneWidget);
  });
}
