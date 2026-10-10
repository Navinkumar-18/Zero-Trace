import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/certificate_dialog.dart';

void main() {
  Widget createSubject(SanitizationController controller) {
    return ChangeNotifierProvider<SanitizationController>.value(
      value: controller,
      child: const MaterialApp(
        home: Scaffold(
          body: SimpleCertificateDialog(),
        ),
      ),
    );
  }

  testWidgets('Certificate dialog shows empty state when no cert is available', (tester) async {
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

    expect(find.text('No certificate available.'), findsOneWidget);
  });

  testWidgets('Certificate dialog shows success certificate with simulated disclaimer and flash caveat', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());

    final cert = SanitizationCertificate(
      certificateId: 'ZT-CERT-2026-999',
      jobId: 'JOB-999',
      deviceSerial: '4C530000151121111494',
      deviceModel: 'Cruzer Blade',
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
      executionMode: 'simulated',
      evidence: VerificationEvidence(
        statusCode: 0,
        controllerConfirmation: 'Confirmed',
        sampleOffsets: [0, 512],
        sampleHashes: {0: 'h0'},
        evidenceHash: 'evidence-hash',
        limitations: 'Flash clear only',
        verifiedPassed: true,
      ),
    );
    controller.setMockCompletedCertificate(cert);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    expect(find.text('Sanitization Certificate'), findsOneWidget);
    expect(find.text('SIMULATED — Not a valid sanitization record'), findsOneWidget);
    expect(find.text('Wiped (Clear) ⚠'), findsOneWidget);
    expect(find.textContaining('Flash media cannot be guaranteed purged'), findsOneWidget);
    expect(find.text('Download PDF'), findsOneWidget);
    expect(find.text('Close'), findsOneWidget);
  });

  testWidgets('Certificate dialog displays Failure Report when result is FAILED', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());

    final failedCert = SanitizationCertificate(
      certificateId: 'ZT-FAIL-2026-001',
      jobId: 'JOB-FAIL-1',
      deviceSerial: '4C530000151121111494',
      deviceModel: 'Cruzer Blade',
      mediaType: 'USB Flash',
      capacity: '16 GB',
      method: 'Single-Pass Overwrite',
      sanitizationCategory: 'CLEAR',
      standardReference: 'NIST SP 800-88 Rev. 1',
      startTime: DateTime.now().subtract(const Duration(minutes: 5)),
      endTime: DateTime.now(),
      result: 'FAILED',
      verificationSummary: 'Verification non-zero sample detected',
      softwareVersion: '2.0.0',
      signature: 'MOCK-SIG',
      publicKeyPem: 'MOCK-KEY',
      executionMode: 'simulated',
      evidence: VerificationEvidence(
        statusCode: 1,
        controllerConfirmation: 'Failed',
        sampleOffsets: [0, 512],
        sampleHashes: {0: 'bad'},
        evidenceHash: 'evidence-hash',
        limitations: 'Verification failed',
        verifiedPassed: false,
      ),
    );
    controller.setMockCompletedCertificate(failedCert);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    expect(find.text('Failure Report'), findsOneWidget);
    expect(find.textContaining('FAILED — This is a failure report'), findsOneWidget);
    expect(find.text('WIPE FAILED'), findsOneWidget);
    expect(find.text('SIMULATED — Not a valid sanitization record'), findsOneWidget);
    expect(find.text('Download Report'), findsOneWidget);
    expect(find.text('Close'), findsOneWidget);
  });
}
