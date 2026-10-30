import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/services/failure_report_wording.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/certificate_dialog.dart';

const _realHash =
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

SanitizationCertificate _certificate({
  required String result,
  required VerificationEvidence evidence,
  int? verificationSampleCount,
  String verificationSummary = '',
  bool? wipeCompleted,
}) {
  return SanitizationCertificate(
    certificateId: 'ZT-CERT-WORDING',
    jobId: 'JOB-WORDING',
    deviceSerial: 'SERIAL-WORDING',
    deviceModel: 'Test Drive',
    mediaType: 'USB Flash',
    capacity: '16 GB',
    method: 'Single-Pass Overwrite',
    sanitizationCategory: 'Clear',
    standardReference: 'NIST SP 800-88 Rev. 1',
    startTime: DateTime(2026, 10, 29, 10),
    endTime: DateTime(2026, 10, 29, 10, 5),
    result: result,
    verificationSummary: verificationSummary,
    verificationSampleCount: verificationSampleCount,
    softwareVersion: '2.0.0',
    signature: 'MOCK-SIG',
    publicKeyPem: 'MOCK-KEY',
    executionMode: 'real',
    scope: 'partial',
    partitionsWiped: const [
      {
        'name': 'sdb1',
        'partition_number': 1,
        'start_sector': 2048,
        'size_bytes': 1073741824,
      },
    ],
    evidence: evidence,
    wipeCompleted: wipeCompleted,
  );
}

VerificationEvidence _notRunEvidence() => VerificationEvidence(
  statusCode: 1,
  controllerConfirmation: 'VERIFICATION: Not run (wipe did not complete)',
  sampleOffsets: const [],
  sampleHashes: const {},
  evidenceHash: '',
  limitations: 'Partition wipe',
  verifiedPassed: false,
);

VerificationEvidence _passedEvidence() => VerificationEvidence(
  statusCode: 0,
  controllerConfirmation:
      'VERIFICATION: Pass: true | Samples: 50 | Entropy: 0.0',
  sampleOffsets: const [0, 512],
  sampleHashes: const {0: _realHash, 512: _realHash},
  evidenceHash: _realHash,
  limitations: 'Partition wipe',
  verifiedPassed: true,
);

VerificationEvidence _failedEvidence() => VerificationEvidence(
  statusCode: 1,
  controllerConfirmation:
      'VERIFICATION: Pass: false | Samples: 50 | Entropy: 1.0',
  sampleOffsets: const [0, 512],
  sampleHashes: const {0: 'bad-hash', 512: 'worse-hash'},
  evidenceHash: 'verification-fingerprint',
  limitations: 'Partition wipe',
  verifiedPassed: false,
);

Widget _subject(SanitizationController controller) {
  return ChangeNotifierProvider<SanitizationController>.value(
    value: controller,
    child: const MaterialApp(home: Scaffold(body: SimpleCertificateDialog())),
  );
}

Future<SanitizationController> _pump(
  WidgetTester tester,
  SanitizationCertificate cert,
) async {
  tester.view.physicalSize = const Size(1920, 1080);
  tester.view.devicePixelRatio = 1.0;
  addTearDown(() {
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });

  final controller = SanitizationController(enableAutoPolling: false);
  addTearDown(controller.dispose);
  controller.setMockCompletedCertificate(cert);

  await tester.pumpWidget(_subject(controller));
  await tester.pumpAndSettle();
  return controller;
}

void main() {
  group('FailureReportWording', () {
    test('placeholder sample evidence is not reported as verification', () {
      final cert = _certificate(
        result: 'FAILED',
        evidence: VerificationEvidence(
          statusCode: 1,
          controllerConfirmation: 'Failed',
          sampleOffsets: List.generate(50, (index) => index * 1000),
          sampleHashes: {
            for (var index = 0; index < 50; index++) index: '0' * 64,
          },
          evidenceHash: 'VERIFY_UNAVAILABLE',
          limitations: '',
          verifiedPassed: false,
        ),
        verificationSampleCount: 50,
      );

      expect(FailureReportWording.verificationRan(cert), isFalse);
      expect(FailureReportWording.overwriteConfirmed(cert), isFalse);
    });

    test('a completed wipe with a failed verification is still confirmed', () {
      final cert = _certificate(
        result: 'FAILED',
        evidence: _failedEvidence(),
        verificationSampleCount: 50,
      );

      expect(FailureReportWording.verificationRan(cert), isTrue);
      expect(FailureReportWording.overwriteConfirmed(cert), isTrue);
    });

    test(
      'overwriteConfirmed is true when wipeCompleted is true even if verification did not run',
      () {
        final cert = _certificate(
          result: 'FAILED',
          evidence: _notRunEvidence(),
          wipeCompleted: true,
        );

        expect(FailureReportWording.verificationRan(cert), isFalse);
        expect(FailureReportWording.overwriteConfirmed(cert), isTrue);
      },
    );
  });

  group('failure report UI wording', () {
    testWidgets(
      'failed, unconfirmed wipe does not claim the partitions were overwritten',
      (tester) async {
        final cert = _certificate(
          result: 'FAILED',
          evidence: _notRunEvidence(),
          verificationSampleCount: 50,
          verificationSummary:
              'Sample Verification Failed - Non-Zero Data Detected',
        );

        await _pump(tester, cert);

        expect(
          find.text('Target partitions (not confirmed overwritten)'),
          findsOneWidget,
        );
        expect(find.text('Target Partitions Overwritten:'), findsNothing);
        expect(find.text('Verification: not run'), findsOneWidget);
        expect(find.textContaining('Samples Checked'), findsNothing);
        expect(find.textContaining('Evidence Hash'), findsNothing);
        expect(find.textContaining('000000000000000'), findsNothing);
      },
    );

    testWidgets('completed overwrite keeps the confirmed partition wording', (
      tester,
    ) async {
      final cert = _certificate(
        result: 'SUCCESS',
        evidence: _passedEvidence(),
        verificationSampleCount: 50,
        verificationSummary: '50/50 Sector Samples Passed',
      );

      await _pump(tester, cert);

      expect(find.text('Target Partitions Overwritten:'), findsOneWidget);
      expect(
        find.text('Target partitions (not confirmed overwritten)'),
        findsNothing,
      );
      expect(find.textContaining('Samples Checked'), findsOneWidget);
      expect(find.textContaining('Evidence Hash'), findsOneWidget);
      expect(find.text('Verification: not run'), findsNothing);
    });

    testWidgets(
      'completed overwrite with a failed verification still shows the samples',
      (tester) async {
        final cert = _certificate(
          result: 'FAILED',
          evidence: _failedEvidence(),
          verificationSampleCount: 50,
          verificationSummary: 'Sample Verification Failed',
        );

        await _pump(tester, cert);

        expect(find.text('Target Partitions Overwritten:'), findsOneWidget);
        expect(
          find.text('Target partitions (not confirmed overwritten)'),
          findsNothing,
        );
        expect(find.textContaining('Samples Checked'), findsOneWidget);
        expect(find.textContaining('Evidence Hash'), findsOneWidget);
        expect(find.text('Verification: not run'), findsNothing);
      },
    );

    testWidgets(
      'wipe that completed without verification says verification was not run',
      (tester) async {
        final cert = _certificate(
          result: 'SUCCESS',
          evidence: VerificationEvidence(
            statusCode: 1,
            controllerConfirmation:
                'VERIFICATION: Sampling unavailable (disk wipe command succeeded)',
            sampleOffsets: List.generate(50, (index) => index * 1000),
            sampleHashes: {
              for (var index = 0; index < 50; index++) index: '0' * 64,
            },
            evidenceHash: 'VERIFY_UNAVAILABLE',
            limitations: 'Partition wipe',
            verifiedPassed: false,
          ),
          verificationSampleCount: 50,
        );

        await _pump(tester, cert);

        expect(find.text('Target Partitions Overwritten:'), findsOneWidget);
        expect(find.text('Verification: not run'), findsOneWidget);
        expect(find.textContaining('Samples Checked'), findsNothing);
        expect(find.textContaining('Evidence Hash'), findsNothing);
        expect(find.textContaining('VERIFY_UNAVAILABLE'), findsNothing);
      },
    );
  });
}
