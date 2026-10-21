import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/services/certificate_service.dart';

/// C0: characterization golden — the exact v4 signing payload bytes that must
/// never change for existing v1–v4 certificates (Phase C hard rule).
///
/// Regenerate ONLY for an intentional, reviewed protocol change:
///
/// ```sh
/// ZT_UPDATE_GOLDEN=1 flutter test test/certificate_payload_golden_test.dart
/// ```
void main() {
  test('v4 signing payload matches the committed golden bytes', () {
    final payload = CertificateService.buildSigningPayload(
      certVersion: 4,
      certificateId: 'ZT-CERT-GOLDEN-0000001',
      jobId: 'JOB-GOLDEN-001',
      deviceSerial: 'GOLDEN-SERIAL-1234',
      method: 'singlePassOverwrite',
      sanitizationCategory: 'Clear',
      executionMode: 'real',
      evidenceHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      result: 'SUCCESS',
      timestamp: '2026-01-01T00:00:00.000',
      warningLine: null,
      scope: 'partial',
      limitation:
          'Partition wipe: partition table and unselected sectors are not overwritten',
      partitionsWiped: [
        {
          'name': 'sda3',
          'partition_number': 3,
          'start_sector': 8192,
          'size_bytes': 1048576,
        },
      ],
      sanitizationLevel: 'Clear',
      stepsExecuted: [
        '[DRY RUN] [guard] partition geometry and table fingerprint verified',
      ],
      bytesOverwritten: 1048576,
      totalDeviceBytes: 512110190592,
      bootEnvironment: 'live',
    );

    final actual = '${const JsonEncoder.withIndent('  ').convert(payload)}\n';
    final path = 'test/fixtures/certificate_payload_v4_golden.json';
    if (Platform.environment['ZT_UPDATE_GOLDEN'] == '1') {
      File(path).parent.createSync(recursive: true);
      File(path).writeAsStringSync(actual);
      return;
    }
    final expected = File(path).readAsStringSync();
    expect(actual, expected,
        reason: 'v4 signing payload bytes changed — existing certificates '
            'would stop verifying. This is a protocol break unless explicitly '
            'reviewed and versioned.');
  });
}
