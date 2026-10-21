import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/certificate_service.dart';
import 'package:zero_trace/services/platform_backend.dart';

void main() {
  late CertificateService service;

  setUp(() {
    service = CertificateService();
  });

  final testEvidence = VerificationEvidence(
    statusCode: 0,
    controllerConfirmation: 'Controller confirmation OK',
    sampleOffsets: [0, 512, 1024],
    sampleHashes: {0: 'hash0', 512: 'hash512', 1024: 'hash1024'},
    evidenceHash:
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    limitations: 'Sample of 3 sectors',
    verifiedPassed: true,
  );

  const nvmeDevice = DeviceProfile(
    id: 'nvme0n1',
    name: 'Samsung 980 PRO 1TB',
    serialNumber: 'S5GXNF0R123456',
    mediaType: MediaType.nvmeSsd,
    busType: 'NVMe',
    capacityBytes: 1000204886016,
    supportsNvmeSanitize: true,
  );

  SanitizationJob buildJob() => SanitizationJob(
        jobId: 'JOB-C7-001',
        device: nvmeDevice,
        dataSensitivity: DataSensitivity.internal,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.25,
        targetCategory: NistCategory.purge,
        recommendedMethod: SanitizationMethod.nvmeSanitize,
        standardReference: 'NIST SP 800-88r2 Purge',
        explanationText: 'NVMe Sanitize firmware purge',
      );

  group('C7: signed platform + backend fields (v4)', () {
    test('newly issued certificates are stamped with the issuing platform '
        'backend and verify across a model round-trip', () {
      final cert = service.generateCertificate(
        job: buildJob(),
        evidence: testEvidence,
        executionMode: 'simulated',
        actualMethodExecuted: 'NVMe Sanitize (start-block-erase)',
      );

      final json = cert.toJson();
      // CI/test host is Linux — mirrors the Rust current_backend() ids.
      expect(json['platform'], 'linux');
      expect(json['backend'], 'linux');
      expect(cert.platform, 'linux');
      expect(cert.backend, 'linux');
      expect(service.verifyCertificateSignature(json), isTrue);

      // Save/load round-trip keeps the signed fields intact.
      final reparsed = SanitizationCertificate.fromJson(json);
      expect(reparsed.platform, 'linux');
      expect(reparsed.backend, 'linux');
      expect(service.verifyCertificateSignature(reparsed.toJson()), isTrue);
    });

    test('pre-C7 v4 payloads (no platform/backend keys) still verify', () {
      final payload = CertificateService.buildSigningPayload(
        certVersion: 4,
        certificateId: 'ZT-CERT-PREC7',
        jobId: 'JOB-PREC7',
        deviceSerial: nvmeDevice.serialNumber,
        method: 'NVMe Sanitize (start-block-erase)',
        sanitizationCategory: 'Purge',
        executionMode: 'simulated',
        evidenceHash: testEvidence.evidenceHash,
        result: 'SUCCESS',
        timestamp: '2026-01-01T00:00:00.000',
        scope: 'full',
        bootEnvironment: 'live',
      );

      // Absent values are omitted entirely — the historic byte shape.
      expect(payload.containsKey('platform'), isFalse);
      expect(payload.containsKey('backend'), isFalse);

      final fixture = <String, dynamic>{
        ...payload,
        'signature': service.signPayloadForTesting(jsonEncode(payload)),
      };
      expect(service.verifyCertificateSignature(fixture), isTrue);

      // The builder only adds the keys when values are present.
      final withPlatform = CertificateService.buildSigningPayload(
        certVersion: 4,
        certificateId: 'ZT-CERT-PREC7',
        jobId: 'JOB-PREC7',
        deviceSerial: nvmeDevice.serialNumber,
        method: 'NVMe Sanitize (start-block-erase)',
        sanitizationCategory: 'Purge',
        executionMode: 'simulated',
        evidenceHash: testEvidence.evidenceHash,
        result: 'SUCCESS',
        timestamp: '2026-01-01T00:00:00.000',
        scope: 'full',
        platform: 'linux',
        backend: 'linux',
      );
      expect(withPlatform['platform'], 'linux');
      expect(withPlatform['backend'], 'linux');
    });

    test('the signed platform claim cannot be forged or stripped after the '
        'fact', () {
      final cert = service.generateCertificate(
        job: buildJob(),
        evidence: testEvidence,
        executionMode: 'simulated',
      );
      final json = cert.toJson();

      final forged = Map<String, dynamic>.from(json);
      forged['platform'] = 'windows';
      forged['backend'] = 'windows';
      expect(service.verifyCertificateSignature(forged), isFalse);

      final stripped = Map<String, dynamic>.from(json)
        ..remove('platform')
        ..remove('backend');
      expect(service.verifyCertificateSignature(stripped), isFalse);
    });
  });

  group('C7: backend identity values', () {
    test('provider reports platform and backend ids for this host', () {
      final backend = resolvePlatformBackend();
      expect(backend.platformName, 'linux'); // CI test host
      expect(backend.backendId, 'linux');
      expect(WindowsPlatformBackend().backendId, 'windows');
      expect(AndroidPlatformBackend().backendId, 'android');
    });
  });
}
