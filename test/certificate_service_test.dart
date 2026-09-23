import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/certificate_service.dart';

void main() {
  group('CertificateService and SanitizationCertificate Tests', () {
    late CertificateService service;

    setUp(() {
      service = CertificateService();
    });

    final testEvidence = VerificationEvidence(
      statusCode: 0,
      controllerConfirmation: 'Controller confirmation OK',
      sampleOffsets: [0, 512, 1024],
      sampleHashes: {
        0: 'hash0',
        512: 'hash512',
        1024: 'hash1024',
      },
      evidenceHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
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

    const usbDevice = DeviceProfile(
      id: 'sdb',
      name: 'SanDisk Ultra',
      serialNumber: 'SD12345678',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 32000000000,
    );

    test('Generates v2 certificate with required fields and verifies signature', () {
      final job = SanitizationJob(
        jobId: 'JOB-V2-001',
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

      final cert = service.generateCertificate(
        job: job,
        evidence: testEvidence,
        executionMode: 'simulated',
        actualMethodExecuted: 'NVMe Sanitize (Block Erase)',
      );

      expect(cert.certVersion, 2);
      expect(cert.executionMode, 'simulated');
      expect(cert.simulationDisclaimer, contains('SIMULATED, not a valid sanitization record'));
      expect(cert.sanitizationCategory, 'Purge');
      expect(cert.busType, 'NVMe');
      expect(cert.supportLevel, contains('Full support'));
      expect(cert.signature, isNotEmpty);
      expect(cert.signature, contains(':'));

      // Verify signature via CertificateService
      final certJson = cert.toJson();
      final isValid = service.verifyCertificateSignature(certJson);
      expect(isValid, isTrue);
    });

    test('Real execution mode omits simulation disclaimer', () {
      final job = SanitizationJob(
        jobId: 'JOB-REAL-001',
        device: nvmeDevice,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 0.60,
        targetCategory: NistCategory.purge,
        recommendedMethod: SanitizationMethod.nvmeSanitize,
        standardReference: 'NIST SP 800-88r2 Purge',
        explanationText: 'Real NVMe Sanitize',
      );

      final cert = service.generateCertificate(
        job: job,
        evidence: testEvidence,
        executionMode: 'real',
        actualMethodExecuted: 'NVMe Format / Sanitize',
      );

      expect(cert.certVersion, 2);
      expect(cert.executionMode, 'real');
      expect(cert.simulationDisclaimer, isNull);

      final json = cert.toJson();
      expect(json.containsKey('simulationDisclaimer'), isFalse);
      expect(service.verifyCertificateSignature(json), isTrue);
    });

    group('Derive sanitizationCategory rules', () {
      test('Flash media running overwrite gets Clear even if target was Purge', () {
        final category = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.singlePassOverwrite,
          device: usbDevice,
          actualMethodExecuted: 'Single-Pass Zero Overwrite',
          isSuccess: true,
        );
        expect(category, 'Clear');
      });

      test('Firmware sanitize command on NVMe gets Purge', () {
        final category = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.nvmeSanitize,
          device: nvmeDevice,
          actualMethodExecuted: 'NVMe Sanitize (Crypto Erase)',
          isSuccess: true,
        );
        expect(category, 'Purge');
      });

      test('Failed execution gets Failed', () {
        final category = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.nvmeSanitize,
          device: nvmeDevice,
          actualMethodExecuted: 'NVMe Sanitize',
          isSuccess: false,
        );
        expect(category, 'Failed');
      });

      test('Physical destruction method gets Destroy', () {
        final category = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.physicalDestructionRecommended,
          device: usbDevice,
          isSuccess: true,
        );
        expect(category, 'Destroy');
      });
    });

    test('Populates warningLine when user executes overwrite despite Destroy recommendation', () {
      final job = SanitizationJob(
        jobId: 'JOB-WARN-001',
        device: usbDevice,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 0.85,
        targetCategory: NistCategory.destroy,
        recommendedMethod: SanitizationMethod.physicalDestructionRecommended,
        standardReference: 'NIST SP 800-88r2 Destroy',
        explanationText: 'Physical destruction recommended for confidential flash',
        overriddenMethod: SanitizationMethod.singlePassOverwrite,
        destroyAcknowledged: true,
      );

      final cert = service.generateCertificate(
        job: job,
        evidence: testEvidence,
        executionMode: 'simulated',
      );

      expect(cert.warningLine, contains('WARNING: User proceeded with overwrite despite NIST SP 800-88 Destroy recommendation'));
      expect(cert.sanitizationCategory, 'Clear');

      // Signature verification covers the warningLine
      final json = cert.toJson();
      expect(json['warningLine'], isNotNull);
      expect(service.verifyCertificateSignature(json), isTrue);
    });

    test('Backward compatibility: verifies real legacy v1 certificate fixture without certVersion', () {
      // Generate a legitimate v1 certificate signed with this keypair
      final legacyJob = SanitizationJob(
        jobId: 'JOB-LEGACY-123',
        device: nvmeDevice,
        dataSensitivity: DataSensitivity.internal,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.30,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88r2 Clear',
        explanationText: 'Legacy Clear',
      );

      final legacyCert = service.generateLegacyV1Certificate(
        job: legacyJob,
        evidence: testEvidence,
      );

      // Convert to old-style JSON fixture (remove any v2 specific fields to simulate old file)
      final Map<String, dynamic> oldFixtureJson = {
        'certificateId': legacyCert.certificateId,
        'jobId': legacyCert.jobId,
        'deviceModel': legacyCert.deviceModel,
        'deviceSerial': legacyCert.deviceSerial,
        'mediaType': legacyCert.mediaType,
        'capacity': legacyCert.capacity,
        'method': legacyCert.method,
        'standardReference': legacyCert.standardReference,
        'startTime': legacyCert.startTime.toIso8601String(),
        'endTime': legacyCert.endTime.toIso8601String(),
        'timestamp': legacyCert.endTime.toIso8601String(),
        'result': legacyCert.result,
        'verificationSummary': legacyCert.verificationSummary,
        'evidence': legacyCert.evidence.toJson(),
        'softwareVersion': 'Zero Trace v1.0 Legacy',
        'signature': legacyCert.signature,
        'publicKeyPem': legacyCert.publicKeyPem,
        // Notice: NO 'certVersion', NO 'busType', NO 'sanitizationCategory', NO 'executionMode'
      };

      // 1. Must parse via SanitizationCertificate.fromJson without error
      final parsedCert = SanitizationCertificate.fromJson(oldFixtureJson);
      expect(parsedCert.certVersion, 1);
      expect(parsedCert.certificateId, legacyCert.certificateId);
      expect(parsedCert.deviceSerial, 'S5GXNF0R123456');

      // 2. Must verify signature as VALID using the v1 payload format
      final isValid = service.verifyCertificateSignature(oldFixtureJson);
      expect(isValid, isTrue);
    });

    test('PDF generation creates valid PDF bytes for v2 certificate', () async {
      final job = SanitizationJob(
        jobId: 'JOB-PDF-001',
        device: nvmeDevice,
        dataSensitivity: DataSensitivity.internal,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.20,
        targetCategory: NistCategory.purge,
        recommendedMethod: SanitizationMethod.nvmeSanitize,
        standardReference: 'NIST SP 800-88r2 Purge',
        explanationText: 'NVMe Sanitize',
      );

      final cert = service.generateCertificate(
        job: job,
        evidence: testEvidence,
        executionMode: 'simulated',
        verificationSampleCount: 50,
        verificationEntropyScore: 0.0002,
      );

      final pdfBytes = await service.generatePdfBytes(cert);
      expect(pdfBytes, isNotEmpty);
      // PDF file magic header (%PDF-)
      final pdfHeader = utf8.decode(pdfBytes.sublist(0, 5));
      expect(pdfHeader, '%PDF-');
    });
  });
}
