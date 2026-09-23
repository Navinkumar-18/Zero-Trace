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
        actualMethodExecuted: 'NVMe Sanitize (start-block-erase)',
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

    const sataSsdDevice = DeviceProfile(
      id: 'sda',
      name: 'Crucial MX500 500GB',
      serialNumber: 'CT500MX500123',
      mediaType: MediaType.sataSsd,
      busType: 'SATA',
      capacityBytes: 500000000000,
      supportsAtaSecureErase: true,
      supportsAtaSanitize: true,
    );

    group('Derive sanitizationCategory rules', () {
      test('overwrite -> Clear', () {
        // Test single-pass zero overwrite
        final cat1 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.singlePassOverwrite,
          device: nvmeDevice,
          actualMethodExecuted: 'Software Overwrite (1-pass, Zeros)',
          isSuccess: true,
        );
        expect(cat1, 'Clear');

        // Test multi-pass overwrite
        final cat2 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.multiPassOverwrite,
          device: nvmeDevice,
          actualMethodExecuted: 'Software Overwrite (3-pass, NistLegacy3Pass)',
          isSuccess: true,
        );
        expect(cat2, 'Clear');

        // Test ATA Sanitize Overwrite
        final cat3 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.singlePassOverwrite,
          device: sataSsdDevice,
          actualMethodExecuted: 'ATA Sanitize Overwrite',
          isSuccess: true,
        );
        expect(cat3, 'Clear');

        // Test Flash media without firmware purge running overwrite
        final cat4 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.singlePassOverwrite,
          device: usbDevice,
          actualMethodExecuted: 'Single-Pass Zero Overwrite',
          isSuccess: true,
        );
        expect(cat4, 'Clear');
      });

      test('secure erase success -> Purge', () {
        // Test ATA Secure Erase
        final cat1 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.ataSecureErase,
          device: sataSsdDevice,
          actualMethodExecuted: 'ATA Secure Erase',
          isSuccess: true,
        );
        expect(cat1, 'Purge');

        // Test ATA Enhanced Secure Erase
        final cat2 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.ataSecureErase,
          device: sataSsdDevice,
          actualMethodExecuted: 'ATA Enhanced Secure Erase',
          isSuccess: true,
        );
        expect(cat2, 'Purge');

        // Test ATA Sanitize Block Erase
        final cat3 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.ataSanitizeBlockErase,
          device: sataSsdDevice,
          actualMethodExecuted: 'ATA Sanitize Block Erase',
          isSuccess: true,
        );
        expect(cat3, 'Purge');
      });

      test('nvme sanitize -> Purge', () {
        // Test NVMe Sanitize (start-block-erase)
        final cat1 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.nvmeSanitize,
          device: nvmeDevice,
          actualMethodExecuted: 'NVMe Sanitize (start-block-erase)',
          isSuccess: true,
        );
        expect(cat1, 'Purge');

        // Test NVMe Sanitize (start-crypto-erase)
        final cat2 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.nvmeSanitize,
          device: nvmeDevice,
          actualMethodExecuted: 'NVMe Sanitize (start-crypto-erase)',
          isSuccess: true,
        );
        expect(cat2, 'Purge');

        // Test Flutter simulated mode display name
        final cat3 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.nvmeSanitize,
          device: nvmeDevice,
          actualMethodExecuted: 'NVMe Sanitize (Block / Crypto Erase)',
          isSuccess: true,
        );
        expect(cat3, 'Purge');
      });

      test('unknown string -> Clear (default to the safer label)', () {
        // Filesystem formats must NOT return Purge
        final cat1 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.singlePassOverwrite,
          device: nvmeDevice,
          actualMethodExecuted: 'mkfs.ext4 /dev/nvme0n1',
          isSuccess: true,
        );
        expect(cat1, 'Clear');

        // NVMe format without secure erase parameters
        final cat2 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.singlePassOverwrite,
          device: nvmeDevice,
          actualMethodExecuted: 'NVMe Format (Namespace Format)',
          isSuccess: true,
        );
        expect(cat2, 'Clear');

        // Arbitrary tool / unknown string defaults to Clear
        final cat3 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.singlePassOverwrite,
          device: nvmeDevice,
          actualMethodExecuted: 'custom-vendor-erase-tool',
          isSuccess: true,
        );
        expect(cat3, 'Clear');
      });

      test('failed -> Failed', () {
        final category = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.nvmeSanitize,
          device: nvmeDevice,
          actualMethodExecuted: 'NVMe Sanitize (start-block-erase)',
          isSuccess: false,
        );
        expect(category, 'Failed');
      });

      test('physical destruction recommended -> not "Destroy" ("Destroy recommended, not performed")', () {
        final cat1 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.physicalDestructionRecommended,
          device: usbDevice,
          isSuccess: true,
        );
        expect(cat1, isNot(equals('Destroy')));
        expect(cat1, 'Destroy recommended, not performed');

        final cat2 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.unsupportedFlagForDestroy,
          device: usbDevice,
          isSuccess: true,
        );
        expect(cat2, isNot(equals('Destroy')));
        expect(cat2, 'Destroy recommended, not performed');

        final cat3 = CertificateService.deriveSanitizationCategory(
          method: SanitizationMethod.singlePassOverwrite,
          device: usbDevice,
          actualMethodExecuted: 'Physical Destruction',
          isSuccess: true,
        );
        expect(cat3, isNot(equals('Destroy')));
        expect(cat3, 'Destroy recommended, not performed');
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
