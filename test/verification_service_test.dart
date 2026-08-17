import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/verification_service.dart';

void main() {
  group('Algorithm 3 — VerificationService Tests', () {
    final service = VerificationService();

    const dev = DeviceProfile(
      id: '1',
      name: 'Test Device',
      serialNumber: 'SN123',
      mediaType: MediaType.nvmeSsd,
      busType: 'NVMe',
      capacityBytes: 10000000000,
    );

    final job = SanitizationJob(
      jobId: 'JOB-TEST-100',
      device: dev,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 0.65,
      targetCategory: NistCategory.purge,
      recommendedMethod: SanitizationMethod.nvmeSanitize,
      standardReference: 'NIST SP 800-88r2 Purge',
      explanationText: 'NVMe Sanitize test',
    );

    test('Generates exactly 50 sample offsets and valid SHA-256 evidence hash on success', () {
      final evidence = service.verify(job, isSuccess: true);
      expect(evidence.sampleOffsets.length, 50);
      expect(evidence.sampleHashes.length, 50);
      expect(evidence.verifiedPassed, isTrue);
      expect(evidence.evidenceHash.length, 64); // SHA-256 length
      expect(evidence.limitations, contains('Verifies controller sanitize completion flag'));
    });

    test('Marks verification failed on error status', () {
      final evidence = service.verify(job, isSuccess: false);
      expect(evidence.verifiedPassed, isFalse);
      expect(evidence.statusCode, 1);
    });
  });
}
