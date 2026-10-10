import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/services/audit_log_service.dart';

void main() {
  group('AuditLogService Hash Chain & Schema Integrity Tests', () {
    late Directory tempDir;
    late AuditLogService service;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('zt_audit_test_');
      service = AuditLogService(customBaseDirectory: tempDir.path);
    });

    tearDown(() async {
      if (tempDir.existsSync()) {
        await tempDir.delete(recursive: true);
      }
    });

    AuditLogEntry createSampleEntry({
      required String jobId,
      String? certId,
      String? certSha,
      bool isSimulated = false,
      bool success = true,
      String scope = 'full',
      String? methodClass,
      bool? verificationPassed,
      List<PartitionAuditOutcome>? partitions,
    }) {
      return AuditLogEntry(
        timestamp: '2026-10-10T12:00:00Z',
        jobId: jobId,
        deviceSerial: 'SERIAL-12345',
        devicePath: '/dev/sdb',
        deviceName: 'Samsung SSD 870',
        method: 'ATA Secure Erase',
        standardReference: 'NIST SP 800-88r1 Purge',
        nistCategory: 'Purge',
        success: success,
        fingerprintHash: 'FINGERPRINT-HASH-123',
        entropyScore: 0.0001,
        sampleCount: 50,
        commandLog: ['Unmounting device', 'Executing erase', 'Verification OK'],
        scope: scope,
        methodClass: methodClass ?? 'firmwareSanitize',
        certificateId: certId,
        certificateSha256: certSha,
        isSimulated: isSimulated,
        verificationPassed: verificationPassed ?? success,
        partitions: partitions,
      );
    }

    test('Chain genesis and valid chain appending', () async {
      final entry1 = await service.appendEntry(createSampleEntry(jobId: 'JOB-001'));
      expect(entry1.previousHash, equals(AuditLogService.genesisHash));
      expect(entry1.entryHash, isNotNull);

      final entry2 = await service.appendEntry(createSampleEntry(jobId: 'JOB-002'));
      expect(entry2.previousHash, equals(entry1.entryHash));
      expect(entry2.entryHash, isNotNull);

      final result = await service.verifyChainIntegrity();
      expect(result.status, equals(ChainIntegrityStatus.valid));
      expect(result.totalEntries, equals(2));
    });

    test('Tampering test: editing an entry breaks chain integrity at that line', () async {
      await service.appendEntry(createSampleEntry(jobId: 'JOB-001'));
      await service.appendEntry(createSampleEntry(jobId: 'JOB-002'));
      await service.appendEntry(createSampleEntry(jobId: 'JOB-003'));

      final logFile = File('${tempDir.path}/audit_log.jsonl');
      final lines = await logFile.readAsLines();

      // Edit line 2 (JOB-002)
      final map2 = jsonDecode(lines[1]) as Map<String, dynamic>;
      map2['method'] = 'TAMPERED METHOD';
      lines[1] = jsonEncode(map2);
      await logFile.writeAsString(lines.join('\n') + '\n');

      final result = await service.verifyChainIntegrity();
      expect(result.status, equals(ChainIntegrityStatus.broken));
      expect(result.brokenLineNumber, equals(2));
      expect(result.failureReason, contains('entryHash mismatch'));
    });

    test('Tampering test: deleting an entry breaks previousHash linking at subsequent line', () async {
      await service.appendEntry(createSampleEntry(jobId: 'JOB-001'));
      await service.appendEntry(createSampleEntry(jobId: 'JOB-002'));
      await service.appendEntry(createSampleEntry(jobId: 'JOB-003'));

      final logFile = File('${tempDir.path}/audit_log.jsonl');
      final lines = await logFile.readAsLines();

      // Delete entry 2
      lines.removeAt(1);
      await logFile.writeAsString(lines.join('\n') + '\n');

      final result = await service.verifyChainIntegrity();
      expect(result.status, equals(ChainIntegrityStatus.broken));
      expect(result.brokenLineNumber, equals(2));
      expect(result.failureReason, contains('previousHash mismatch'));
    });

    test('Tampering test: reordering entries breaks chain integrity', () async {
      await service.appendEntry(createSampleEntry(jobId: 'JOB-001'));
      await service.appendEntry(createSampleEntry(jobId: 'JOB-002'));

      final logFile = File('${tempDir.path}/audit_log.jsonl');
      final lines = await logFile.readAsLines();

      // Swap line 1 and 2
      final swapped = [lines[1], lines[0]];
      await logFile.writeAsString(swapped.join('\n') + '\n');

      final result = await service.verifyChainIntegrity();
      expect(result.status, equals(ChainIntegrityStatus.broken));
      expect(result.brokenLineNumber, equals(1));
    });

    test('Torn last line tolerance: corrupt or truncated final line is tolerated', () async {
      await service.appendEntry(createSampleEntry(jobId: 'JOB-001'));
      await service.appendEntry(createSampleEntry(jobId: 'JOB-002'));

      final logFile = File('${tempDir.path}/audit_log.jsonl');
      // Append a torn incomplete JSON fragment as last line
      await logFile.writeAsString('{"timestamp":"2026-10-10", "jobId":"JOB-TORN', mode: FileMode.append);

      final result = await service.verifyChainIntegrity();
      expect(result.status, equals(ChainIntegrityStatus.valid));
      expect(result.totalEntries, equals(2));
    });

    test('Legacy lines tolerance: older unchained entries at the head are tolerated', () async {
      final logFile = File('${tempDir.path}/audit_log.jsonl');
      // Write legacy entry without hash fields
      final legacyMap = {
        'timestamp': '2026-10-01T10:00:00Z',
        'jobId': 'JOB-LEGACY-001',
        'deviceSerial': 'OLD-SERIAL',
        'devicePath': '/dev/sda',
        'method': 'Single-Pass Overwrite',
        'standardReference': 'NIST SP 800-88',
        'nistCategory': 'Clear',
        'success': true,
        'fingerprintHash': 'OLD-HASH',
        'entropyScore': 0.001,
        'sampleCount': 20,
        'commandLog': ['legacy run'],
        // Legacy entry has NO scope, methodClass, certificateId, previousHash, entryHash
      };
      await logFile.writeAsString('${jsonEncode(legacyMap)}\n');

      // Now append chained entries
      await service.appendEntry(createSampleEntry(jobId: 'JOB-CHAIN-001'));
      await service.appendEntry(createSampleEntry(jobId: 'JOB-CHAIN-002'));

      final result = await service.verifyChainIntegrity();
      expect(result.status, equals(ChainIntegrityStatus.validWithLegacy));
      expect(result.totalEntries, equals(3));
      expect(result.legacyCount, equals(1));
    });

    test('Old legacy entry parsing: scope defaults to full, optional fields stay null', () async {
      final legacyJson = {
        'timestamp': '2026-09-01T00:00:00Z',
        'jobId': 'JOB-OLD',
        'deviceSerial': 'SERIAL-OLD',
        'devicePath': '/dev/sda',
        'method': 'Zero Fill',
        'standardReference': 'NIST',
        'nistCategory': 'Clear',
        'success': true,
        'fingerprintHash': 'HASH',
        'entropyScore': 0.0,
        'sampleCount': 10,
        'commandLog': <String>[],
      };

      final parsed = AuditLogEntry.fromJson(legacyJson);
      expect(parsed.scope, equals('full'));
      expect(parsed.methodClass, isNull);
      expect(parsed.verificationPassed, isNull);
      expect(parsed.certificateId, isNull);
      expect(parsed.certificateSha256, isNull);
    });

    test('Per-partition outcome schema parsing and serialization', () async {
      final partitions = [
        const PartitionAuditOutcome(
          partitionNumber: 1,
          startSector: 2048,
          sizeSectors: 204800,
          status: 'COMPLETED',
          bytesWiped: 104857600,
        ),
      ];

      final entry = createSampleEntry(
        jobId: 'JOB-PART-001',
        scope: 'partial',
        partitions: partitions,
      );

      final appended = await service.appendEntry(entry);
      expect(appended.scope, equals('partial'));
      expect(appended.partitions, isNotNull);
      expect(appended.partitions!.length, equals(1));
      expect(appended.partitions!.first.partitionNumber, equals(1));
      expect(appended.partitions!.first.status, equals('COMPLETED'));
      expect(appended.partitions!.first.bytesWiped, equals(104857600));

      final retrieved = await service.getEntryByJobId('JOB-PART-001');
      expect(retrieved, isNotNull);
      expect(retrieved!.partitions!.first.bytesWiped, equals(104857600));
    });

    test('Atomic certificate and failure report persistence with SHA-256', () async {
      final cert = SanitizationCertificate(
        certificateId: 'ZT-CERT-TEST-123',
        jobId: 'JOB-TEST',
        deviceModel: 'Test Drive',
        deviceSerial: 'SERIAL-999',
        mediaType: 'SATA SSD',
        capacity: '500 GB',
        method: 'ATA Secure Erase',
        standardReference: 'NIST',
        startTime: DateTime.now(),
        endTime: DateTime.now(),
        result: 'SUCCESS',
        verificationSummary: 'Passed',
        evidence: VerificationEvidence(
          statusCode: 0,
          controllerConfirmation: 'OK',
          sampleOffsets: [],
          sampleHashes: {},
          evidenceHash: 'HASH',
          limitations: '',
          verifiedPassed: true,
        ),
        softwareVersion: 'v2.0',
        signature: 'SIG:HEX',
        publicKeyPem: 'PEM',
      );

      final (file, sha) = await service.saveCertificate(cert);
      expect(file.existsSync(), isTrue);
      expect(sha, isNotEmpty);

      // Verify retrieval
      final loaded = await service.getCertificateById('ZT-CERT-TEST-123');
      expect(loaded, isNotNull);
      expect(loaded!.certificateId, equals('ZT-CERT-TEST-123'));
    });
  });
}
