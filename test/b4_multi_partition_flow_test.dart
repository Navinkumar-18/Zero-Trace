import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/partition_info.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/models/untrusted_text.dart';
import 'package:zero_trace/services/certificate_service.dart';
import 'package:zero_trace/services/policy_layer.dart';

/// B4: full-disk and multi-partition flows.
///
/// - SanitizationJob carries every selected partition (subset wipe).
/// - PolicyLayer.validatePartitionTarget gates each target fail-closed.
/// - Certificates list every partition of a subset wipe (v4 `partitions[]`).
void main() {
  PartitionInfo part(int n, {bool protected = false, bool swap = false, String? mp}) =>
      PartitionInfo(
        partitionNumber: n,
        name: 'sdb$n',
        devicePath: '/dev/sdb$n',
        startSector: 2048 * n,
        sizeSectors: 204800,
        sizeBytes: 104857600,
        label: UntrustedText('PART$n'),
        fsType: 'ext4',
        mountPoint: mp,
        isProtected: protected,
        isActiveSwap: swap,
      );

  DeviceProfile device({bool systemDisk = false}) => DeviceProfile(
        id: 'real_sdb',
        name: 'Windows Laptop SSD',
        serialNumber: 'ABCDEF123456',
        mediaType: MediaType.sataSsd,
        busType: 'SATA',
        capacityBytes: 512000000000,
        isSystemDisk: systemDisk,
      );

  SanitizationJob jobFor(
    DeviceProfile dev, {
    PartitionInfo? first,
    List<PartitionInfo>? all,
  }) =>
      SanitizationJob(
        jobId: 'JOB-B4-001',
        device: dev,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 0.3,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88 R1 Clear (Partition Scope Overwrite)',
        explanationText: 'Partition overwrite',
        targetPartition: first,
        targetPartitions: all,
      );

  group('B4 SanitizationJob target list', () {
    test('targetPartitions defaults to the single target partition', () {
      final j = jobFor(device(), first: part(1));
      expect(j.targetPartitions, hasLength(1));
      expect(j.targetPartitions.single.name, 'sdb1');
      expect(j.wipeExecutionTargets, hasLength(1));
      expect(j.wipeExecutionTargets.single!.name, 'sdb1');
    });

    test('whole-device job executes a single whole-disk pass', () {
      final j = jobFor(device());
      expect(j.isPartitionScope, isFalse);
      expect(j.targetPartitions, isEmpty);
      expect(j.wipeExecutionTargets, [null]);
    });

    test('subset wipe keeps every selected partition in order', () {
      final j = jobFor(device(), first: part(1), all: [part(1), part(2), part(3)]);
      expect(j.isPartitionScope, isTrue);
      expect(j.wipeExecutionTargets.map((t) => t!.name), ['sdb1', 'sdb2', 'sdb3']);
    });
  });

  group('B4 validatePartitionTarget pre-flight', () {
    final policy = PolicyLayer();

    test('allows a clean, unmounted, non-system partition', () {
      final result = policy.validatePartitionTarget(jobFor(device()), part(1));
      expect(result.isAllowed, isTrue);
      expect(result.policyMessage, contains('PASSED'));
    });

    test('refuses a protected partition fail-closed', () {
      final result = policy.validatePartitionTarget(
          jobFor(device()), part(2, protected: true));
      expect(result.isAllowed, isFalse);
      expect(result.policyMessage, contains('Target partition (sdb2) is protected'));
    });

    test('refuses active swap and system-mount partitions', () {
      expect(
        policy.validatePartitionTarget(jobFor(device()), part(3, swap: true)).isAllowed,
        isFalse,
      );
      expect(
        policy.validatePartitionTarget(
                jobFor(device()), part(4, mp: '/home'))
            .isAllowed,
        isFalse,
        reason: 'a later protected target must fail the pre-flight so the '
            'subset wipe never starts half-way',
      );
    });

    test('refuses system disks and firmware methods', () {
      expect(
        policy.validatePartitionTarget(jobFor(device(systemDisk: true)), part(1))
            .isAllowed,
        isFalse,
      );
      final fwJob = jobFor(device(), first: part(1));
      fwJob.overriddenMethod = SanitizationMethod.ataSecureErase;
      expect(policy.validatePartitionTarget(fwJob, part(1)).isAllowed, isFalse);
    });
  });

  group('B4 multi-partition certificate', () {
    final service = CertificateService();
    final evidence = VerificationEvidence(
      statusCode: 0,
      controllerConfirmation: 'VERIFICATION: Pass: true',
      sampleOffsets: const [2048, 4096],
      sampleHashes: const {
        2048: 'aa',
        4096: 'bb',
      },
      evidenceHash: 'VEHASH',
      limitations: 'none',
      verifiedPassed: true,
    );

    test('v4 certificate lists every partition of the subset wipe', () {
      final j = jobFor(device(), first: part(1), all: [part(1), part(2)]);
      final cert = service.generateCertificate(
        job: j,
        evidence: evidence,
        executionMode: 'simulated',
        stepsExecuted: const ['unmount sdb1', 'wipe sdb1', 'unmount sdb2', 'wipe sdb2'],
      );

      expect(cert.certVersion, 4);
      expect(cert.scope, 'partial');
      expect(cert.partitionsWiped, hasLength(2));
      expect(cert.partitionsWiped!.map((p) => p['name']), ['sdb1', 'sdb2']);

      final json = cert.toJson();
      expect((json['partitions'] as List).length, 2);
      expect(service.verifyCertificateSignature(json), isTrue);

      // Dropping a partition from the signed list breaks the signature.
      final tampered = Map<String, dynamic>.from(json);
      tampered['partitions'] = [
        (json['partitions'] as List).first,
      ];
      expect(service.verifyCertificateSignature(tampered), isFalse);
    });

    test('single-partition certificates are unchanged (back-compat)', () {
      final j = jobFor(device(), first: part(1));
      final cert = service.generateCertificate(
        job: j,
        evidence: evidence,
        executionMode: 'simulated',
      );
      expect(cert.partitionsWiped, hasLength(1));
      expect(service.verifyCertificateSignature(cert.toJson()), isTrue);
    });

    test('whole-device certificates carry no partition list', () {
      final cert = service.generateCertificate(
        job: jobFor(device()),
        evidence: evidence,
        executionMode: 'simulated',
      );
      expect(cert.partitionsWiped, isNull);
      expect(cert.scope, 'full');
      expect(service.verifyCertificateSignature(cert.toJson()), isTrue);
    });
  });

  group('B4 payload is JSON-stable', () {
    test('partitions key holds name, number, start sector and size', () {
      final payload = CertificateService.buildSigningPayload(
        certVersion: 4,
        certificateId: 'ZT-TEST-1',
        jobId: 'JOB-1',
        deviceSerial: 'SER',
        method: 'singlePassOverwrite',
        sanitizationCategory: 'Clear',
        executionMode: 'simulated',
        evidenceHash: 'VEHASH',
        result: 'SUCCESS',
        timestamp: '2026-01-01T00:00:00Z',
        partitionsWiped: [
          {
            'name': 'sdb1',
            'partition_number': 1,
            'start_sector': 2048,
            'size_bytes': 104857600,
          },
          {
            'name': 'sdb2',
            'partition_number': 2,
            'start_sector': 2097152,
            'size_bytes': 104857600,
          },
        ],
      );
      expect(payload['partitions'], hasLength(2));
      // Stable key order/content for deterministic signing.
      expect(jsonEncode(payload), contains('"partitions"'));
    });
  });

  group('B5 certificate boot environment & disk identity', () {
    final service = CertificateService();
    final evidence = VerificationEvidence(
      statusCode: 0,
      controllerConfirmation: 'VERIFICATION: Pass: true',
      sampleOffsets: const [2048],
      sampleHashes: const {2048: 'aa'},
      evidenceHash: 'VEHASH',
      limitations: 'none',
      verifiedPassed: true,
    );

    test('live-medium claim is signed and verifiable', () {
      final cert = service.generateCertificate(
        job: jobFor(device()),
        evidence: evidence,
        executionMode: 'real',
        bootEnvironment: 'live',
      );

      expect(cert.bootEnvironment, 'live');
      expect(cert.bootEnvironmentDisplay, contains('live medium'));
      // Disk model + serial are recorded (serial is the signed identity).
      expect(cert.deviceModel, 'Windows Laptop SSD');
      expect(cert.deviceSerial, 'ABCDEF123456');

      final json = cert.toJson();
      expect(json['bootEnvironment'], 'live');
      expect(service.verifyCertificateSignature(json), isTrue);

      // Forging the boot-environment claim breaks the signature.
      final forged = Map<String, dynamic>.from(json);
      forged['bootEnvironment'] = 'normal';
      expect(service.verifyCertificateSignature(forged), isFalse);
    });

    test('pre-B5 v4 certificates (no bootEnvironment) still verify', () {
      final cert = service.generateCertificate(
        job: jobFor(device()),
        evidence: evidence,
        executionMode: 'real',
      );
      final json = cert.toJson();
      expect(json.containsKey('bootEnvironment'), isFalse,
          reason: 'older v4 payloads must stay byte-identical');
      expect(service.verifyCertificateSignature(json), isTrue);
      expect(cert.bootEnvironmentDisplay, isNull);
    });

    test('boot environment wording covers all modes', () {
      SanitizationCertificate certWith(String? env) =>
          SanitizationCertificate.fromJson({
            ...service
                .generateCertificate(
                  job: jobFor(device()),
                  evidence: evidence,
                  executionMode: 'real',
                  bootEnvironment: env,
                )
                .toJson(),
            'bootEnvironment': env,
          });
      expect(certWith('live').bootEnvironmentDisplay, contains('live medium'));
      expect(certWith('normal').bootEnvironmentDisplay, contains('installed system'));
      expect(certWith('container').bootEnvironmentDisplay, contains('container'));
    });

    test('SSD/NVMe partition-only wipes keep the Clear level (B5 wording)', () {
      final j = jobFor(device(), first: part(1), all: [part(1), part(2)]);
      final cert = service.generateCertificate(
        job: j,
        evidence: evidence,
        executionMode: 'real',
        bootEnvironment: 'live',
      );
      // Overwrite of a subset is Clear even on purge-capable SSDs — the
      // certificate never claims Purge for partition-scoped wipes.
      expect(cert.sanitizationLevel, 'Clear');
      expect(cert.scope, 'partial');
      expect(cert.partitionsWiped, hasLength(2));
      expect(cert.bytesOverwritten, 2 * 104857600,
          reason: 'B4: bytes overwritten sums every targeted partition');
    });
  });
}
