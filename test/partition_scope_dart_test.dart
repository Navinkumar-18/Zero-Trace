import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/partition_info.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/models/untrusted_text.dart';
import 'package:zero_trace/services/assistant_context_builder.dart';
import 'package:zero_trace/services/certificate_service.dart';
import 'package:zero_trace/services/device_intelligence_service.dart';
import 'package:zero_trace/services/job_state_file.dart';
import 'package:zero_trace/services/partition_table_service.dart';
import 'package:zero_trace/services/policy_layer.dart';
import 'package:zero_trace/services/real_sanitization_service.dart';
import 'package:zero_trace/services/sanitization_controller.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Partition Table Fingerprint', () {
    test('matches Rust zt_engine shared test vector', () {
      final partitions = [
        const PartitionInfo(
          partitionNumber: 1,
          name: 'sdb1',
          devicePath: '/dev/sdb1',
          startSector: 2048,
          sizeSectors: 20969472,
          sizeBytes: 20969472 * 512,
          label: UntrustedText('PART1'),
        ),
        const PartitionInfo(
          partitionNumber: 2,
          name: 'sdb2',
          devicePath: '/dev/sdb2',
          startSector: 20971520,
          sizeSectors: 20971520,
          sizeBytes: 20971520 * 512,
          label: UntrustedText('PART2'),
        ),
        const PartitionInfo(
          partitionNumber: 3,
          name: 'sdb3',
          devicePath: '/dev/sdb3',
          startSector: 41943040,
          sizeSectors: 19496960,
          sizeBytes: 19496960 * 512,
          label: UntrustedText('PART3'),
        ),
      ];

      final fp = PartitionTableService.computeFingerprint(partitions);
      // Rust test_partition_table_fingerprint_shared_test_vector pinned SHA-256
      expect(fp, '8c4efb1b4866d0b332ebef624e1ba8cff76427c143b08a4f1199e6ee81279580');
    });

    test('is order-independent (canonical sorting by partitionNumber)', () {
      final p1 = const PartitionInfo(
        partitionNumber: 1,
        name: 'sda1',
        devicePath: '/dev/sda1',
        startSector: 2048,
        sizeSectors: 204800,
        sizeBytes: 104857600,
        label: UntrustedText('BOOT'),
      );
      final p2 = const PartitionInfo(
        partitionNumber: 2,
        name: 'sda2',
        devicePath: '/dev/sda2',
        startSector: 206848,
        sizeSectors: 409600,
        sizeBytes: 209715200,
        label: UntrustedText('DATA'),
      );

      final fp1 = PartitionTableService.computeFingerprint([p1, p2]);
      final fp2 = PartitionTableService.computeFingerprint([p2, p1]);
      expect(fp1, fp2);
    });
  });

  group('DeviceIntelligenceService Partition Parsing', () {
    test('parses children partitions with UntrustedText labels and mount classifications', () {
      final service = DeviceIntelligenceService();
      final lsblkFixture = [
        {
          "name": "sdb",
          "model": "Ultra Fit",
          "serial": "AA010928374",
          "size": 32000000000,
          "rota": false,
          "tran": "usb",
          "mountpoint": null,
          "type": "disk",
          "rm": true,
          "hotplug": true,
          "fstype": null,
          "label": null,
          "partuuid": null,
          "start": null,
          "partn": null,
          "children": [
            {
              "name": "sdb1",
              "model": null,
              "serial": null,
              "size": 104857600,
              "rota": false,
              "tran": "usb",
              "mountpoint": "/media/user/MY_USB",
              "type": "part",
              "rm": true,
              "hotplug": true,
              "fstype": "vfat",
              "label": "SECURE_USB\x1b[31m",
              "partuuid": "1234-abcd-5678",
              "start": 2048,
              "partn": 1
            },
            {
              "name": "sdb2",
              "model": null,
              "serial": null,
              "size": 209715200,
              "rota": false,
              "tran": "usb",
              "mountpoint": null,
              "type": "part",
              "rm": true,
              "hotplug": true,
              "fstype": "ext4",
              "label": "WORK_DATA",
              "partuuid": "9999-ffff-0000",
              "start": 206848,
              "partn": 2
            }
          ]
        }
      ];

      final profiles = service.parseBlockDevices(lsblkFixture);
      expect(profiles.length, 1);
      final profile = profiles.first;

      expect(profile.hasPartitions, isTrue);
      expect(profile.partitions.length, 2);

      final p1 = profile.partitions[0];
      expect(p1.partitionNumber, 1);
      expect(p1.name, 'sdb1');
      expect(p1.devicePath, '/dev/sdb1');
      expect(p1.startSector, 2048);
      expect(p1.sizeSectors, 104857600 ~/ 512);
      expect(p1.sizeBytes, 104857600);
      expect(p1.fsType, 'vfat');
      expect(p1.partUuid, '1234-abcd-5678');
      expect(p1.isMounted, isTrue);
      expect(p1.isMountAllowed, isTrue);
      expect(p1.isProtected, isFalse);
      expect(p1.label.rawValue, contains('SECURE_USB'));
      expect(p1.label.sanitized, isNot(contains('\x1b')));

      final p2 = profile.partitions[1];
      expect(p2.partitionNumber, 2);
      expect(p2.name, 'sdb2');
      expect(p2.devicePath, '/dev/sdb2');
      expect(p2.startSector, 206848);
      expect(p2.sizeSectors, 209715200 ~/ 512);
      expect(p2.isMounted, isFalse);

      expect(profile.partitionTableFingerprint, isNotNull);
      expect(profile.partitionTableFingerprint!.length, 64);
    });

    test('marks partition protected if hosting system mount or swap', () {
      final service = DeviceIntelligenceService();
      final lsblkFixture = [
        {
          "name": "sdc",
          "model": "Generic Disk",
          "serial": "DISK001",
          "size": 64000000000,
          "rota": true,
          "tran": "sata",
          "mountpoint": null,
          "type": "disk",
          "rm": false,
          "hotplug": false,
          "children": [
            {
              "name": "sdc1",
              "size": 16000000000,
              "mountpoint": "/home",
              "fstype": "ext4",
              "type": "part",
              "start": 2048,
              "partn": 1
            },
            {
              "name": "sdc2",
              "size": 4000000000,
              "mountpoint": null,
              "fstype": "swap",
              "type": "part",
              "start": 31252048,
              "partn": 2
            }
          ]
        }
      ];

      final profiles = service.parseBlockDevices(lsblkFixture);
      expect(profiles.length, 1);
      final profile = profiles.first;

      final p1 = profile.partitions[0];
      expect(p1.isMounted, isTrue);
      expect(p1.isMountAllowed, isFalse);
      expect(p1.isProtected, isTrue);

      final p2 = profile.partitions[1];
      expect(p2.isActiveSwap, isTrue);
      expect(p2.isProtected, isTrue);
    });
  });

  group('PolicyLayer Partition Scope Checks', () {
    final device = const DeviceProfile(
      id: 'real_sdb',
      name: 'USB Drive',
      serialNumber: 'USB123',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
      isSystemDisk: false,
    );

    final safePartition = const PartitionInfo(
      partitionNumber: 1,
      name: 'sdb1',
      devicePath: '/dev/sdb1',
      startSector: 2048,
      sizeSectors: 204800,
      sizeBytes: 104857600,
      label: UntrustedText('DATA'),
      isMounted: true,
      isMountAllowed: true,
      isProtected: false,
      isActiveSwap: false,
    );

    final protectedPartition = const PartitionInfo(
      partitionNumber: 2,
      name: 'sdb2',
      devicePath: '/dev/sdb2',
      startSector: 206848,
      sizeSectors: 409600,
      sizeBytes: 209715200,
      label: UntrustedText('SYSTEM'),
      isMounted: true,
      isMountAllowed: false,
      isProtected: true,
      isActiveSwap: false,
    );

    test('allows overwrite methods in partition mode', () {
      final policy = PolicyLayer();
      final job = SanitizationJob(
        jobId: 'JOB-PART-1',
        device: device,
        dataSensitivity: DataSensitivity.internal,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.3,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST Clear',
        explanationText: 'Overwrite',
        targetPartition: safePartition,
      );

      final result = policy.validateOperation(job);
      expect(result.isAllowed, isTrue);
    });

    test('refuses firmware sanitize/erase in partition mode', () {
      final policy = PolicyLayer();
      final job = SanitizationJob(
        jobId: 'JOB-PART-2',
        device: device,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.externalResale,
        riskScore: 0.8,
        targetCategory: NistCategory.purge,
        recommendedMethod: SanitizationMethod.cryptographicErase,
        standardReference: 'NIST Purge',
        explanationText: 'Crypto Erase',
        targetPartition: safePartition,
      );

      final result = policy.validateOperation(job);
      expect(result.isAllowed, isFalse);
      expect(result.policyMessage, contains('Partition mode only allows overwrite methods'));
    });

    test('refuses partition scope on an internal (non-removable) disk', () {
      final policy = PolicyLayer();
      final internalDevice = const DeviceProfile(
        id: 'real_sda',
        name: 'Internal SATA SSD',
        serialNumber: 'INT123',
        mediaType: MediaType.sataSsd,
        busType: 'SATA',
        capacityBytes: 512000000000,
        isRemovable: false,
        isSystemDisk: false,
      );

      final job = SanitizationJob(
        jobId: 'JOB-PART-INT',
        device: internalDevice,
        dataSensitivity: DataSensitivity.internal,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.3,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST Clear',
        explanationText: 'Overwrite',
        targetPartition: safePartition,
      );

      final result = policy.validateOperation(job);
      expect(result.isAllowed, isFalse);
      expect(result.policyMessage, contains('only permitted on removable media'));
    });

    test('refuses operation on protected partition', () {
      final policy = PolicyLayer();
      final job = SanitizationJob(
        jobId: 'JOB-PART-3',
        device: device,
        dataSensitivity: DataSensitivity.internal,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.3,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST Clear',
        explanationText: 'Overwrite',
        targetPartition: protectedPartition,
      );

      final result = policy.validateOperation(job);
      expect(result.isAllowed, isFalse);
      expect(result.policyMessage, contains('Target partition (sdb2) is protected'));
    });
  });

  group('ActiveJobState Partition Serialization', () {
    test('serializes and deserializes partition fields accurately', () {
      final state = ActiveJobState(
        jobId: 'JOB-100',
        deviceSerial: 'SER999',
        devicePath: '/dev/sdb1',
        deviceName: 'USB Drive',
        method: 'Single-Pass Zero Overwrite',
        startedAt: '2026-10-05T12:00:00Z',
        partitionNumber: 1,
        partitionStartSector: 2048,
        partitionSizeSectors: 204800,
        scope: 'partial',
        limitation: 'Partition wipe: partition table and unselected sectors are not overwritten',
      );

      final json = state.toJson();
      expect(json['partitionNumber'], 1);
      expect(json['partitionStartSector'], 2048);
      expect(json['partitionSizeSectors'], 204800);
      expect(json['scope'], 'partial');
      expect(json['limitation'], contains('Partition wipe'));

      final restored = ActiveJobState.fromJson(json);
      expect(restored.jobId, state.jobId);
      expect(restored.partitionNumber, 1);
      expect(restored.partitionStartSector, 2048);
      expect(restored.partitionSizeSectors, 204800);
      expect(restored.scope, 'partial');
      expect(restored.limitation, state.limitation);
    });
  });

  group('Certificate v3 Partition Scope & Tamper Detection', () {
    final certService = CertificateService();

    final device = const DeviceProfile(
      id: 'real_sdb',
      name: 'USB Drive',
      serialNumber: 'ABC12345',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
    );

    final partition = const PartitionInfo(
      partitionNumber: 1,
      name: 'sdb1',
      devicePath: '/dev/sdb1',
      startSector: 2048,
      sizeSectors: 204800,
      sizeBytes: 104857600,
      label: UntrustedText('DATA'),
    );

    final job = SanitizationJob(
      jobId: 'JOB-CERT-V3',
      device: device,
      dataSensitivity: DataSensitivity.internal,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.internalReuse,
      riskScore: 0.3,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 R1 Clear',
      explanationText: 'Single pass overwrite on partition',
      targetPartition: partition,
      startTime: DateTime.parse('2026-10-05T12:00:00Z'),
      endTime: DateTime.parse('2026-10-05T12:05:00Z'),
    );

    final evidence = VerificationEvidence(
      statusCode: 0,
      controllerConfirmation: 'VERIFICATION: Pass: true | Samples: 50 | Entropy: 0.0',
      sampleOffsets: List.generate(50, (i) => i * 2048),
      sampleHashes: {0: '0000000000000000000000000000000000000000000000000000000000000000'},
      evidenceHash: 'a1b2c3d4e5f6',
      limitations: 'Partition wipe: partition table and unselected sectors are not overwritten',
      verifiedPassed: true,
    );

    test('issues certVersion 3 with partial scope and partition list', () {
      final cert = certService.generateCertificate(
        job: job,
        evidence: evidence,
        executionMode: 'real',
        actualMethodExecuted: 'overwrite-zero',
        verificationSampleCount: 50,
        verificationEntropyScore: 0.0,
      );

      expect(cert.certVersion, 3);
      expect(cert.scope, 'partial');
      expect(cert.limitation, contains('Partition wipe'));
      expect(cert.partitionsWiped, isNotNull);
      expect(cert.partitionsWiped!.length, 1);
      expect(cert.partitionsWiped![0]['partition_number'], 1);
      expect(cert.partitionsWiped![0]['start_sector'], 2048);
      expect(cert.partitionsWiped![0]['size_bytes'], 104857600);
      expect(cert.bytesOverwritten, 104857600);
      expect(cert.totalDeviceBytes, 16000000000);

      // Signature verification on untampered cert
      final isValid = certService.verifyCertificateSignature(cert.toJson());
      expect(isValid, isTrue);
    });

    test('tampering with scope invalidates signature', () {
      final cert = certService.generateCertificate(
        job: job,
        evidence: evidence,
        executionMode: 'real',
      );

      final certJson = cert.toJson();
      certJson['scope'] = 'full'; // Tampered

      final isValid = certService.verifyCertificateSignature(certJson);
      expect(isValid, isFalse);
    });

    test('tampering with wiped partition list invalidates signature', () {
      final cert = certService.generateCertificate(
        job: job,
        evidence: evidence,
        executionMode: 'real',
      );

      final certJson = cert.toJson();
      certJson['partitionsWiped'] = [
        {'partition_number': 2, 'start_sector': 4096, 'size_bytes': 200000000}
      ]; // Tampered

      final isValid = certService.verifyCertificateSignature(certJson);
      expect(isValid, isFalse);
    });

    test('tampering with limitation invalidates signature', () {
      final cert = certService.generateCertificate(
        job: job,
        evidence: evidence,
        executionMode: 'real',
      );

      final certJson = cert.toJson();
      certJson['limitation'] = 'Whole disk sanitized'; // Tampered

      final isValid = certService.verifyCertificateSignature(certJson);
      expect(isValid, isFalse);
    });
  });

  group('AssistantContext & AssistantContextBuilder Partition Scope', () {
    test('populates partition scope facts and targeted quick questions', () {
      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());

      final partition = const PartitionInfo(
        partitionNumber: 1,
        name: 'sdb1',
        devicePath: '/dev/sdb1',
        startSector: 2048,
        sizeSectors: 204800,
        sizeBytes: 104857600,
        label: UntrustedText('USB_STICK'),
      );

      final device = DeviceProfile(
        id: 'real_sdb',
        name: 'Kingston DataTraveler',
        serialNumber: 'KNG123',
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        capacityBytes: 16000000000,
        isRemovable: true,
        partitions: [partition],
      );

      controller.selectDevice(device);
      controller.selectPartition(partition);

      final context = AssistantContextBuilder.fromController(controller);

      expect(context.isPartitionScope, isTrue);
      expect(context.partitionNumber, 1);
      expect(context.partitionLabel?.rawValue, 'USB_STICK');
      expect(context.targetSummary, contains('Partition 1: "USB_STICK"'));

      expect(context.quickQuestions, contains('What are the limitations of a partition wipe?'));
      expect(context.quickQuestions, contains('Are unselected partitions overwritten?'));
    });
  });

  group('RealSanitizationService Engine Argument Contract', () {
    final service = RealSanitizationService(
      paths: AppPaths(
        baseDir: Directory.systemTemp,
        checkpointDir: Directory.systemTemp,
      ),
    );

    const partition = PartitionInfo(
      partitionNumber: 1,
      name: 'sdb1',
      devicePath: '/dev/sdb1',
      startSector: 2048,
      sizeSectors: 204800,
      sizeBytes: 104857600,
      label: UntrustedText('DATA'),
    );

    final deviceWithTable = DeviceProfile(
      id: 'real_sdb',
      name: 'USB Drive',
      serialNumber: 'USB777',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
      partitions: const [partition],
    );

    final expectedFingerprint =
        PartitionTableService.computeFingerprint([partition]);

    test('passes the partition-table fingerprint to a whole-disk run', () {
      final args = service.buildSanitizeArgs(
        device: deviceWithTable,
        method: SanitizationMethod.singlePassOverwrite,
        confirmationToken: 'TOKEN',
        deviceSerial: 'USB777',
      );

      expect(args, isNot(contains('--mode')));
      expect(args, contains('--expected-table-fingerprint'));
      expect(args[args.indexOf('--expected-table-fingerprint') + 1],
          expectedFingerprint);
    });

    test('passes the partition-table fingerprint and mode to a partition run', () {
      final args = service.buildSanitizeArgs(
        device: deviceWithTable,
        method: SanitizationMethod.singlePassOverwrite,
        confirmationToken: 'TOKEN',
        deviceSerial: 'USB777',
        targetPartition: partition,
      );

      expect(args[args.indexOf('--mode') + 1], 'partition');
      expect(args[args.indexOf('--expected-part-num') + 1], '1');
      expect(args[args.indexOf('--expected-start-sector') + 1], '2048');
      expect(args[args.indexOf('--expected-size-sectors') + 1], '204800');
      expect(args[args.indexOf('--expected-table-fingerprint') + 1],
          expectedFingerprint);
    });

    test('omits the fingerprint when the device has no partition table', () {
      final bare = DeviceProfile(
        id: 'real_sdc',
        name: 'Bare Disk',
        serialNumber: 'BARE1',
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        capacityBytes: 8000000000,
        isRemovable: true,
      );

      final args = service.buildSanitizeArgs(
        device: bare,
        method: SanitizationMethod.singlePassOverwrite,
        confirmationToken: 'TOKEN',
        deviceSerial: 'BARE1',
      );

      expect(args, isNot(contains('--expected-table-fingerprint')));
    });
  });
}
