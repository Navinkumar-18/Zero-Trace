import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/filesystem_recreation.dart';
import 'package:zero_trace/models/partition_info.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/models/untrusted_text.dart';
import 'package:zero_trace/services/audit_log_service.dart';
import 'package:zero_trace/services/certificate_service.dart';
import 'package:zero_trace/services/filesystem_recreation_preference.dart';
import 'package:zero_trace/services/real_sanitization_service.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/filesystem_recreation_dialog.dart';

const _record = FilesystemRecreationRecord(
  tool: 'mkfs.vfat',
  fsType: 'vfat',
  label: 'RESTORED',
  time: '2026-10-25T10:00:00.000',
  sanitizationVerifiedBeforeFormat: true,
  scope: 'partial',
);

const _device = DeviceProfile(
  id: 'real_sdb',
  name: 'Test USB',
  serialNumber: 'TESTSERIAL123',
  mediaType: MediaType.usbFlash,
  busType: 'USB',
  capacityBytes: 32000000000,
  fsType: 'vfat',
  partitions: [
    PartitionInfo(
      partitionNumber: 3,
      name: 'sdb3',
      devicePath: '/dev/sdb3',
      startSector: 8192,
      sizeSectors: 2048,
      sizeBytes: 1048576,
      label: UntrustedText('DATA'),
      fsType: 'vfat',
    ),
  ],
  partitionTableFingerprint: 'abc123',
  partitionTableType: 'gpt',
);

final _evidence = VerificationEvidence(
  statusCode: 0,
  controllerConfirmation: 'ok',
  sampleOffsets: [0, 512],
  sampleHashes: {0: 'aa', 512: 'bb'},
  evidenceHash:
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  limitations: 'sample',
  verifiedPassed: true,
);

SanitizationJob _job() => SanitizationJob(
  jobId: 'JOB-FORMAT-1',
  device: _device,
  dataSensitivity: DataSensitivity.confidential,
  deviceCondition: DeviceCondition.functional,
  disposalPath: DisposalPath.recycling,
  riskScore: 0.2,
  targetCategory: NistCategory.clear,
  recommendedMethod: SanitizationMethod.singlePassOverwrite,
  standardReference: 'NIST SP 800-88 Rev. 1',
  explanationText: 'overwrite',
  targetPartition: _device.partitions.first,
  targetPartitions: _device.partitions,
);

AppPaths _tempPaths(Directory dir) =>
    AppPaths(baseDir: dir, checkpointDir: Directory('${dir.path}/checkpoints'));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Phase F signing payload', () {
    Map<String, dynamic> payload(
      int version, {
      FilesystemRecreationRecord? format,
    }) => CertificateService.buildSigningPayload(
      certVersion: version,
      certificateId: 'ZT-CERT-1',
      jobId: 'JOB-FORMAT-1',
      deviceSerial: 'TESTSERIAL123',
      method: 'singlePassOverwrite',
      evidenceHash: _evidence.evidenceHash,
      result: 'SUCCESS',
      timestamp: '2026-10-25T10:00:00.000',
      sanitizationCategory: 'Clear',
      executionMode: 'real',
      scope: 'partial',
      filesystemRecreation: format,
    );

    test('v4 payload includes the format record only when present', () {
      expect(payload(4).containsKey('filesystemRecreation'), isFalse);
      expect(
        payload(4, format: _record)['filesystemRecreation'],
        _record.toJson(),
      );
    });

    test('v1-v3 payloads stay byte-identical with a format record', () {
      for (final version in [1, 2, 3]) {
        expect(
          jsonEncode(payload(version, format: _record)),
          jsonEncode(payload(version)),
        );
      }
    });
  });

  group('Phase F certificate record', () {
    test('round-trips and verifies with a format record', () {
      final service = CertificateService();
      final cert = service.generateCertificate(
        job: _job(),
        evidence: _evidence,
        executionMode: 'real',
        filesystemRecreation: _record,
      );

      expect(cert.filesystemRecreation, isNotNull);
      final json = cert.toJson();
      expect(json['filesystemRecreation'], _record.toJson());
      expect(service.verifyCertificateSignature(json), isTrue);

      final parsed = SanitizationCertificate.fromJson(json);
      expect(parsed.filesystemRecreation!.tool, 'mkfs.vfat');
      expect(parsed.filesystemRecreation!.fsType, 'vfat');
      expect(
        parsed.filesystemRecreation!.sanitizationVerifiedBeforeFormat,
        isTrue,
      );
    });

    test('wipe-only certificate omits the field and still verifies', () {
      final service = CertificateService();
      final cert = service.generateCertificate(
        job: _job(),
        evidence: _evidence,
        executionMode: 'real',
      );
      final json = cert.toJson();
      expect(json.containsKey('filesystemRecreation'), isFalse);
      expect(service.verifyCertificateSignature(json), isTrue);
    });

    test('attaching a format record re-signs only the added field', () {
      final service = CertificateService();
      final wipeOnly = service.generateCertificate(
        job: _job(),
        evidence: _evidence,
        executionMode: 'real',
      );
      final withFormat = service.withFilesystemRecreation(wipeOnly, _record);

      expect(withFormat.certificateId, wipeOnly.certificateId);
      expect(withFormat.signature, isNot(wipeOnly.signature));
      expect(service.verifyCertificateSignature(withFormat.toJson()), isTrue);
      // The original signed certificate is untouched and still verifies.
      expect(service.verifyCertificateSignature(wipeOnly.toJson()), isTrue);
    });
  });

  group('Phase F audit log', () {
    test(
      'format step is a separate chained entry with its own record',
      () async {
        final dir = await Directory.systemTemp.createTemp('zt_format_audit_');
        addTearDown(() => dir.deleteSync(recursive: true));
        final service = AuditLogService(paths: _tempPaths(dir));

        await service.appendEntry(
          AuditLogEntry(
            timestamp: '2026-10-25T09:59:00.000',
            jobId: 'JOB-FORMAT-1',
            deviceSerial: 'TESTSERIAL123',
            devicePath: '/dev/sdb3',
            deviceName: 'Test USB',
            method: 'overwrite-zero',
            standardReference: 'NIST SP 800-88 Rev. 1',
            nistCategory: 'Clear',
            success: true,
            verificationPassed: true,
            fingerprintHash: 'FINGERPRINT',
            entropyScore: 0.0,
            sampleCount: 50,
            commandLog: const ['wipe'],
          ),
        );

        await service.appendEntry(
          AuditLogEntry(
            timestamp: _record.time,
            jobId: 'JOB-FORMAT-1',
            deviceSerial: 'TESTSERIAL123',
            devicePath: '/dev/sdb3',
            deviceName: 'Test USB',
            scope: 'partial',
            method: 'recreate filesystem (vfat)',
            methodClass: 'format',
            standardReference: 'Post-wipe filesystem recreation',
            nistCategory: 'FORMAT',
            outcome: 'format_completed',
            success: true,
            verificationPassed: true,
            fingerprintHash: 'FORMAT_VERIFIED',
            entropyScore: 1.0,
            sampleCount: 0,
            commandLog: const ['mkfs.vfat ...'],
            filesystemRecreation: _record,
          ),
        );

        final integrity = await service.verifyChainIntegrity();
        expect(integrity.status, ChainIntegrityStatus.valid);

        final entries = await service.getEntries();
        expect(entries.first.filesystemRecreation!.tool, 'mkfs.vfat');
        expect(entries.first.filesystemRecreation!.fsType, 'vfat');
        expect(entries.last.filesystemRecreation, isNull);
      },
    );

    test('canonical bytes are unchanged when no format record is present', () {
      final entry = AuditLogEntry(
        timestamp: '2026-10-25T09:59:00.000',
        jobId: 'JOB-1',
        deviceSerial: 'SERIAL',
        devicePath: '/dev/sdb',
        method: 'overwrite-zero',
        standardReference: 'NIST SP 800-88 Rev. 1',
        nistCategory: 'Clear',
        success: true,
        fingerprintHash: 'HASH',
        entropyScore: 0.0,
        sampleCount: 1,
        commandLog: const [],
      );
      expect(entry.toCanonicalJson().contains('filesystemRecreation'), isFalse);
      expect(
        entry
            .copyWithChain(previousHash: 'a', entryHash: 'b')
            .toCanonicalJson(),
        entry.toCanonicalJson(),
      );
    });
  });

  group('Phase F format arguments', () {
    final service = RealSanitizationService(
      paths: _tempPaths(Directory('/tmp')),
    );

    test('partition scope passes the partition node, guard expectations and '
        'the verified receipt', () {
      final args = service.buildFormatArgs(
        device: _device,
        fsType: 'vfat',
        label: 'RESTORED',
        confirmationToken: 'TESTSERIAL123',
        deviceSerial: 'TESTSERIAL123',
        targetPartition: _device.partitions.first,
        verifiedReceiptPath: '/tmp/receipt.json',
      );

      expect(args.take(6), [
        'format',
        '/dev/sdb3',
        'vfat',
        'RESTORED',
        'TESTSERIAL123',
        'TESTSERIAL123',
      ]);
      expect(args, containsAllInOrder(['--mode', 'partition']));
      expect(args, containsAllInOrder(['--expected-part-num', '3']));
      expect(args, containsAllInOrder(['--expected-start-sector', '8192']));
      expect(args, containsAllInOrder(['--expected-size-sectors', '2048']));
      expect(
        args,
        containsAllInOrder(['--expected-table-fingerprint', 'abc123']),
      );
      expect(
        args,
        containsAllInOrder(['--verified-receipt', '/tmp/receipt.json']),
      );
      expect(args, isNot(contains('--table')));
    });

    test('whole-device scope requires and passes a new table type', () {
      expect(
        () => service.buildFormatArgs(
          device: _device,
          fsType: 'ext4',
          label: 'RESTORED',
          confirmationToken: 'TESTSERIAL123',
          deviceSerial: 'TESTSERIAL123',
          verifiedReceiptPath: '/tmp/receipt.json',
        ),
        throwsArgumentError,
      );

      final args = service.buildFormatArgs(
        device: _device,
        fsType: 'ext4',
        label: 'RESTORED',
        confirmationToken: 'TESTSERIAL123',
        deviceSerial: 'TESTSERIAL123',
        tableType: 'gpt',
        verifiedReceiptPath: '/tmp/receipt.json',
      );
      expect(args.take(2), ['format', '/dev/sdb']);
      expect(args, containsAllInOrder(['--table', 'gpt']));
      expect(args, isNot(contains('--mode')));
      expect(
        args,
        containsAllInOrder(['--verified-receipt', '/tmp/receipt.json']),
      );
    });
  });

  group('Phase F preference + receipt paths', () {
    test('normalizes only supported filesystems', () {
      expect(normalizeFilesystemType('FAT32'), 'vfat');
      expect(normalizeFilesystemType('vfat'), 'vfat');
      expect(normalizeFilesystemType('exfat'), 'exfat');
      expect(normalizeFilesystemType('BitLocker'), 'ntfs');
      expect(normalizeFilesystemType('ext3'), 'ext4');
      expect(normalizeFilesystemType('btrfs'), isNull);
      expect(normalizeFilesystemType(null), isNull);
    });

    test('remembers fs/label but never a default-on action', () async {
      final dir = await Directory.systemTemp.createTemp('zt_format_pref_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final paths = _tempPaths(dir);
      final store = FilesystemRecreationPreferenceStore(paths: paths);

      expect(store.load().fsType, isNull);
      store.save(fsType: 'ext4', label: 'KEEP');
      final loaded = store.load();
      expect(loaded.fsType, 'ext4');
      expect(loaded.label, 'KEEP');
      // The preference carries no enabled flag at all: the action is always
      // opt-in for each run.
      expect(loaded.toJson().containsKey('enabled'), isFalse);
    });

    test('receipt paths are per job and per partition', () {
      final paths = _tempPaths(Directory('/tmp'));
      expect(
        paths.verifiedWipeReceiptFile('JOB-1').path,
        '/tmp/checkpoints/verified_wipe_JOB-1.json',
      );
      expect(
        paths.verifiedWipeReceiptFile('JOB-1', partitionNumber: 3).path,
        '/tmp/checkpoints/verified_wipe_JOB-1_p3.json',
      );
    });
  });

  group('Phase F dialog', () {
    testWidgets('starts OFF, explains the wipe is unaffected and shows a '
        'refusal reason', (tester) async {
      final dir = Directory.systemTemp.createTempSync('zt_format_dialog_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final controller = SanitizationController(
        appPaths: _tempPaths(dir),
        enableAutoPolling: false,
        deferInitialDiscovery: true,
      );
      addTearDown(controller.dispose);

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: FilesystemRecreationDialog(
              controller: controller,
              defaults: const FilesystemRecreationDefaults(
                fsType: 'vfat',
                label: 'RESTORED',
                scope: 'partial',
              ),
            ),
          ),
        ),
      );

      expect(find.text('Recreate filesystem?'), findsOneWidget);
      expect(
        find.textContaining('does not change the sanitization verdict'),
        findsOneWidget,
      );
      final toggle = tester.widget<CheckboxListTile>(
        find.byKey(const Key('filesystem-recreate-toggle')),
      );
      expect(toggle.value, isFalse);

      await tester.tap(find.byKey(const Key('filesystem-recreate-toggle')));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 50));
      await tester.tap(find.byKey(const Key('filesystem-recreate-confirm')));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 50));

      expect(
        find.byKey(const Key('filesystem-recreate-error')),
        findsOneWidget,
      );
      expect(find.textContaining('Format failed:'), findsOneWidget);
    });
  });
}
