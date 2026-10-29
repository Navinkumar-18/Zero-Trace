//! Phase G — multi-partition automatic restore.
//!
//! A fake `zt_engine` runs the whole pipeline end-to-end. It records every
//! `format` invocation (partition|fs|label|token) and can skip writing a
//! specific partition's receipt or refuse a specific partition's format.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/filesystem_recreation.dart';
import 'package:zero_trace/models/partition_info.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/models/untrusted_text.dart';
import 'package:zero_trace/services/audit_log_service.dart';
import 'package:zero_trace/services/real_sanitization_service.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/confirm_wipe_dialog.dart';

const _serial = 'FAKE-SERIAL-003';
const _fingerprint = 'TABLE-FP';

PartitionInfo part(int n, String fs, String label) => PartitionInfo(
  partitionNumber: n,
  name: 'sdb$n',
  devicePath: '/dev/sdb$n',
  startSector: 2048 * n,
  sizeSectors: 204800,
  sizeBytes: 104857600,
  label: UntrustedText(label),
  fsType: fs,
);

final partitions = [
  part(1, 'ext4', 'DATA'),
  part(2, 'vfat', 'PHOTOS'),
  part(3, 'exfat', 'ARCHIVE'),
];

DeviceProfile fakeDevice() => DeviceProfile(
  id: 'real_sdb',
  name: 'Fake Multi Partition SSD',
  serialNumber: _serial,
  mediaType: MediaType.sataSsd,
  busType: 'SATA',
  capacityBytes: 512 * 1024 * 1024 * 1024,
  isRemovable: false,
  partitions: partitions,
  partitionTableFingerprint: _fingerprint,
);

/// Writes an executable fake `zt_engine`.
///
/// [skipReceiptForPartition] makes the verify branch ignore the receipt env
/// var for that partition number (missing-receipt scenario).
/// [failFormatFor] makes the format branch refuse that partition path
/// (engine-rejected receipt scenario).
File writeFakeEngine({
  required Directory dir,
  required String markerPath,
  int? skipReceiptForPartition,
  String? failFormatFor,
}) {
  final skip = skipReceiptForPartition ?? -1;
  final failDev = failFormatFor ?? '';
  final script = '''#!/bin/sh
case "\$1" in
  sanitize)
    echo 'REPORT:{"success":true,"method_used":"overwrite-zero","command_log":["fake sanitize"],"stdout":"","stderr":"","exit_code":0,"duration_ms":1,"dry_run":false}'
    exit 0
    ;;
  verify)
    dev="\$2"
    p=0
    case "\$dev" in
      /dev/sdb1) p=1 ;;
      /dev/sdb2) p=2 ;;
      /dev/sdb3) p=3 ;;
    esac
    if [ "\$p" != "$skip" ]; then
      if [ -n "\$ZT_VERIFIED_WIPE_RECEIPT" ]; then
        mkdir -p "\$(dirname "\$ZT_VERIFIED_WIPE_RECEIPT")"
        printf '{"canonical_path":"%s","device_serial":"%s","rdev":0,"ino":0,"scope":"partial","parent_name":"sdb","partition_number":%s,"partition_table_fingerprint":"%s","verified_at_epoch_secs":1893456000}' "\$dev" "$_serial" "\$p" "$_fingerprint" > "\$ZT_VERIFIED_WIPE_RECEIPT"
        chmod 600 "\$ZT_VERIFIED_WIPE_RECEIPT"
      fi
    fi
    echo 'VERIFY_REPORT:{"pass":true,"sample_count":50,"samples":[],"entropy_score":1.0,"fingerprint_hash":"FAKE_FP","rng_seed":1}'
    exit 0
    ;;
  format)
    printf '%s|%s|%s|%s\\n' "\$2" "\$3" "\$4" "\$5" >> '$markerPath'
    success=true
    code=0
    if [ "\$2" = "$failDev" ]; then success=false; code=2; fi
    printf 'FORMAT_REPORT:{"success":%s,"tool":"mkfs.%s","fs_type":"%s","label":"%s","time":"2026-01-01T00:00:00Z","sanitization_verified_before_format":true,"scope":"partial","partition_table_created":false,"command_log":["mkfs.%s"],"stdout":"","stderr":"engine refused receipt","exit_code":%s,"duration_ms":1,"dry_run":false}\\n' "\$success" "\$3" "\$3" "\$4" "\$3" "\$code"
    exit \$code
    ;;
  *)
    exit 1
    ;;
esac
''';
  final file = File('${dir.path}/zt_engine')..writeAsStringSync(script);
  final chmod = Process.runSync('chmod', ['755', file.path]);
  if (chmod.exitCode != 0) {
    throw StateError('chmod failed for ${file.path}: ${chmod.stderr}');
  }
  return file;
}

void main() {
  late Directory dir;
  late AppPaths paths;
  late String markerPath;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('zt_auto_restore_parts_');
    markerPath = '${dir.path}/format_args.txt';
    paths = AppPaths(
      baseDir: dir,
      checkpointDir: Directory('${dir.path}/checkpoints'),
    );
  });

  tearDown(() {
    RealSanitizationService.binaryPathOverride = null;
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  SanitizationController makeController(DeviceProfile device) {
    final controller = SanitizationController(
      appPaths: paths,
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(controller.dispose);
    controller.setMockDevices([device]);
    for (final p in device.partitions) {
      controller.togglePartitionSelection(p);
    }
    return controller;
  }

  Map<String, FilesystemRestoreSpec> restoreSpecs() => {
    for (final p in partitions)
      p.devicePath: FilesystemRestoreSpec(
        fsType: p.fsType!,
        label: p.label.sanitized,
      ),
  };

  Future<SanitizationJob> runWipe(SanitizationController controller) async {
    final device = fakeDevice();
    await controller.startSimpleWipe(
      device,
      DisposalIntent.reuseMyself,
      authorization: WipeAuthorization.forTesting(
        deviceSerial: device.serialNumber,
        typedConfirmation: '3456',
        overrideMethod: SanitizationMethod.singlePassOverwrite,
        restoreFilesystem: true,
        restoreFsType: 'ext4',
        restoreLabel: 'DATA',
        partitionRestoreSpecs: restoreSpecs(),
      ),
      overrideMethod: SanitizationMethod.singlePassOverwrite,
    );
    return controller.currentJob!;
  }

  List<String> formatLines() {
    final file = File(markerPath);
    if (!file.existsSync()) return const [];
    return file.readAsLinesSync();
  }

  test(
    'three partitions are each restored with their own captured fs/label',
    () async {
      final engine = writeFakeEngine(dir: dir, markerPath: markerPath);
      RealSanitizationService.binaryPathOverride = engine.path;

      final controller = makeController(fakeDevice());
      final job = await runWipe(controller);

      expect(job.status, JobStatus.completed);
      expect(job.targetPartitions, hasLength(3));

      // Every partition was formatted exactly once, in wipe order, with its
      // own fs/label — never the first partition's values.
      expect(formatLines(), [
        '/dev/sdb1|ext4|DATA|$_serial',
        '/dev/sdb2|vfat|PHOTOS|$_serial',
        '/dev/sdb3|exfat|ARCHIVE|$_serial',
      ]);

      expect(controller.partitionRestoreOutcomes, hasLength(3));
      expect(controller.partitionRestoreOutcomes.every((o) => o.success), isTrue);
      expect(controller.failedPartitionRestores, isEmpty);
      expect(controller.successfulPartitionRestores, hasLength(3));
      expect(controller.driveLeftBlank, isFalse);

      // One-shot receipts: every partition's proof was consumed.
      for (final p in partitions) {
        expect(
          paths
              .verifiedWipeReceiptFile(
                job.jobId,
                partitionNumber: p.partitionNumber,
              )
              .existsSync(),
          isFalse,
        );
      }

      // A separate audit entry exists per partition's format step.
      final entries = await AuditLogService(paths: paths).getEntries();
      final formatEntries =
          entries.where((e) => e.methodClass == 'format').toList();
      expect(formatEntries, hasLength(3));
      expect(
        formatEntries
            .map((e) => e.filesystemRecreation?.fsType)
            .toSet(),
        {'ext4', 'vfat', 'exfat'},
      );
    },
    skip: Platform.isLinux ? false : 'the real-mode pipeline is Linux-only',
  );

  test(
    'a missing receipt on one partition leaves only that partition blank '
    'and the rest are restored',
    () async {
      final engine = writeFakeEngine(
        dir: dir,
        markerPath: markerPath,
        skipReceiptForPartition: 2,
      );
      RealSanitizationService.binaryPathOverride = engine.path;

      final controller = makeController(fakeDevice());
      final job = await runWipe(controller);

      expect(job.status, JobStatus.completed);

      // Only p1 and p3 had receipts, so only they were formatted.
      expect(formatLines(), [
        '/dev/sdb1|ext4|DATA|$_serial',
        '/dev/sdb3|exfat|ARCHIVE|$_serial',
      ]);

      final failures = controller.failedPartitionRestores;
      expect(failures, hasLength(1));
      expect(failures.single.partition.name, 'sdb2');
      expect(failures.single.error, contains('receipt'));
      expect(controller.successfulPartitionRestores, hasLength(2));
      expect(controller.driveLeftBlank, isTrue);
      expect(controller.canRecreatePartition(partitions[1]), isFalse);

      // p2's receipt was never minted; p1/p3 were consumed.
      expect(
        paths
            .verifiedWipeReceiptFile(job.jobId, partitionNumber: 2)
            .existsSync(),
        isFalse,
      );
      expect(
        paths
            .verifiedWipeReceiptFile(job.jobId, partitionNumber: 1)
            .existsSync(),
        isFalse,
      );

      final entries = await AuditLogService(paths: paths).getEntries();
      expect(
        entries.where((e) => e.methodClass == 'format'),
        hasLength(2),
      );
    },
    skip: Platform.isLinux ? false : 'the real-mode pipeline is Linux-only',
  );

  test(
    'an engine-refused partition keeps its receipt and a retry stays possible',
    () async {
      final engine = writeFakeEngine(
        dir: dir,
        markerPath: markerPath,
        failFormatFor: '/dev/sdb2',
      );
      RealSanitizationService.binaryPathOverride = engine.path;

      final controller = makeController(fakeDevice());
      await runWipe(controller);

      expect(formatLines(), [
        '/dev/sdb1|ext4|DATA|$_serial',
        '/dev/sdb2|vfat|PHOTOS|$_serial',
        '/dev/sdb3|exfat|ARCHIVE|$_serial',
      ]);

      final failures = controller.failedPartitionRestores;
      expect(failures, hasLength(1));
      expect(failures.single.partition.name, 'sdb2');
      expect(controller.driveLeftBlank, isTrue);
      // The refused receipt was not consumed, so the per-partition
      // "Restore now" action remains enabled.
      expect(controller.canRecreatePartition(partitions[1]), isTrue);
    },
    skip: Platform.isLinux ? false : 'the real-mode pipeline is Linux-only',
  );
}
