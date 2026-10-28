//! Phase G — automatic restore of the pre-wipe "After wiping" choice.
//!
//! A fake `zt_engine` (POSIX shell script) is spawned through the
//! `RealSanitizationService.binaryPathOverride` seam so the post-wipe pipeline
//! runs end-to-end. It records the exact `format` argv in a marker file, which
//! lets each test assert *whether* a format ran and with which fs/label/serial.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/audit_log_service.dart';
import 'package:zero_trace/services/real_sanitization_service.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/confirm_wipe_dialog.dart';

const _serial = 'FAKE-SERIAL-001';
const _devicePath = '/dev/sdb';
const _fingerprint = 'MATCHED-FP';

DeviceProfile fakeDevice({String? fingerprint}) => DeviceProfile(
  id: 'real_sdb',
  name: 'Fake Test Disk',
  serialNumber: _serial,
  mediaType: MediaType.usbFlash,
  busType: 'USB',
  capacityBytes: 16 * 1024 * 1024 * 1024,
  partitionTableFingerprint: fingerprint ?? _fingerprint,
);

/// Receipt JSON binding to the whole-disk fake target.
String matchingReceiptJson() => jsonEncode({
  'canonical_path': _devicePath,
  'device_serial': _serial,
  'rdev': 0,
  'ino': 0,
  'scope': 'full',
  'parent_name': null,
  'partition_number': null,
  'partition_table_fingerprint': _fingerprint,
  'verified_at_epoch_secs': DateTime.now().millisecondsSinceEpoch ~/ 1000,
});

/// Fake engine that records every `format` invocation in [markerPath].
///
/// When [writeReceipt] is false the verify branch deliberately ignores
/// `ZT_VERIFIED_WIPE_RECEIPT` (missing-receipt scenario). [verifyPass] controls
/// the verification verdict; [formatSucceeds] lets the engine refuse a format
/// (expired or rejected receipt) without the app ever bypassing it.
File writeFakeEngine({
  required Directory dir,
  required String name,
  required String markerPath,
  bool writeReceipt = true,
  String receiptJson = '',
  bool verifyPass = true,
  bool formatSucceeds = true,
}) {
  final receiptCmd = writeReceipt
      ? '''  if [ -n "\$ZT_VERIFIED_WIPE_RECEIPT" ]; then
    mkdir -p "\$(dirname "\$ZT_VERIFIED_WIPE_RECEIPT")"
    printf '%s' '$receiptJson' > "\$ZT_VERIFIED_WIPE_RECEIPT"
    chmod 600 "\$ZT_VERIFIED_WIPE_RECEIPT"
  fi
'''
      : '';
  final script = '''#!/bin/sh
case "\$1" in
  sanitize)
    echo 'REPORT:{"success":true,"method_used":"overwrite-zero","command_log":["fake sanitize"],"stdout":"","stderr":"","exit_code":0,"duration_ms":1,"dry_run":false}'
    exit 0
    ;;
  verify)
$receiptCmd
    echo 'VERIFY_REPORT:{"pass":$verifyPass,"sample_count":50,"samples":[],"entropy_score":1.0,"fingerprint_hash":"FAKE_FP","rng_seed":1}'
    exit 0
    ;;
  format)
    printf '%s\\n' "\$@" > '$markerPath'
    printf 'FORMAT_REPORT:{"success":$formatSucceeds,"tool":"mkfs.%s","fs_type":"%s","label":"%s","time":"2026-01-01T00:00:00Z","sanitization_verified_before_format":true,"scope":"full","partition_table_created":true,"partition_table_type":"gpt","command_log":["mkfs.%s"],"stdout":"","stderr":"engine refused receipt","exit_code":2,"duration_ms":1,"dry_run":false}\\n' "\$3" "\$3" "\$4" "\$3"
    if [ "$formatSucceeds" = "true" ]; then exit 0; else exit 2; fi
    ;;
  *)
    exit 1
    ;;
esac
''';
  final file = File('${dir.path}/$name')..writeAsStringSync(script);
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
    dir = Directory.systemTemp.createTempSync('zt_auto_restore_');
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

  SanitizationController makeController() {
    final controller = SanitizationController(
      appPaths: paths,
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(controller.dispose);
    return controller;
  }

  Future<SanitizationJob> runFakeWipe(
    SanitizationController controller,
    DeviceProfile device, {
    required bool restoreFilesystem,
    String? restoreFsType,
    String? restoreLabel,
  }) async {
    await controller.startSimpleWipe(
      device,
      DisposalIntent.reuseMyself,
      authorization: WipeAuthorization.forTesting(
        deviceSerial: device.serialNumber,
        // Deliberately not the full serial: the dialog confirms last-4 only.
        typedConfirmation: '1494',
        overrideMethod: SanitizationMethod.singlePassOverwrite,
        restoreFilesystem: restoreFilesystem,
        restoreFsType: restoreFsType,
        restoreLabel: restoreLabel,
      ),
      overrideMethod: SanitizationMethod.singlePassOverwrite,
    );
    return controller.currentJob!;
  }

  List<String> formatArgs() {
    final file = File(markerPath);
    if (!file.existsSync()) return const [];
    return file.readAsLinesSync();
  }

  test(
    'Restore chosen: the format runs after verification with the captured '
    'fs/label and the serial already confirmed in the dialog',
    () async {
      final engine = writeFakeEngine(
        dir: dir,
        name: 'zt_engine_restore',
        markerPath: markerPath,
        receiptJson: matchingReceiptJson(),
      );
      RealSanitizationService.binaryPathOverride = engine.path;

      final controller = makeController();
      final device = fakeDevice();
      final job = await runFakeWipe(
        controller,
        device,
        restoreFilesystem: true,
        restoreFsType: 'exfat',
        restoreLabel: 'BACKUP',
      );

      // The wipe itself is untouched: completed and verified.
      expect(job.status, JobStatus.completed);
      expect(controller.completedCertificate?.evidence.verifiedPassed, isTrue);

      // Requirement (d): no second serial prompt — the format ran with the
      // full serial the dialog already pinned, not the typed last-4 token.
      expect(formatArgs(), isNotEmpty);
      expect(formatArgs()[0], 'format');
      expect(formatArgs()[1], _devicePath);
      expect(formatArgs()[2], 'exfat');
      expect(formatArgs()[3], 'BACKUP');
      expect(formatArgs()[4], _serial);
      expect(formatArgs()[5], _serial);
      expect(formatArgs(), contains('--verified-receipt'));

      // The captured fs/label are the recorded ones.
      final record = controller.filesystemRecreation;
      expect(record, isNotNull);
      expect(record!.fsType, 'exfat');
      expect(record.label, 'BACKUP');

      // One-shot receipt adoption: no prompt and no receipt left behind.
      expect(controller.canRecreateFilesystem, isFalse);
      expect(controller.showFilesystemRecreationPrompt, isFalse);
      expect(controller.driveLeftBlank, isFalse);
      expect(
        paths.verifiedWipeReceiptFile(job.jobId).existsSync(),
        isFalse,
      );

      // The certificate carries the separate format record.
      expect(
        controller.completedCertificate?.filesystemRecreation?.fsType,
        'exfat',
      );

      // The format step is a separate audit entry.
      final entries = await AuditLogService(paths: paths).getEntries();
      final formatEntries =
          entries.where((e) => e.methodClass == 'format').toList();
      expect(formatEntries, hasLength(1));
      expect(formatEntries.single.filesystemRecreation?.label, 'BACKUP');
    },
    skip: Platform.isLinux ? false : 'the real-mode pipeline is Linux-only',
  );

  test(
    'Leave blank: no format runs and the drive is reported as blank',
    () async {
      final engine = writeFakeEngine(
        dir: dir,
        name: 'zt_engine_leave_blank',
        markerPath: markerPath,
        receiptJson: matchingReceiptJson(),
      );
      RealSanitizationService.binaryPathOverride = engine.path;

      final controller = makeController();
      final job = await runFakeWipe(
        controller,
        fakeDevice(),
        restoreFilesystem: false,
      );

      expect(job.status, JobStatus.completed);
      expect(controller.completedCertificate?.evidence.verifiedPassed, isTrue);

      // No format was requested.
      expect(formatArgs(), isEmpty);
      expect(controller.filesystemRecreation, isNull);
      expect(controller.autoRestoreFailed, isFalse);
      expect(controller.driveLeftBlank, isTrue);
      expect(
        controller.completedCertificate?.filesystemRecreation,
        isNull,
      );

      final entries = await AuditLogService(paths: paths).getEntries();
      expect(entries.where((e) => e.methodClass == 'format'), isEmpty);
    },
    skip: Platform.isLinux ? false : 'the real-mode pipeline is Linux-only',
  );

  test(
    'verification failed: "Restore" never formats',
    () async {
      final engine = writeFakeEngine(
        dir: dir,
        name: 'zt_engine_verify_failed',
        markerPath: markerPath,
        receiptJson: matchingReceiptJson(),
        verifyPass: false,
      );
      RealSanitizationService.binaryPathOverride = engine.path;

      final controller = makeController();
      final job = await runFakeWipe(
        controller,
        fakeDevice(),
        restoreFilesystem: true,
        restoreFsType: 'vfat',
        restoreLabel: 'DATA',
      );

      expect(job.status, JobStatus.failed);
      expect(controller.completedCertificate?.evidence.verifiedPassed, isFalse);
      expect(formatArgs(), isEmpty);
      expect(controller.filesystemRecreation, isNull);
      expect(controller.canRecreateFilesystem, isFalse);
      // A failed wipe is not a "completed but blank" drive.
      expect(controller.driveLeftBlank, isFalse);

      final entries = await AuditLogService(paths: paths).getEntries();
      expect(entries.where((e) => e.methodClass == 'format'), isEmpty);
    },
    skip: Platform.isLinux ? false : 'the real-mode pipeline is Linux-only',
  );

  test(
    'missing receipt: "Restore" is withheld and reported, never formatted',
    () async {
      final engine = writeFakeEngine(
        dir: dir,
        name: 'zt_engine_no_receipt',
        markerPath: markerPath,
        writeReceipt: false,
      );
      RealSanitizationService.binaryPathOverride = engine.path;

      final controller = makeController();
      final job = await runFakeWipe(
        controller,
        fakeDevice(),
        restoreFilesystem: true,
        restoreFsType: 'vfat',
        restoreLabel: 'DATA',
      );

      expect(job.status, JobStatus.completed);
      expect(controller.completedCertificate?.evidence.verifiedPassed, isTrue);
      expect(controller.canRecreateFilesystem, isFalse);
      expect(formatArgs(), isEmpty);
      expect(controller.filesystemRecreation, isNull);
      expect(controller.autoRestoreFailed, isTrue);
      expect(controller.driveLeftBlank, isTrue);
      expect(
        controller.filesystemRecreationError,
        allOf(contains('receipt')),
        reason: 'the UI must surface why the restore was skipped',
      );

      final entries = await AuditLogService(paths: paths).getEntries();
      expect(entries.where((e) => e.methodClass == 'format'), isEmpty);
    },
    skip: Platform.isLinux ? false : 'the real-mode pipeline is Linux-only',
  );

  test(
    'engine refuses the receipt (expired): no format is recorded and the '
    'drive stays blank',
    () async {
      final engine = writeFakeEngine(
        dir: dir,
        name: 'zt_engine_refused_format',
        markerPath: markerPath,
        receiptJson: matchingReceiptJson(),
        formatSucceeds: false,
      );
      RealSanitizationService.binaryPathOverride = engine.path;

      final controller = makeController();
      final job = await runFakeWipe(
        controller,
        fakeDevice(),
        restoreFilesystem: true,
        restoreFsType: 'vfat',
        restoreLabel: 'DATA',
      );

      expect(job.status, JobStatus.completed);
      // The engine was asked, and it refused: Dart never fabricates success.
      expect(formatArgs(), isNotEmpty);
      expect(controller.filesystemRecreation, isNull);
      expect(controller.autoRestoreFailed, isTrue);
      expect(controller.driveLeftBlank, isTrue);
      expect(
        controller.completedCertificate?.filesystemRecreation,
        isNull,
      );

      final entries = await AuditLogService(paths: paths).getEntries();
      expect(entries.where((e) => e.methodClass == 'format'), isEmpty);
    },
    skip: Platform.isLinux ? false : 'the real-mode pipeline is Linux-only',
  );
}
