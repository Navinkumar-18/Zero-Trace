//! Phase F receipt hardening — Dart regression tests.
//!
//! A fake `zt_engine` (POSIX shell script) is spawned through the
//! `RealSanitizationService.binaryPathOverride` test seam so the whole
//! post-wipe pipeline runs end-to-end:
//!  * a fake engine that IGNORES `ZT_VERIFIED_WIPE_RECEIPT` must not earn
//!    the format prompt — a warning is logged and the reason is surfaced;
//!  * a receipt-WRITING fake engine leaves a file that exists and matches
//!    the target (path, serial, scope, fingerprint), earning the prompt;
//!  * exit 4 (verification passed, receipt unsaved) keeps the verification
//!    verdict intact while withholding the prompt with the engine's reason.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/simple/confirm_wipe_dialog.dart';
import 'package:zero_trace/services/real_sanitization_service.dart';
import 'package:zero_trace/services/sanitization_controller.dart';

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

/// Receipt JSON a receipt-writing fake engine would leave behind — binds to
/// the whole-disk fake target on every axis the controller validates.
String matchingReceiptJson({
  String? canonicalPath,
  String serial = _serial,
  String scope = 'full',
  int? partitionNumber,
  Object? fingerprint = _fingerprint,
  int? verifiedAtEpochSecs,
}) => jsonEncode({
  'canonical_path': canonicalPath ?? _devicePath,
  'device_serial': serial,
  'rdev': 0,
  'ino': 0,
  'scope': scope,
  'parent_name': scope == 'partial' ? 'sdb' : null,
  'partition_number': partitionNumber,
  'partition_table_fingerprint': fingerprint,
  'verified_at_epoch_secs':
      verifiedAtEpochSecs ??
      (DateTime.now().millisecondsSinceEpoch ~/ 1000),
});

/// Writes an executable fake `zt_engine` handling sanitize/verify/format.
///
/// [writeReceipt] honors `ZT_VERIFIED_WIPE_RECEIPT` by writing
/// [receiptJson]; when false the script deliberately ignores the env var
/// (the regression scenario). [verifyExit] exits with that code after
/// printing `VERIFY_REPORT:`, optionally emitting [verifyStderr].
File writeFakeEngine({
  required Directory dir,
  required String name,
  bool writeReceipt = false,
  String receiptJson = '',
  int verifyExit = 0,
  String verifyStderr = '',
}) {
  final receiptCmd = writeReceipt
      ? '''  if [ -n "\$ZT_VERIFIED_WIPE_RECEIPT" ]; then
    mkdir -p "\$(dirname "\$ZT_VERIFIED_WIPE_RECEIPT")"
    printf '%s' '$receiptJson' > "\$ZT_VERIFIED_WIPE_RECEIPT"
    chmod 600 "\$ZT_VERIFIED_WIPE_RECEIPT"
  fi
'''
      : '';
  final stderrCmd = verifyStderr.isEmpty
      ? ''
      : "  printf '%s\\n' '$verifyStderr' >&2\n";
  final script = '''#!/bin/sh
# Fake zt_engine for the Phase F receipt regression tests.
case "\$1" in
  sanitize)
    echo 'REPORT:{"success":true,"method_used":"overwrite-zero","command_log":["fake sanitize"],"stdout":"","stderr":"","exit_code":0,"duration_ms":1,"dry_run":false}'
    exit 0
    ;;
  verify)
$receiptCmd
    echo 'VERIFY_REPORT:{"pass":true,"sample_count":50,"samples":[],"entropy_score":1.0,"fingerprint_hash":"FAKE_FP","rng_seed":1}'
$stderrCmd    exit $verifyExit
    ;;
  format)
    echo 'FORMAT_REPORT:{"success":true,"tool":"mkfs.fake","fs_type":"vfat","label":"ZT_FAKE","time":"2026-01-01T00:00:00Z","sanitization_verified_before_format":true,"scope":"full","partition_table_created":false,"command_log":["mkfs.fake"],"stdout":"","stderr":"","exit_code":0,"duration_ms":1,"dry_run":false}'
    exit 0
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

  setUp(() {
    dir = Directory.systemTemp.createTempSync('zt_receipt_dart_');
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
    DeviceProfile device,
  ) async {
    await controller.startSimpleWipe(
      device,
      DisposalIntent.reuseMyself,
      authorization: WipeAuthorization.forTesting(
        deviceSerial: device.serialNumber,
        overrideMethod: SanitizationMethod.singlePassOverwrite,
      ),
      overrideMethod: SanitizationMethod.singlePassOverwrite,
    );
    return controller.currentJob!;
  }

  group(
    'fake engine ignoring the receipt env',
    () {
      test(
        'no prompt is offered, the reason is surfaced and a warning is logged',
        () async {
          final engine = writeFakeEngine(
            dir: dir,
            name: 'zt_engine_ignore_receipt',
            writeReceipt: false,
          );
          RealSanitizationService.binaryPathOverride = engine.path;

          final controller = makeController();
          final device = fakeDevice();
          final job = await runFakeWipe(controller, device);

          // The wipe itself still succeeded: verification passed from the
          // engine's report — only the format promise is withheld.
          expect(job.status, JobStatus.completed);
          expect(controller.completedCertificate?.evidence.verifiedPassed, isTrue);

          expect(controller.canRecreateFilesystem, isFalse);
          expect(controller.showFilesystemRecreationPrompt, isFalse);
          expect(
            controller.filesystemRecreationUnavailableReason,
            allOf(contains('Filesystem recreation unavailable'), contains('receipt')),
            reason: 'the UI must say why the format prompt is missing',
          );

          final logs = job.logs.join('\n');
          expect(logs, contains('WARNING'));
          expect(logs, contains('receipt'));

          final receipt = paths.verifiedWipeReceiptFile(job.jobId);
          expect(
            receipt.existsSync(),
            isFalse,
            reason: 'the fake engine never wrote a receipt',
          );
        },
        skip: Platform.isLinux
            ? false
            : 'the real-mode pipeline is Linux-only',
      );
    },
  );

  group(
    'receipt-writing fake engine',
    () {
      test(
        'the receipt exists, matches the target and earns the prompt',
        () async {
          final engine = writeFakeEngine(
            dir: dir,
            name: 'zt_engine_write_receipt',
            writeReceipt: true,
            receiptJson: matchingReceiptJson(),
          );
          RealSanitizationService.binaryPathOverride = engine.path;

          final controller = makeController();
          final device = fakeDevice();
          final job = await runFakeWipe(controller, device);

          expect(job.status, JobStatus.completed);
          expect(controller.completedCertificate?.evidence.verifiedPassed, isTrue);

          final receipt = paths.verifiedWipeReceiptFile(job.jobId);
          expect(receipt.existsSync(), isTrue);

          final stamp = jsonDecode(receipt.readAsStringSync())
              as Map<String, dynamic>;
          expect(stamp['canonical_path'], _devicePath);
          expect(stamp['device_serial'], _serial);
          expect(stamp['scope'], 'full');
          expect(stamp['partition_number'], isNull);
          // Both sides carry the fingerprint and they agree (the app checks
          // this pair before offering the format step).
          expect(stamp['partition_table_fingerprint'], _fingerprint);

          // Receipt file privacy: 0600 (0x180) permission bits.
          expect(receipt.statSync().mode & 0x1FF, 0x180);

          expect(controller.canRecreateFilesystem, isTrue);
          expect(controller.showFilesystemRecreationPrompt, isTrue);
          expect(controller.filesystemRecreationUnavailableReason, isNull);
        },
        skip: Platform.isLinux
            ? false
            : 'the real-mode pipeline is Linux-only',
      );
    },
  );

  group('engine exit 4 (receipt unsaved after passing verify)', () {
    test(
      'verification verdict survives, prompt withheld with the engine reason',
      () async {
        const engineReason =
            'Verified-wipe receipt failed: cannot create receipt temp file '
            '/nonexistent/state/receipt.json: No such file or directory';
        final engine = writeFakeEngine(
          dir: dir,
          name: 'zt_engine_exit4',
          writeReceipt: false,
          verifyExit: 4,
          verifyStderr: engineReason,
        );
        RealSanitizationService.binaryPathOverride = engine.path;

        final controller = makeController();
        final device = fakeDevice();
        final job = await runFakeWipe(controller, device);

        // The verification itself passed — exit 4 must NOT fail the job,
        // the certificate or the evidence.
        expect(job.status, JobStatus.completed);
        expect(controller.completedCertificate?.evidence.verifiedPassed, isTrue);

        // …but the format step can never be offered.
        expect(controller.canRecreateFilesystem, isFalse);
        expect(controller.showFilesystemRecreationPrompt, isFalse);
        expect(
          controller.filesystemRecreationUnavailableReason,
          contains('Verified-wipe receipt failed'),
        );
        expect(job.logs.join('\n'), contains('WARNING'));

        final receipt = paths.verifiedWipeReceiptFile(job.jobId);
        expect(receipt.existsSync(), isFalse);
      },
      skip: Platform.isLinux ? false : 'the real-mode pipeline is Linux-only',
    );

    test(
      'executeVerification still parses VERIFY_REPORT on exit 4',
      () async {
        final engine = writeFakeEngine(
          dir: dir,
          name: 'zt_engine_exit4_service',
          writeReceipt: false,
          verifyExit: 4,
          verifyStderr: 'Verified-wipe receipt failed: typed reason',
        );
        RealSanitizationService.binaryPathOverride = engine.path;

        final service = RealSanitizationService(paths: paths);
        final report = await service.executeVerification(
          device: fakeDevice(),
          method: 'overwrite-zero',
          deviceSerial: _serial,
          verifiedReceiptPath: '${dir.path}/receipt.json',
        );

        expect(report.pass, isTrue, reason: 'report rides out on exit 4');
        expect(report.exitCode, 4);
        expect(report.stderr, contains('Verified-wipe receipt failed'));
        expect(report.sampleCount, 50);
      },
    );

    test('a non-reportable exit stays a verification failure', () async {
      final engine = writeFakeEngine(
        dir: dir,
        name: 'zt_engine_exit3_service',
        writeReceipt: false,
        verifyExit: 3,
        verifyStderr: 'Error executing verify: boom',
      );
      RealSanitizationService.binaryPathOverride = engine.path;

      final service = RealSanitizationService(paths: paths);
      final report = await service.executeVerification(
        device: fakeDevice(),
        method: 'overwrite-zero',
        deviceSerial: _serial,
        verifiedReceiptPath: '${dir.path}/receipt.json',
      );

      expect(report.pass, isFalse);
      expect(report.fingerprintHash, 'ERROR_VERIFICATION_FAILED');
      expect(report.exitCode, 3);
    });
  });

  group('receipt validation rules (static validator)', () {
    File seedReceipt(String json, {String name = 'receipt.json'}) {
      final file = File('${dir.path}/$name')..writeAsStringSync(json);
      return file;
    }

    test('accepts a receipt that matches on every axis', () {
      expect(
        SanitizationController.validateVerifiedWipeReceipt(
          targetPath: _devicePath,
          receiptFile: seedReceipt(matchingReceiptJson()),
          deviceSerial: _serial,
          isPartitionScope: false,
          expectedFingerprint: _fingerprint,
        ),
        isNull,
      );
    });

    test('fingerprint mismatch (both non-null) is refused', () {
      final reason = SanitizationController.validateVerifiedWipeReceipt(
        targetPath: _devicePath,
        receiptFile: seedReceipt(matchingReceiptJson(fingerprint: 'OTHER-TABLE')),
        deviceSerial: _serial,
        isPartitionScope: false,
        expectedFingerprint: _fingerprint,
      );
      expect(reason, contains('partition table'));
    });

    test('whole-disk receipt without a fingerprint never mismatches', () {
      // Engine-minted whole-disk receipts carry a null fingerprint: the app
      // must not reject them even when the device itself has one…
      expect(
        SanitizationController.validateVerifiedWipeReceipt(
          targetPath: _devicePath,
          receiptFile: seedReceipt(
            matchingReceiptJson(fingerprint: null),
            name: 'receipt_a.json',
          ),
          deviceSerial: _serial,
          isPartitionScope: false,
          expectedFingerprint: _fingerprint,
        ),
        isNull,
      );
      // …and equally not when the device has none (empty fingerprint).
      expect(
        SanitizationController.validateVerifiedWipeReceipt(
          targetPath: _devicePath,
          receiptFile: seedReceipt(
            matchingReceiptJson(fingerprint: null),
            name: 'receipt_b.json',
          ),
          deviceSerial: _serial,
          isPartitionScope: false,
          expectedFingerprint: '',
        ),
        isNull,
      );
    });

    test('wrong device serial is refused', () {
      final reason = SanitizationController.validateVerifiedWipeReceipt(
        targetPath: _devicePath,
        receiptFile: seedReceipt(matchingReceiptJson(serial: 'OTHER-SERIAL')),
        deviceSerial: _serial,
        isPartitionScope: false,
        expectedFingerprint: _fingerprint,
      );
      expect(reason, contains('serial'));
    });

    test('wrong partition is refused', () {
      final reason = SanitizationController.validateVerifiedWipeReceipt(
        targetPath: '/dev/sdb1',
        receiptFile: seedReceipt(
          matchingReceiptJson(
            canonicalPath: '/dev/sdb1',
            scope: 'partial',
            partitionNumber: 1,
          ),
        ),
        deviceSerial: _serial,
        isPartitionScope: true,
        partitionNumber: 2, // the job wiped #2, the receipt says #1
        expectedFingerprint: _fingerprint,
      );
      expect(reason, contains('different partition'));
    });

    test('a partition receipt is refused for a whole-device target', () {
      final reason = SanitizationController.validateVerifiedWipeReceipt(
        targetPath: _devicePath,
        receiptFile: seedReceipt(
          matchingReceiptJson(scope: 'partial', partitionNumber: 1),
        ),
        deviceSerial: _serial,
        isPartitionScope: false,
        expectedFingerprint: _fingerprint,
      );
      expect(reason, contains('not this whole device'));
    });

    test('symlinked target matches the canonical receipt path', () {
      final real = File('${dir.path}/real_sdb')..writeAsStringSync('x');
      final link = Link('${dir.path}/link_sdb');
      if (link.existsSync()) link.deleteSync();
      link.createSync(real.path);

      // Receipt carries the canonical path — the resolved link matches.
      expect(
        SanitizationController.validateVerifiedWipeReceipt(
          targetPath: link.path,
          receiptFile: seedReceipt(
            matchingReceiptJson(canonicalPath: real.path),
            name: 'receipt_link.json',
          ),
          deviceSerial: _serial,
          isPartitionScope: false,
          expectedFingerprint: _fingerprint,
        ),
        isNull,
      );

      // A receipt naming the raw symlink target itself is NOT canonical and
      // must be refused once the target resolves elsewhere.
      final reason = SanitizationController.validateVerifiedWipeReceipt(
        targetPath: link.path,
        receiptFile: seedReceipt(
          matchingReceiptJson(canonicalPath: link.path),
          name: 'receipt_rawlink.json',
        ),
        deviceSerial: _serial,
        isPartitionScope: false,
        expectedFingerprint: _fingerprint,
      );
      expect(reason, isNotNull);
      expect(reason, contains('not'));
    });

    test('unresolvable target falls back to the raw path comparison', () {
      // /dev node absent (device unplugged): resolution throws, the raw
      // path is compared — an exact match still stands, a mismatch refuses.
      expect(
        SanitizationController.validateVerifiedWipeReceipt(
          targetPath: '/dev/zt-no-such-node',
          receiptFile: seedReceipt(
            matchingReceiptJson(canonicalPath: '/dev/zt-no-such-node'),
            name: 'receipt_raw_ok.json',
          ),
          deviceSerial: _serial,
          isPartitionScope: false,
          expectedFingerprint: _fingerprint,
        ),
        isNull,
      );
      final reason = SanitizationController.validateVerifiedWipeReceipt(
        targetPath: '/dev/zt-no-such-node',
        receiptFile: seedReceipt(
          matchingReceiptJson(canonicalPath: '/dev/other-node'),
          name: 'receipt_raw_bad.json',
        ),
        deviceSerial: _serial,
        isPartitionScope: false,
        expectedFingerprint: _fingerprint,
      );
      expect(reason, contains('not'));
    });

    test('missing receipt file states the reason', () {
      final reason = SanitizationController.validateVerifiedWipeReceipt(
        targetPath: _devicePath,
        receiptFile: File('${dir.path}/does-not-exist.json'),
        deviceSerial: _serial,
        isPartitionScope: false,
        expectedFingerprint: _fingerprint,
      );
      expect(reason, contains('not written by the engine'));
    });

    test('unparseable receipt states the reason', () {
      final reason = SanitizationController.validateVerifiedWipeReceipt(
        targetPath: _devicePath,
        receiptFile: seedReceipt('this is not json'),
        deviceSerial: _serial,
        isPartitionScope: false,
        expectedFingerprint: _fingerprint,
      );
      expect(reason, contains('not valid JSON'));
    });
  });
}
