import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/job_state_file.dart';
import 'package:zero_trace/services/orphaned_process_checker.dart';
import 'package:zero_trace/services/sanitization_controller.dart';

import '../support/real_state_guard.dart';

/// Guard that fails if a test writes under the real app state directories.
///
/// The deliberately-violating fixture points the guard at a temp directory that
/// stands in for the real one, proving the guard can fail. No test here ever
/// writes the real `~/.zero_trace`.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('RealStateGuard detection', () {
    late Directory pretendReal;

    setUp(() {
      pretendReal = Directory.systemTemp.createTempSync('zt_guard_');
    });

    tearDown(() {
      if (pretendReal.existsSync()) pretendReal.deleteSync(recursive: true);
    });

    test('passes when the guarded root is untouched', () {
      File('${pretendReal.path}/audit_log.jsonl').writeAsStringSync('seed');
      final guard = RealStateGuard(pretendReal)..snapshot();

      expect(guard.assertUnchanged, returnsNormally);
    });

    test('fails on a deliberate write (violating fixture)', () {
      final guard = RealStateGuard(pretendReal)..snapshot();

      // Deliberately violating fixture: writes a file into the temp root that
      // pretends to be the real state dir. Never the real one.
      File('${pretendReal.path}/active_job.json').writeAsStringSync('{"oops":true}');

      expect(guard.assertUnchanged, throwsA(isA<StateViolation>()));
    });

    test('fails on modification and on removal', () {
      final file = File('${pretendReal.path}/audit_log.jsonl')..writeAsStringSync('a');
      final guard = RealStateGuard(pretendReal)..snapshot();

      file.writeAsStringSync('ab');
      expect(guard.assertUnchanged, throwsA(isA<StateViolation>()));

      guard.snapshot();
      file.deleteSync();
      expect(guard.assertUnchanged, throwsA(isA<StateViolation>()));
    });
  });

  group('real state directories stay untouched', () {
    final realBase = AppPaths.production().baseDir;
    final engineState = Directory(
      '${Platform.environment['HOME'] ?? '/root'}/.local/state/zero_trace',
    );

    test('write paths with injected temp AppPaths leave the real dirs unchanged', () async {
      final baseGuard = RealStateGuard(realBase)..snapshot();
      final engineGuard = RealStateGuard(engineState)..snapshot();

      final tempDir = Directory.systemTemp.createTempSync('zt_guard_ops_');
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });
      final appPaths = AppPaths(
        baseDir: tempDir,
        checkpointDir: Directory('${tempDir.path}/checkpoints'),
      );

      const device = DeviceProfile(
        id: 'sdb',
        name: 'Guard Test Drive',
        serialNumber: 'GUARD-SERIAL-1',
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        capacityBytes: 16000000000,
        isRemovable: true,
      );

      final controller = SanitizationController(
        appPaths: appPaths,
        enableAutoPolling: false,
        deferInitialDiscovery: true,
      );
      addTearDown(() => controller.dispose());
      controller.setMockDevices([device]);
      controller.setMockJob(SanitizationJob(
        jobId: 'job-guard-1',
        device: device,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 0.5,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88 Clear',
        explanationText: 'Single-Pass Overwrite',
        status: JobStatus.sanitizing,
        progress: 0.5,
        startTime: DateTime.now(),
      ));

      // Exercise the write paths (interrupted record + audit log + clear).
      await controller.interruptOnExit();

      // The interrupted record landed in the temp dir, not the real one.
      expect(File('${tempDir.path}/active_job.json').existsSync(), isTrue);

      controller.setMockOrphanResult(OrphanCheckResult(
        status: OrphanCheckStatus.interrupted,
        activeJobState: ActiveJobState(
          jobId: 'job-guard-1',
          deviceSerial: device.serialNumber,
          devicePath: device.id,
          deviceName: device.name,
          method: 'Single-Pass Overwrite',
          startedAt: DateTime.now().toIso8601String(),
        ),
      ));
      await controller.acknowledgeOrphan();

      baseGuard.assertUnchanged();
      engineGuard.assertUnchanged();
    });
  });
}
