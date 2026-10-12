import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/services/job_state_file.dart';
import 'package:zero_trace/services/orphaned_process_checker.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/drive_list_screen.dart';

/// Behaviour snapshots pinned *before* the test-isolation refactor.
///
/// Every filesystem assertion writes to a throwaway temp directory so the real
/// `~/.zero_trace` is never touched by a test.
void main() {
  late Directory tempDir;
  late Directory stateDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('zt_snapshot_');
    stateDir = Directory('${tempDir.path}/state');
    stateDir.createSync(recursive: true);
  });

  tearDown(() {
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  AppPaths paths() => AppPaths(
        baseDir: stateDir,
        checkpointDir: Directory('${tempDir.path}/checkpoints'),
      );

  ActiveJobState sampleState() => ActiveJobState(
        jobId: 'job-snapshot-1',
        deviceSerial: 'SNAP-UNIQUE-SERIAL-1',
        devicePath: '/dev/sdz',
        deviceName: 'SanDisk Snapshot Drive',
        method: 'Single-Pass Overwrite',
        methodKind: 'overwrite',
        deviceSize: 16000000000,
        startedAt: '2026-10-12T00:00:00.000Z',
        status: 'running',
        partitionNumber: 2,
        partitionStartSector: 2048,
        partitionSizeSectors: 4096,
        scope: 'partition',
        limitation: 'Only the selected partition is affected',
      );

  group('interrupted-job recording (JobStateFile snapshot)', () {
    test('recordInterrupted writes status=interrupted and preserves every field', () async {
      await JobStateFile(paths: paths()).recordInterrupted(sampleState());

      final saved = await JobStateFile(paths: paths()).readActiveJob();
      expect(saved, isNotNull);
      expect(saved!.status, 'interrupted');
      expect(saved.jobId, 'job-snapshot-1');
      expect(saved.deviceSerial, 'SNAP-UNIQUE-SERIAL-1');
      expect(saved.devicePath, '/dev/sdz');
      expect(saved.deviceName, 'SanDisk Snapshot Drive');
      expect(saved.method, 'Single-Pass Overwrite');
      expect(saved.startedAt, '2026-10-12T00:00:00.000Z');
      expect(saved.partitionNumber, 2);
      expect(saved.partitionStartSector, 2048);
      expect(saved.partitionSizeSectors, 4096);
      expect(saved.scope, 'partition');
      expect(saved.limitation, 'Only the selected partition is affected');
    });

    test('active_job.json on disk has the exact expected shape', () async {
      await JobStateFile(paths: paths()).recordInterrupted(sampleState());

      final file = File('${stateDir.path}/active_job.json');
      expect(file.existsSync(), isTrue);

      final decoded = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
      expect(
        decoded.keys.toSet(),
        {
          'jobId',
          'deviceSerial',
          'devicePath',
          'deviceName',
          'method',
          'methodKind',
          'deviceSize',
          'startedAt',
          'status',
          'partitionNumber',
          'partitionStartSector',
          'partitionSizeSectors',
          'scope',
          'limitation',
        },
      );
      expect(decoded['status'], 'interrupted');
    });

    test('clearActiveJob removes the file and readActiveJob returns null', () async {
      await JobStateFile(paths: paths()).recordInterrupted(sampleState());
      expect(File('${stateDir.path}/active_job.json').existsSync(), isTrue);

      await JobStateFile(paths: paths()).clearActiveJob();

      expect(File('${stateDir.path}/active_job.json').existsSync(), isFalse);
      expect(await JobStateFile(paths: paths()).readActiveJob(), isNull);
    });

    test('readActiveJob on a missing directory returns null without throwing', () async {
      final missing = AppPaths(
        baseDir: Directory('${tempDir.path}/does-not-exist'),
        checkpointDir: Directory('${tempDir.path}/checkpoints'),
      );
      expect(await JobStateFile(paths: missing).readActiveJob(), isNull);
    });
  });

  group('orphan card (widget snapshot)', () {
    const usbDevice = DeviceProfile(
      id: 'sdb',
      name: 'SanDisk Cruzer Blade',
      serialNumber: '4C530000151121111494',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
    );

    Widget subject(SanitizationController controller) {
      return ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: const MaterialApp(home: Scaffold(body: DriveListScreen())),
      );
    }

    testWidgets('interrupted card pins title, wording and Dismiss action', (tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      final controller = SanitizationController(
        appPaths: paths(),
        enableAutoPolling: false,
        deferInitialDiscovery: true,
      );
      addTearDown(() => controller.dispose());
      controller.setMockDevices([usbDevice]);

      await tester.pumpWidget(subject(controller));
      await tester.pumpAndSettle();

      controller.setMockOrphanResult(OrphanCheckResult(
        status: OrphanCheckStatus.interrupted,
        activeJobState: ActiveJobState(
          jobId: 'JOB-888',
          deviceSerial: '4C530000151121111494',
          devicePath: '/dev/sdb',
          deviceName: 'SanDisk Cruzer Blade',
          method: 'Single-Pass Overwrite',
          startedAt: '2026-10-12T00:00:00.000Z',
        ),
        checkpointWording: 'about 3.5 GB reported written at the last check, not verified',
      ));
      await tester.pumpAndSettle();

      expect(find.text('Interrupted wipe detected'), findsOneWidget);
      expect(
        find.text(
          'Device SanDisk Cruzer Blade: '
          'about 3.5 GB reported written at the last check, not verified. '
          'Check before reuse.',
        ),
        findsOneWidget,
      );
      expect(find.text('Dismiss'), findsOneWidget);
    });
  });
}
