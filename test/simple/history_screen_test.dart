import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/services/audit_log_service.dart';
import 'package:zero_trace/simple/history_screen.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory tempDir;
  late AuditLogService service;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('zt_history_');
    service = AuditLogService(
      paths: AppPaths(
        baseDir: tempDir,
        checkpointDir: Directory('${tempDir.path}/checkpoints'),
      ),
    );
  });

  tearDown(() {
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
  });

  AuditLogEntry entry({
    required String jobId,
    String? deviceName,
    bool isSimulated = false,
    String? outcome = 'completed',
    String? failureReason,
  }) {
    return AuditLogEntry(
      timestamp: '2026-10-10T12:00:00Z',
      jobId: jobId,
      deviceSerial: 'SERIAL-$jobId',
      devicePath: '/dev/sdb',
      deviceName: deviceName,
      method: 'Single-Pass Overwrite',
      standardReference: 'NIST SP 800-88 Rev. 1',
      nistCategory: 'Clear',
      outcome: outcome,
      success: true,
      fingerprintHash: 'FP',
      entropyScore: 0.0,
      sampleCount: 50,
      commandLog: const ['Unmounting device', 'Executing erase'],
      isSimulated: isSimulated,
      failureReason: failureReason,
    );
  }

  Future<void> pumpHistory(WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: HistoryScreen(auditLogService: service)),
      ),
    );
    // The screen reads files and verifies the chain in a real Isolate, so let
    // real async work complete before settling the frame.
    await tester.runAsync(() async {
      await Future<void>.delayed(const Duration(milliseconds: 500));
    });
    await tester.pumpAndSettle();
  }

  testWidgets('empty directory shows the honest empty state', (tester) async {
    await pumpHistory(tester);

    expect(find.byKey(const Key('history-empty')), findsOneWidget);
    expect(find.byKey(const Key('history-integrity-valid')), findsOneWidget);
    expect(find.text('No sanitization history'), findsOneWidget);
  });

  testWidgets('a real entry written through the service appears',
      (tester) async {
    await service.appendEntry(
      entry(jobId: 'JOB-REAL', deviceName: 'SanDisk Flash Drive'),
    );

    await pumpHistory(tester);

    expect(find.byKey(const Key('history-empty')), findsNothing);
    expect(find.byKey(const ValueKey('history-entry-JOB-REAL')), findsOneWidget);
    expect(find.text('SanDisk Flash Drive'), findsOneWidget);
    expect(find.text('COMPLETED'), findsOneWidget);
  });

  testWidgets('simulated runs are hidden by default and shown when toggled',
      (tester) async {
    await service.appendEntry(
      entry(jobId: 'JOB-SIM', deviceName: 'Simulated Drive', isSimulated: true),
    );

    await pumpHistory(tester);

    expect(find.byKey(const ValueKey('history-entry-JOB-SIM')), findsNothing);
    expect(find.byKey(const Key('history-empty')), findsOneWidget);

    await tester.tap(find.byKey(const Key('history-toggle-simulated')));
    await tester.pumpAndSettle();

    expect(find.byKey(const ValueKey('history-entry-JOB-SIM')), findsOneWidget);
    expect(find.text('SIMULATED'), findsOneWidget);
  });

  testWidgets('legacy entries stay hidden until explicitly revealed',
      (tester) async {
    final legacy = {
      'timestamp': '2026-09-01T00:00:00Z',
      'jobId': 'JOB-LEGACY',
      'deviceSerial': 'OLD',
      'devicePath': '/dev/sda',
      'method': 'Zero Fill',
      'standardReference': 'NIST',
      'nistCategory': 'Clear',
      'success': true,
      'fingerprintHash': 'OLD-HASH',
      'entropyScore': 0.001,
      'sampleCount': 20,
      'commandLog': <String>['legacy run'],
    };
    File('${tempDir.path}/audit_log.jsonl')
        .writeAsStringSync('${jsonEncode(legacy)}\n');

    await pumpHistory(tester);

    // Legacy is not in the main list and the "show legacy" control is offered.
    expect(find.byKey(const ValueKey('history-entry-JOB-LEGACY')), findsNothing);
    expect(find.byKey(const Key('history-toggle-legacy')), findsOneWidget);

    await tester.tap(find.byKey(const Key('history-toggle-legacy')));
    await tester.pumpAndSettle();

    expect(find.text('Legacy entries, source unknown'), findsOneWidget);
    expect(find.byKey(const ValueKey('history-entry-JOB-LEGACY')), findsOneWidget);
    expect(find.text('LEGACY'), findsOneWidget);
  });

  testWidgets('a tampered log shows the broken integrity row', (tester) async {
    await service.appendEntry(entry(jobId: 'JOB-1'));
    await service.appendEntry(entry(jobId: 'JOB-2'));

    final logFile = File('${tempDir.path}/audit_log.jsonl');
    final lines = logFile.readAsLinesSync();
    final map = jsonDecode(lines[0]) as Map<String, dynamic>;
    map['method'] = 'TAMPERED';
    lines[0] = jsonEncode(map);
    logFile.writeAsStringSync('${lines.join('\n')}\n');

    await pumpHistory(tester);

    expect(find.byKey(const Key('history-integrity-broken')), findsOneWidget);
  });

  testWidgets('a failed entry shows the readable engine failure reason',
      (tester) async {
    // Phase P4-fix: `wipe_failed` entries carry the typed engine reason
    // (including the blocking mount point) and the card must show it.
    await service.appendEntry(
      entry(
        jobId: 'JOB-FAIL',
        deviceName: 'Broken Drive',
        outcome: 'wipe_failed',
        failureReason:
            "The wipe or verification failed (exit 2). /dev/sdb1 is "
            "mounted/active as '/dev/sdb1' (mounted at /mnt/data)",
      ),
    );

    await pumpHistory(tester);

    expect(find.byKey(const ValueKey('history-entry-JOB-FAIL')), findsOneWidget);
    expect(find.text('WIPE FAILED'), findsOneWidget);
    expect(find.text('Failure'), findsOneWidget);
    expect(find.textContaining('/mnt/data'), findsOneWidget);
  });
}
