import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/services/audit_log_service.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/history_screen.dart';

void main() {
  group('HistoryScreen UI Tests', () {
    late Directory tempHome;
    late AuditLogService auditLogService;

    setUp(() async {
      tempHome = await Directory.systemTemp.createTemp('zt_home_test_');
      auditLogService = AuditLogService(customBaseDirectory: tempHome.path);
    });

    tearDown(() async {
      if (tempHome.existsSync()) {
        await tempHome.delete(recursive: true);
      }
    });

    testWidgets('HistoryScreen renders empty state when log is empty', (tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;

      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());

      await tester.pumpWidget(
        ChangeNotifierProvider<SanitizationController>.value(
          value: controller,
          child: MaterialApp(
            home: HistoryScreen(auditLogService: auditLogService),
          ),
        ),
      );

      await tester.runAsync(() async {
        await Future.delayed(const Duration(milliseconds: 100));
      });
      await tester.pump();

      expect(find.text('Operation History'), findsOneWidget);
      expect(find.text('No Sanitization History'), findsOneWidget);
      expect(find.text('Export Log'), findsOneWidget);
      expect(find.text('Show simulated runs'), findsOneWidget);

      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });
    });

    testWidgets('HistoryScreen displays logged entries, integrity check banner, and simulated filter', (tester) async {
      tester.view.physicalSize = const Size(1920, 1080);
      tester.view.devicePixelRatio = 1.0;

      // Seed audit log with real and simulated entries in real async
      await tester.runAsync(() async {
        await auditLogService.appendEntry(
          AuditLogEntry(
            timestamp: '2026-10-10T14:00:00Z',
            jobId: 'JOB-REAL-001',
            deviceSerial: 'REAL-SERIAL-123',
            devicePath: '/dev/sdb',
            deviceName: 'Crucial MX500',
            method: 'ATA Secure Erase',
            methodClass: 'firmwareSanitize',
            standardReference: 'NIST SP 800-88r1',
            nistCategory: 'Purge',
            success: true,
            fingerprintHash: 'HASH123',
            entropyScore: 0.0001,
            sampleCount: 50,
            commandLog: ['Unmount OK', 'Command complete'],
            scope: 'full',
            isSimulated: false,
            verificationPassed: true,
            certificateId: 'ZT-CERT-REAL-001',
          ),
        );

        await auditLogService.appendEntry(
          AuditLogEntry(
            timestamp: '2026-10-10T15:00:00Z',
            jobId: 'JOB-SIM-002',
            deviceSerial: 'SIM-SERIAL-456',
            devicePath: '/dev/sdc',
            deviceName: 'Virtual Test Disk',
            method: 'Single-Pass Overwrite',
            methodClass: 'overwrite',
            standardReference: 'NIST SP 800-88r1 Clear',
            nistCategory: 'Clear',
            success: true,
            fingerprintHash: 'SIMHASH456',
            entropyScore: 0.0002,
            sampleCount: 50,
            commandLog: ['Simulated write'],
            scope: 'full',
            isSimulated: true,
            verificationPassed: true,
            certificateId: 'ZT-CERT-SIM-002',
          ),
        );
      });

      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());

      await tester.pumpWidget(
        ChangeNotifierProvider<SanitizationController>.value(
          value: controller,
          child: MaterialApp(
            home: HistoryScreen(auditLogService: auditLogService),
          ),
        ),
      );

      for (int i = 0; i < 20; i++) {
        await tester.runAsync(() async {
          await Future.delayed(const Duration(milliseconds: 100));
        });
        await tester.pump();
        if (find.text('Crucial MX500').evaluate().isNotEmpty) break;
      }

      // Real entry should be visible
      expect(find.text('Crucial MX500'), findsOneWidget);
      expect(find.text('REAL-SERIAL-123'), findsOneWidget);
      expect(find.text('ZT-CERT-REAL-001'), findsOneWidget);

      // Simulated entry is hidden by default
      expect(find.text('Virtual Test Disk'), findsNothing);

      for (int i = 0; i < 20; i++) {
        await tester.runAsync(() async {
          await Future.delayed(const Duration(milliseconds: 100));
        });
        await tester.pump();
        if (find.textContaining('Integrity Check: Valid').evaluate().isNotEmpty) break;
      }

      expect(find.textContaining('Integrity Check: Valid'), findsOneWidget);

      // Toggle "Show simulated runs"
      final switchFinder = find.byType(Switch);
      final switchWidget = tester.widget<Switch>(switchFinder);
      switchWidget.onChanged!(true);
      
      for (int i = 0; i < 20; i++) {
        await tester.runAsync(() async {
          await Future.delayed(const Duration(milliseconds: 100));
        });
        await tester.pump();
        if (find.text('Virtual Test Disk').evaluate().isNotEmpty) break;
      }

      // Now simulated entry is visible
      expect(find.text('Virtual Test Disk'), findsOneWidget);
      expect(find.text('SIM-SERIAL-456'), findsOneWidget);
      expect(find.text('SIMULATED'), findsOneWidget);

      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });
    });
  });
}
