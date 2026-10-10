import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/confirm_wipe_dialog.dart';

void main() {
  group('Wipe Entry Point Static Scan Guard', () {
    const allowlistedCallers = {
      'lib/simple/drive_detail_screen.dart',
    };

    List<String> scanFilesForForbiddenCalls(Map<String, String> filesToScan) {
      final violations = <String>[];
      final regex = RegExp(r'(startSimpleWipe\s*\(|runSanitizationPipeline\s*\()');

      for (final entry in filesToScan.entries) {
        final filePath = entry.key;
        final content = entry.value;

        // Skip allowlisted files
        if (allowlistedCallers.contains(filePath) ||
            filePath == 'lib/services/sanitization_controller.dart') {
          continue;
        }

        final lines = content.split('\n');
        for (int i = 0; i < lines.length; i++) {
          final line = lines[i];
          // Ignore comments or definitions of the method
          if (line.trim().startsWith('//') ||
              line.contains('Future<void> startSimpleWipe(') ||
              line.contains('Future<void> _runSanitizationPipeline(') ||
              line.contains('runSanitizationPipelineForTesting(')) {
            continue;
          }
          if (regex.hasMatch(line)) {
            violations.add('$filePath:${i + 1}: ${line.trim()}');
          }
        }
      }
      return violations;
    }

    test('lib/ codebase static scan verifies ONLY drive_detail_screen.dart initiates wipes', () {
      final libDir = Directory('lib');
      expect(libDir.existsSync(), isTrue);

      final filesMap = <String, String>{};
      for (final entity in libDir.listSync(recursive: true)) {
        if (entity is File && entity.path.endsWith('.dart')) {
          final relativePath = entity.path.replaceAll('\\', '/');
          filesMap[relativePath] = entity.readAsStringSync();
        }
      }

      final violations = scanFilesForForbiddenCalls(filesMap);
      expect(
        violations,
        isEmpty,
        reason: 'Forbidden direct wipe entry point calls detected outside allowlist:\n${violations.join('\n')}',
      );
    });

    test('Failing-fixture test: proves that unallowlisted wipe call is caught by the scan', () {
      final violatingFixture = {
        'lib/features/evil_module/evil_screen.dart': '''
import 'package:zero_trace/services/sanitization_controller.dart';

void evilFunction(SanitizationController controller, device, intent, auth) {
  // Rogue unconfirmed wipe call
  controller.startSimpleWipe(device, intent, authorization: auth);
}
''',
      };

      final violations = scanFilesForForbiddenCalls(violatingFixture);
      expect(violations, isNotEmpty);
      expect(violations.first, contains('evil_screen.dart'));
      expect(violations.first, contains('startSimpleWipe'));
    });

    test('WipeAuthorization token validates device serial match', () async {
      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());

      const deviceA = DeviceProfile(
        id: 'sda',
        name: 'Device A',
        serialNumber: 'SERIAL-AAA',
        mediaType: MediaType.sataSsd,
        busType: 'SATA',
        capacityBytes: 500000000000,
      );

      const deviceB = DeviceProfile(
        id: 'sdb',
        name: 'Device B',
        serialNumber: 'SERIAL-BBB',
        mediaType: MediaType.sataSsd,
        busType: 'SATA',
        capacityBytes: 500000000000,
      );

      // Auth issued for device B
      final authB = WipeAuthorization.forTesting(deviceSerial: deviceB.serialNumber);

      // Attempting to wipe device A with auth for device B must throw ArgumentError
      expect(
        () => controller.startSimpleWipe(deviceA, DisposalIntent.reuseMyself, authorization: authB),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
