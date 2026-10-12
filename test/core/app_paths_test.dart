import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';

void main() {
  late Directory tempDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('zt_apppaths_');
  });

  tearDown(() {
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
  });

  AppPaths build() => AppPaths(
        baseDir: Directory('${tempDir.path}/base'),
        checkpointDir: Directory('${tempDir.path}/checkpoints'),
      );

  test('derived paths hang off baseDir', () {
    final paths = build();
    expect(paths.auditLogFile.path, '${tempDir.path}/base/audit_log.jsonl');
    expect(paths.activeJobFile.path, '${tempDir.path}/base/active_job.json');
    expect(paths.certificatesDir.path, '${tempDir.path}/base/certificates');
    expect(paths.reportsDir.path, '${tempDir.path}/base/reports');
  });

  test('ensureDirectories creates base, certificates and reports', () {
    final paths = build();
    paths.ensureDirectories();
    expect(paths.baseDir.existsSync(), isTrue);
    expect(paths.certificatesDir.existsSync(), isTrue);
    expect(paths.reportsDir.existsSync(), isTrue);
  });
}
