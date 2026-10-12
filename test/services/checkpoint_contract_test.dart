import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/services/job_state_file.dart';
import 'package:zero_trace/services/orphaned_process_checker.dart';

/// Contract test for the engine checkpoint fixture.
///
/// The same file `test/fixtures/active_checkpoint.json` is asserted by the Rust
/// test `native/zt_engine/tests/checkpoint_contract_test.rs` against the
/// engine's real writer. This side proves Dart parses that exact shape.
void main() {
  final fixtureFile = File('test/fixtures/active_checkpoint.json');

  test('fixture file exists and parses as an EngineCheckpoint', () {
    expect(fixtureFile.existsSync(), isTrue);
    final json = jsonDecode(fixtureFile.readAsStringSync()) as Map<String, dynamic>;
    final checkpoint = EngineCheckpoint.fromJson(json);
    expect(checkpoint.jobId, 'contract-job-1');
    expect(checkpoint.deviceSize, 16000000000);
    expect(checkpoint.bytesDone, 3500000000);
    expect(checkpoint.timestamp, 1760000000);
    expect(
      checkpoint.deviceIdHash,
      sha256.convert(utf8.encode('CONTRACT-SERIAL-1')).toString(),
    );
  });

  test('fixture matches the active job identity (job id + sha256(serial) + size)', () {
    final json = jsonDecode(fixtureFile.readAsStringSync()) as Map<String, dynamic>;
    final checkpoint = EngineCheckpoint.fromJson(json);
    expect(
      checkpoint.matches(
        jobId: 'contract-job-1',
        serial: 'CONTRACT-SERIAL-1',
        deviceSize: 16000000000,
      ),
      isTrue,
    );
  });

  test('fixture shape is exactly the engine field set', () {
    final json = jsonDecode(fixtureFile.readAsStringSync()) as Map<String, dynamic>;
    expect(
      json.keys.toSet(),
      {'job_id', 'device_size', 'device_id_hash', 'bytes_done', 'timestamp'},
    );
  });

  test('checker reads the fixture placed in a temp checkpoint dir', () async {
    final tempDir = Directory.systemTemp.createTempSync('zt_contract_');
    addTearDown(() {
      if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
    });
    final checkpointDir = Directory('${tempDir.path}/checkpoints')..createSync(recursive: true);
    File('${checkpointDir.path}/active_checkpoint.json')
        .writeAsStringSync(fixtureFile.readAsStringSync());

    final checker = OrphanedProcessChecker(
      paths: AppPaths(baseDir: tempDir, checkpointDir: checkpointDir),
    );
    final state = ActiveJobState(
      jobId: 'contract-job-1',
      deviceSerial: 'CONTRACT-SERIAL-1',
      devicePath: '/dev/sdb',
      deviceName: 'Contract Drive',
      method: 'Single-Pass Overwrite',
      methodKind: 'overwrite',
      deviceSize: 16000000000,
      startedAt: '2026-10-12T00:00:00.000Z',
    );

    final read = checker.readEngineCheckpoint(state);
    expect(read.status, CheckpointReadStatus.matched);
    expect(read.checkpoint!.bytesDone, 3500000000);
  });

  test('fixture hash equals sha256 of the serial the engine hashes', () {
    final json = jsonDecode(fixtureFile.readAsStringSync()) as Map<String, dynamic>;
    expect(
      json['device_id_hash'],
      sha256.convert(utf8.encode('CONTRACT-SERIAL-1')).toString(),
    );
  });
}
