import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/services/job_state_file.dart';
import 'package:zero_trace/services/orphaned_process_checker.dart';

/// Behaviour tests for the orphan checker checkpoint recovery.
///
/// All files live in a throwaway temp dir; the real `~/.zero_trace` is never
/// touched. The single in-flight job limit means one `active_job.json` plus one
/// `active_checkpoint.json` describe the interrupted job.
void main() {
  late Directory tempDir;
  late Directory checkpointDir;
  late AppPaths paths;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('zt_orphan_');
    checkpointDir = Directory('${tempDir.path}/checkpoints')..createSync(recursive: true);
    paths = AppPaths(baseDir: tempDir, checkpointDir: checkpointDir);
  });

  tearDown(() {
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
  });

  const serial = 'SERIAL-ORPHAN-1';
  const jobId = 'job-orphan-1';
  const deviceSize = 16000000000;

  ActiveJobState state({String kind = 'overwrite'}) => ActiveJobState(
        jobId: jobId,
        deviceSerial: serial,
        devicePath: '/dev/sdb',
        deviceName: 'Orphan Test Drive',
        method: 'Single-Pass Overwrite',
        methodKind: kind,
        deviceSize: deviceSize,
        startedAt: '2026-10-12T00:00:00.000Z',
        status: 'interrupted',
      );

  String hashOf(String s) => sha256.convert(utf8.encode(s)).toString();

  void writeCheckpoint({
    String id = jobId,
    String idHash = '',
    int size = deviceSize,
    int bytes = 3500000000,
  }) {
    final hash = idHash.isEmpty ? hashOf(serial) : idHash;
    File('${checkpointDir.path}/active_checkpoint.json').writeAsStringSync(jsonEncode({
      'job_id': id,
      'device_size': size,
      'device_id_hash': hash,
      'bytes_done': bytes,
      'timestamp': 1760000000,
    }));
  }

  test('overwrite with a matching checkpoint reports the byte wording', () async {
    await JobStateFile(paths: paths).recordInterrupted(state());
    writeCheckpoint(bytes: 3500000000);

    final result = await OrphanedProcessChecker(paths: paths).checkForOrphan();
    expect(result.status, isNot(OrphanCheckStatus.none));
    expect(result.bytesDone, 3500000000);
    expect(
      result.checkpointWording,
      'about 3.5 GB reported written at the last check, not verified',
    );
    expect(result.checkpointWording, isNot(contains('wiped')));
  });

  test('firmware sanitize reports "state unknown", never a byte count', () async {
    await JobStateFile(paths: paths).recordInterrupted(state(kind: 'firmware'));
    writeCheckpoint(bytes: 3500000000);

    final result = await OrphanedProcessChecker(paths: paths).checkForOrphan();
    expect(result.checkpointWording, OrphanedProcessChecker.stateUnknownWording);
    expect(result.checkpointWording, contains('not sanitized until verified'));
    expect(result.checkpointWording, isNot(contains('wiped')));
    expect(result.bytesDone, isNull);
  });

  test('stale checkpoint from another device is ignored', () async {
    await JobStateFile(paths: paths).recordInterrupted(state());
    // Valid checkpoint, but hash/identity belongs to a different serial.
    writeCheckpoint(id: 'other-job', idHash: hashOf('SOME-OTHER-DEVICE'));

    final result = await OrphanedProcessChecker(paths: paths).checkForOrphan();
    expect(result.bytesDone, isNull);
    expect(result.checkpointWording, OrphanedProcessChecker.unreadableWording);
  });

  test('checkpoint with a mismatched device_size is ignored', () async {
    await JobStateFile(paths: paths).recordInterrupted(state());
    writeCheckpoint(size: 999); // wrong size, same job id + hash

    final result = await OrphanedProcessChecker(paths: paths).checkForOrphan();
    expect(result.bytesDone, isNull);
    expect(result.checkpointWording, OrphanedProcessChecker.unreadableWording);
  });

  test('missing checkpoint is handled (overwrite: progress could not be read)', () async {
    await JobStateFile(paths: paths).recordInterrupted(state());

    final result = await OrphanedProcessChecker(paths: paths).checkForOrphan();
    expect(result.bytesDone, isNull);
    expect(result.checkpointWording, OrphanedProcessChecker.unreadableWording);
  });

  test('corrupt / truncated checkpoint is handled without crashing', () async {
    await JobStateFile(paths: paths).recordInterrupted(state());
    File('${checkpointDir.path}/active_checkpoint.json')
        .writeAsStringSync('{"job_id": "job-orphan-1", "device_size": 16');

    final result = await OrphanedProcessChecker(paths: paths).checkForOrphan();
    expect(result.bytesDone, isNull);
    expect(result.checkpointWording, OrphanedProcessChecker.unreadableWording);
  });

  test('leftover engine temp files are ignored and cleaned, final file untouched', () async {
    await JobStateFile(paths: paths).recordInterrupted(state());
    writeCheckpoint(bytes: 1000000000);
    final tmp1 = File('${checkpointDir.path}/active_checkpoint.1234.tmp')..writeAsStringSync('partial');
    final legacyTmp = File('${checkpointDir.path}/active_checkpoint.tmp')..writeAsStringSync('x');
    // A non-matching file must be left alone.
    final unrelated = File('${checkpointDir.path}/notes.txt')..writeAsStringSync('keep');

    final result = await OrphanedProcessChecker(paths: paths).checkForOrphan();

    expect(result.bytesDone, 1000000000);
    expect(File('${checkpointDir.path}/active_checkpoint.json').existsSync(), isTrue);
    expect(tmp1.existsSync(), isFalse);
    expect(legacyTmp.existsSync(), isFalse);
    expect(unrelated.existsSync(), isTrue);
  });

  test('readEngineCheckpoint distinguishes missing / corrupt / mismatch / matched', () {
    final checker = OrphanedProcessChecker(paths: paths);
    final s = state();

    expect(checker.readEngineCheckpoint(s).status, CheckpointReadStatus.missing);

    File('${checkpointDir.path}/active_checkpoint.json').writeAsStringSync('{ not json');
    expect(checker.readEngineCheckpoint(s).status, CheckpointReadStatus.corrupt);

    writeCheckpoint(idHash: hashOf('ANOTHER-DEVICE'));
    expect(checker.readEngineCheckpoint(s).status, CheckpointReadStatus.mismatch);

    writeCheckpoint();
    final matched = checker.readEngineCheckpoint(s);
    expect(matched.status, CheckpointReadStatus.matched);
    expect(matched.checkpoint!.timestamp, 1760000000);
  });

  test('no active job means no orphan result', () async {
    final result = await OrphanedProcessChecker(paths: paths).checkForOrphan();
    expect(result.status, OrphanCheckStatus.none);
  });
}
