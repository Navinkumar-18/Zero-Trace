import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../core/app_paths.dart';
import 'job_state_file.dart';

enum OrphanCheckStatus {
  none,
  processActive,
  interrupted,
}

/// Result of reading `<checkpointDir>/active_checkpoint.json`.
enum CheckpointReadStatus {
  /// No `active_checkpoint.json` present.
  missing,

  /// File present but empty, truncated or not valid JSON.
  corrupt,

  /// File present and valid but belongs to a different job/device.
  mismatch,

  /// File present, valid, and matches the active job.
  matched,
}

class EngineCheckpointRead {
  final CheckpointReadStatus status;
  final EngineCheckpoint? checkpoint;

  const EngineCheckpointRead(this.status, [this.checkpoint]);
}

/// Parsed engine checkpoint.
///
/// Exact shape written by `native/zt_engine/src/execute.rs` (`CheckpointData`):
/// `{ "job_id": String, "device_size": u64, "device_id_hash": String,
///    "bytes_done": u64, "timestamp": u64 }`
/// where `device_id_hash = sha256(device serial)` in lowercase hex.
///
/// There is a single in-flight job at a time, so there is a single
/// `active_checkpoint.json` describing it. A checkpoint is only ever used when
/// its `job_id` equals the active job's id **and** its `device_id_hash` equals
/// `sha256(active job serial)`; a checkpoint for another device is ignored.
class EngineCheckpoint {
  final String jobId;
  final int deviceSize;
  final String deviceIdHash;
  final int bytesDone;
  final int timestamp;

  EngineCheckpoint({
    required this.jobId,
    required this.deviceSize,
    required this.deviceIdHash,
    required this.bytesDone,
    required this.timestamp,
  });

  factory EngineCheckpoint.fromJson(Map<String, dynamic> json) {
    final jobId = json['job_id'];
    final deviceIdHash = json['device_id_hash'];
    if (jobId is! String || jobId.isEmpty) {
      throw const FormatException('active_checkpoint.json: missing job_id');
    }
    if (deviceIdHash is! String || deviceIdHash.isEmpty) {
      throw const FormatException('active_checkpoint.json: missing device_id_hash');
    }
    return EngineCheckpoint(
      jobId: jobId,
      deviceSize: (json['device_size'] as num? ?? 0).toInt(),
      deviceIdHash: deviceIdHash,
      bytesDone: (json['bytes_done'] as num? ?? 0).toInt(),
      timestamp: (json['timestamp'] as num? ?? 0).toInt(),
    );
  }

  /// True only when this checkpoint's job id, device identity hash and (when
  /// known) device size all match the active job.
  bool matches({required String jobId, required String serial, int? deviceSize}) {
    if (jobId.isEmpty || this.jobId != jobId) return false;
    if (deviceIdHash != sha256.convert(utf8.encode(serial)).toString()) {
      return false;
    }
    if (deviceSize != null && this.deviceSize != deviceSize) return false;
    return true;
  }
}

class OrphanCheckResult {
  final OrphanCheckStatus status;
  final ActiveJobState? activeJobState;
  final String? pid;
  final int? bytesDone;
  final int? bytesTotal;
  final String? checkpointWording;

  OrphanCheckResult({
    required this.status,
    this.activeJobState,
    this.pid,
    this.bytesDone,
    this.bytesTotal,
    this.checkpointWording,
  });
}

/// Recovers an interrupted wipe from `active_job.json` plus the engine's
/// `active_checkpoint.json`.
///
/// There is a single in-flight job limit: at most one `active_job.json` and one
/// `active_checkpoint.json` exist at a time; a new job replaces the previous
/// pair. The checker never invents progress it cannot prove.
class OrphanedProcessChecker {
  final AppPaths paths;
  final JobStateFile _jobState;

  OrphanedProcessChecker({required this.paths})
      : _jobState = JobStateFile(paths: paths);

  /// Wording for byte-tracked software overwrites with a readable checkpoint.
  static String overwriteWording(int bytesDone) =>
      'about ${(bytesDone / 1e9).toStringAsFixed(1)} GB reported written at the last check, not verified';

  /// Wording when an overwrite checkpoint is absent or unreadable.
  static const String unreadableWording = 'progress could not be read';

  /// Wording for firmware sanitize (or unknown method) where byte progress is
  /// not meaningful and the controller may still be working.
  static const String stateUnknownWording =
      'state unknown, may still be running or finished; treat as not sanitized until verified';

  /// The engine's temp-file pattern, e.g. `active_checkpoint.1234.tmp` or the
  /// legacy `active_checkpoint.tmp`. Only files matching this inside our
  /// checkpoint dir are ever cleaned; the final file is never matched.
  static final RegExp _tempPattern =
      RegExp(r'^active_checkpoint(\.\d+)?\.tmp$');

  /// Reads and validates the engine checkpoint for [state]. Never throws.
  EngineCheckpointRead readEngineCheckpoint(ActiveJobState state) {
    final file = File('${paths.checkpointDir.path}/active_checkpoint.json');
    if (!file.existsSync()) {
      return const EngineCheckpointRead(CheckpointReadStatus.missing);
    }

    final String content;
    try {
      content = file.readAsStringSync();
    } catch (_) {
      return const EngineCheckpointRead(CheckpointReadStatus.corrupt);
    }
    if (content.trim().isEmpty) {
      return const EngineCheckpointRead(CheckpointReadStatus.corrupt);
    }

    final EngineCheckpoint checkpoint;
    try {
      final decoded = jsonDecode(content);
      if (decoded is! Map<String, dynamic>) {
        return const EngineCheckpointRead(CheckpointReadStatus.corrupt);
      }
      checkpoint = EngineCheckpoint.fromJson(decoded);
    } catch (_) {
      return const EngineCheckpointRead(CheckpointReadStatus.corrupt);
    }

    if (!checkpoint.matches(
      jobId: state.jobId,
      serial: state.deviceSerial,
      deviceSize: state.deviceSize,
    )) {
      return const EngineCheckpointRead(CheckpointReadStatus.mismatch);
    }
    return EngineCheckpointRead(CheckpointReadStatus.matched, checkpoint);
  }

  /// Removes the final checkpoint plus any leftover engine temp files inside our
  /// checkpoint dir.
  Future<void> removeEngineCheckpoint() async {
    final file = File('${paths.checkpointDir.path}/active_checkpoint.json');
    try {
      if (file.existsSync()) file.deleteSync();
    } catch (_) {}
    cleanCheckpointTempFiles();
  }

  /// Deletes only files matching the engine's temp pattern inside our dir.
  void cleanCheckpointTempFiles() {
    final dir = paths.checkpointDir;
    if (!dir.existsSync()) return;
    try {
      for (final entity in dir.listSync()) {
        if (entity is File && _tempPattern.hasMatch(entity.uri.pathSegments.last)) {
          try {
            entity.deleteSync();
          } catch (_) {}
        }
      }
    } catch (_) {}
  }

  Future<OrphanCheckResult> checkForOrphan() async {
    final state = await _jobState.readActiveJob();
    if (state == null) {
      return OrphanCheckResult(status: OrphanCheckStatus.none);
    }

    // Leftover temp files are ignored; only the atomically-renamed final file is
    // read. Clean the temps so they cannot accumulate.
    cleanCheckpointTempFiles();

    final read = readEngineCheckpoint(state);
    final matched = read.status == CheckpointReadStatus.matched;
    // Byte progress is only meaningful for a byte-tracked software overwrite.
    final isOverwrite = state.methodKind == 'overwrite';
    final int? bytesDone = (matched && isOverwrite) ? read.checkpoint!.bytesDone : null;
    final int? bytesTotal = (matched && isOverwrite) ? read.checkpoint!.deviceSize : null;
    final checkpointWording = isOverwrite
        ? (bytesDone != null ? overwriteWording(bytesDone) : unreadableWording)
        : stateUnknownWording;

    OrphanCheckResult build(OrphanCheckStatus status, {String? pid}) => OrphanCheckResult(
          status: status,
          activeJobState: state,
          pid: pid,
          bytesDone: bytesDone,
          bytesTotal: bytesTotal,
          checkpointWording: checkpointWording,
        );

    if (!Platform.isLinux && !Platform.isMacOS) {
      return build(OrphanCheckStatus.interrupted);
    }

    try {
      final resultZt = Process.runSync('pgrep', ['-f', 'zt_engine']);
      final isZtRunning =
          resultZt.exitCode == 0 && (resultZt.stdout as String).trim().isNotEmpty;
      if (isZtRunning) {
        final pid =
            (resultZt.stdout as String).trim().split(RegExp(r'\s+')).firstOrNull;
        return build(OrphanCheckStatus.processActive, pid: pid);
      }
      return build(OrphanCheckStatus.interrupted);
    } catch (_) {
      return build(OrphanCheckStatus.interrupted);
    }
  }
}
