import 'dart:convert';
import 'dart:io';

import '../core/app_paths.dart';
import 'job_state_file.dart';

enum OrphanCheckStatus {
  none,
  processActive,
  interrupted,
}

class EngineCheckpoint {
  final String serial;
  final int bytesDone;
  final int bytesTotal;
  final int timestamp;

  EngineCheckpoint({
    required this.serial,
    required this.bytesDone,
    required this.bytesTotal,
    required this.timestamp,
  });

  factory EngineCheckpoint.fromJson(Map<String, dynamic> json) {
    return EngineCheckpoint(
      serial: json['serial'] as String? ?? '',
      bytesDone: (json['bytes_done'] as num? ?? 0).toInt(),
      bytesTotal: (json['bytes_total'] as num? ?? 0).toInt(),
      timestamp: (json['timestamp'] as num? ?? 0).toInt(),
    );
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

class OrphanedProcessChecker {
  final AppPaths paths;
  final JobStateFile _jobState;

  OrphanedProcessChecker({required this.paths})
      : _jobState = JobStateFile(paths: paths);

  static String sanitizeSerial(String serial) {
    return serial.replaceAll(RegExp(r'[^a-zA-Z0-9_\-]'), '');
  }

  /// Prefer engine-side checkpoint file `/tmp/zt_checkpoint_<serial>.json` to JobStateFile.
  /// NOTE: the engine checkpoint path is a separate task; left unchanged for now.
  Future<EngineCheckpoint?> readEngineCheckpoint(String serial) async {
    final sanitized = sanitizeSerial(serial);
    if (sanitized.isEmpty) return null;
    final file = File('/tmp/zt_checkpoint_$sanitized.json');
    if (file.existsSync()) {
      try {
        final content = file.readAsStringSync();
        final json = jsonDecode(content) as Map<String, dynamic>;
        return EngineCheckpoint.fromJson(json);
      } catch (_) {}
    }
    return null;
  }

  Future<void> removeEngineCheckpoint(String serial) async {
    final sanitized = sanitizeSerial(serial);
    if (sanitized.isEmpty) return;
    final file = File('/tmp/zt_checkpoint_$sanitized.json');
    if (file.existsSync()) {
      try {
        file.deleteSync();
      } catch (_) {}
    }
  }

  Future<OrphanCheckResult> checkForOrphan() async {
    final state = await _jobState.readActiveJob();
    if (state == null) {
      return OrphanCheckResult(status: OrphanCheckStatus.none);
    }

    // Prefer engine-side checkpoint for exact bytes written
    final checkpoint = await readEngineCheckpoint(state.deviceSerial);
    final bytesDone = checkpoint?.bytesDone;
    final bytesTotal = checkpoint?.bytesTotal;

    final gbDone = bytesDone != null ? (bytesDone / 1e9).toStringAsFixed(1) : '0';
    // Exact requested wording: "about X GB reported written at the last check, not verified"
    final checkpointWording = 'about $gbDone GB reported written at the last check, not verified';

    if (!Platform.isLinux && !Platform.isMacOS) {
      return OrphanCheckResult(
        status: OrphanCheckStatus.interrupted,
        activeJobState: state,
        bytesDone: bytesDone,
        bytesTotal: bytesTotal,
        checkpointWording: checkpointWording,
      );
    }

    try {
      // Check if native zt_engine process is alive (no more dd!)
      final resultZt = Process.runSync('pgrep', ['-f', 'zt_engine']);
      final isZtRunning = resultZt.exitCode == 0 && (resultZt.stdout as String).trim().isNotEmpty;

      if (isZtRunning) {
        final pid = (resultZt.stdout as String).trim().split(RegExp(r'\s+')).firstOrNull;
        return OrphanCheckResult(
          status: OrphanCheckStatus.processActive,
          activeJobState: state,
          pid: pid,
          bytesDone: bytesDone,
          bytesTotal: bytesTotal,
          checkpointWording: checkpointWording,
        );
      } else {
        return OrphanCheckResult(
          status: OrphanCheckStatus.interrupted,
          activeJobState: state,
          bytesDone: bytesDone,
          bytesTotal: bytesTotal,
          checkpointWording: checkpointWording,
        );
      }
    } catch (_) {
      return OrphanCheckResult(
        status: OrphanCheckStatus.interrupted,
        activeJobState: state,
        bytesDone: bytesDone,
        bytesTotal: bytesTotal,
        checkpointWording: checkpointWording,
      );
    }
  }
}
