import 'dart:convert';
import 'dart:io';

import '../core/app_paths.dart';

class ActiveJobState {
  final String jobId;
  final String deviceSerial;
  final String devicePath;
  final String deviceName;
  final String method;

  /// Method kind derived from the [SanitizationMethod] enum, not the display
  /// string: `overwrite`, `firmware`, or `unknown`. Files written before this
  /// field existed default to `unknown`.
  final String methodKind;

  /// Total device size in bytes at the time the job started. Used to validate a
  /// recovery checkpoint; `null` for files written before this field existed.
  final int? deviceSize;

  final String startedAt;
  final String status;
  final int? partitionNumber;
  final int? partitionStartSector;
  final int? partitionSizeSectors;
  final String? scope;
  final String? limitation;

  ActiveJobState({
    required this.jobId,
    required this.deviceSerial,
    required this.devicePath,
    required this.deviceName,
    required this.method,
    this.methodKind = 'unknown',
    this.deviceSize,
    required this.startedAt,
    this.status = 'running',
    this.partitionNumber,
    this.partitionStartSector,
    this.partitionSizeSectors,
    this.scope,
    this.limitation,
  });

  Map<String, dynamic> toJson() => {
        'jobId': jobId,
        'deviceSerial': deviceSerial,
        'devicePath': devicePath,
        'deviceName': deviceName,
        'method': method,
        'methodKind': methodKind,
        if (deviceSize != null) 'deviceSize': deviceSize,
        'startedAt': startedAt,
        'status': status,
        if (partitionNumber != null) 'partitionNumber': partitionNumber,
        if (partitionStartSector != null) 'partitionStartSector': partitionStartSector,
        if (partitionSizeSectors != null) 'partitionSizeSectors': partitionSizeSectors,
        if (scope != null) 'scope': scope,
        if (limitation != null) 'limitation': limitation,
      };

  factory ActiveJobState.fromJson(Map<String, dynamic> json) {
    final rawKind = json['methodKind'] as String?;
    return ActiveJobState(
      jobId: json['jobId'] as String? ?? '',
      deviceSerial: json['deviceSerial'] as String? ?? '',
      devicePath: json['devicePath'] as String? ?? '',
      deviceName: json['deviceName'] as String? ?? '',
      method: json['method'] as String? ?? '',
      methodKind: (rawKind == 'overwrite' || rawKind == 'firmware') ? rawKind! : 'unknown',
      deviceSize: (json['deviceSize'] as num?)?.toInt(),
      startedAt: json['startedAt'] as String? ?? '',
      status: json['status'] as String? ?? 'running',
      partitionNumber: json['partitionNumber'] as int?,
      partitionStartSector: (json['partitionStartSector'] as num?)?.toInt(),
      partitionSizeSectors: (json['partitionSizeSectors'] as num?)?.toInt(),
      scope: json['scope'] as String?,
      limitation: json['limitation'] as String?,
    );
  }
}

/// Persists the single in-flight (or interrupted) job marker to
/// `${AppPaths.baseDir}/active_job.json`.
///
/// The directory comes from the injected [AppPaths]; the class never resolves
/// `HOME` itself. Reads and clears never create the state directory.
class JobStateFile {
  final AppPaths paths;

  JobStateFile({required this.paths});

  Future<void> saveActiveJob(ActiveJobState state) async {
    try {
      final baseDir = paths.baseDir;
      baseDir.createSync(recursive: true);
      final file = File('${baseDir.path}/active_job.json');
      file.writeAsStringSync(jsonEncode(state.toJson()), flush: true);
    } catch (_) {}
  }

  /// Records an interrupted job state for recovery on subsequent application launches.
  Future<void> recordInterrupted(ActiveJobState state) async {
    final interrupted = ActiveJobState(
      jobId: state.jobId,
      deviceSerial: state.deviceSerial,
      devicePath: state.devicePath,
      deviceName: state.deviceName,
      method: state.method,
      methodKind: state.methodKind,
      deviceSize: state.deviceSize,
      startedAt: state.startedAt,
      status: 'interrupted',
      partitionNumber: state.partitionNumber,
      partitionStartSector: state.partitionStartSector,
      partitionSizeSectors: state.partitionSizeSectors,
      scope: state.scope,
      limitation: state.limitation,
    );
    await saveActiveJob(interrupted);
  }

  Future<ActiveJobState?> readActiveJob() async {
    try {
      final file = File('${paths.baseDir.path}/active_job.json');
      if (!file.existsSync()) return null;
      final content = file.readAsStringSync();
      if (content.trim().isEmpty) return null;
      return ActiveJobState.fromJson(jsonDecode(content));
    } catch (_) {
      return null;
    }
  }

  Future<void> clearActiveJob() async {
    try {
      final file = File('${paths.baseDir.path}/active_job.json');
      if (file.existsSync()) {
        file.deleteSync();
      }
    } catch (_) {}
  }
}
