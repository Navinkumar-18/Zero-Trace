import 'dart:convert';
import 'dart:io';

class ActiveJobState {
  final String jobId;
  final String deviceSerial;
  final String devicePath;
  final String deviceName;
  final String method;
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
        'startedAt': startedAt,
        'status': status,
        if (partitionNumber != null) 'partitionNumber': partitionNumber,
        if (partitionStartSector != null) 'partitionStartSector': partitionStartSector,
        if (partitionSizeSectors != null) 'partitionSizeSectors': partitionSizeSectors,
        if (scope != null) 'scope': scope,
        if (limitation != null) 'limitation': limitation,
      };

  factory ActiveJobState.fromJson(Map<String, dynamic> json) {
    return ActiveJobState(
      jobId: json['jobId'] as String? ?? '',
      deviceSerial: json['deviceSerial'] as String? ?? '',
      devicePath: json['devicePath'] as String? ?? '',
      deviceName: json['deviceName'] as String? ?? '',
      method: json['method'] as String? ?? '',
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

class JobStateFile {
  static File _getFile() {
    final home = Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'] ?? '/root';
    final directory = Directory('$home/.zero_trace');
    if (!directory.existsSync()) {
      directory.createSync(recursive: true);
    }
    return File('${directory.path}/active_job.json');
  }

  static Future<void> saveActiveJob(ActiveJobState state) async {
    try {
      final file = _getFile();
      file.writeAsStringSync(jsonEncode(state.toJson()), flush: true);
    } catch (_) {}
  }

  /// Records an interrupted job state for recovery on subsequent application launches.
  static Future<void> recordInterrupted(ActiveJobState state) async {
    final interrupted = ActiveJobState(
      jobId: state.jobId,
      deviceSerial: state.deviceSerial,
      devicePath: state.devicePath,
      deviceName: state.deviceName,
      method: state.method,
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

  static Future<ActiveJobState?> readActiveJob() async {
    try {
      final file = _getFile();
      if (!file.existsSync()) return null;
      final content = file.readAsStringSync();
      if (content.trim().isEmpty) return null;
      return ActiveJobState.fromJson(jsonDecode(content));
    } catch (_) {
      return null;
    }
  }

  static Future<void> clearActiveJob() async {
    try {
      final file = _getFile();
      if (file.existsSync()) {
        file.deleteSync();
      }
    } catch (_) {}
  }
}
