import 'dart:convert';
import 'dart:io';

class AuditLogEntry {
  final String timestamp;
  final String jobId;
  final String deviceSerial;
  final String devicePath;
  final String method;
  final String standardReference;
  final String nistCategory;
  final bool success;
  final String fingerprintHash;
  final double entropyScore;
  final int sampleCount;
  final List<String> commandLog;

  AuditLogEntry({
    required this.timestamp,
    required this.jobId,
    required this.deviceSerial,
    required this.devicePath,
    required this.method,
    required this.standardReference,
    required this.nistCategory,
    required this.success,
    required this.fingerprintHash,
    required this.entropyScore,
    required this.sampleCount,
    required this.commandLog,
  });

  Map<String, dynamic> toJson() => {
        'timestamp': timestamp,
        'jobId': jobId,
        'deviceSerial': deviceSerial,
        'devicePath': devicePath,
        'method': method,
        'standardReference': standardReference,
        'nistCategory': nistCategory,
        'success': success,
        'fingerprintHash': fingerprintHash,
        'entropyScore': entropyScore,
        'sampleCount': sampleCount,
        'commandLog': commandLog,
      };

  factory AuditLogEntry.fromJson(Map<String, dynamic> json) {
    return AuditLogEntry(
      timestamp: json['timestamp'] as String? ?? '',
      jobId: json['jobId'] as String? ?? '',
      deviceSerial: json['deviceSerial'] as String? ?? '',
      devicePath: json['devicePath'] as String? ?? '',
      method: json['method'] as String? ?? '',
      standardReference: json['standardReference'] as String? ?? '',
      nistCategory: json['nistCategory'] as String? ?? '',
      success: json['success'] as bool? ?? false,
      fingerprintHash: json['fingerprintHash'] as String? ?? '',
      entropyScore: (json['entropyScore'] as num? ?? 0.0).toDouble(),
      sampleCount: json['sampleCount'] as int? ?? 0,
      commandLog: List<String>.from(json['commandLog'] ?? []),
    );
  }
}

class AuditLogService {
  File _getLogFile() {
    final home = Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'] ?? '/root';
    final directory = Directory('$home/.zero_trace');
    if (!directory.existsSync()) {
      directory.createSync(recursive: true);
    }
    return File('${directory.path}/audit_log.jsonl');
  }

  /// Append a new sanitization operation report to the local audit log.
  Future<void> appendEntry(AuditLogEntry entry) async {
    try {
      final file = _getLogFile();
      final line = '${jsonEncode(entry.toJson())}\n';
      await file.writeAsString(line, mode: FileMode.append, flush: true);
    } catch (_) {
      // In web/sandboxed modes, this might fail, fail silently or print.
    }
  }

  /// Retrieve all recorded sanitization audit logs.
  Future<List<AuditLogEntry>> getEntries() async {
    try {
      final file = _getLogFile();
      if (!await file.exists()) {
        return [];
      }
      final lines = await file.readAsLines();
      return lines
          .map((line) {
            try {
              if (line.trim().isEmpty) return null;
              final parsed = jsonDecode(line);
              return AuditLogEntry.fromJson(parsed);
            } catch (_) {
              return null;
            }
          })
          .whereType<AuditLogEntry>()
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Find audit log entry by job ID.
  Future<AuditLogEntry?> getEntryByJobId(String jobId) async {
    final entries = await getEntries();
    for (final entry in entries) {
      if (entry.jobId == jobId) {
        return entry;
      }
    }
    return null;
  }
}
