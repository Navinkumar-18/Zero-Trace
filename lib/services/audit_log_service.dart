import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';

import '../core/app_paths.dart';
import '../models/certificate.dart';

class PartitionAuditOutcome {
  final int partitionNumber;
  final int startSector;
  final int sizeSectors;
  final String status; // "COMPLETED" | "FAILED" | "INTERRUPTED" | "SKIPPED"
  final int bytesWiped;

  const PartitionAuditOutcome({
    required this.partitionNumber,
    required this.startSector,
    required this.sizeSectors,
    required this.status,
    required this.bytesWiped,
  });

  Map<String, dynamic> toJson() => {
        'bytesWiped': bytesWiped,
        'partitionNumber': partitionNumber,
        'sizeSectors': sizeSectors,
        'startSector': startSector,
        'status': status,
      };

  factory PartitionAuditOutcome.fromJson(Map<String, dynamic> json) =>
      PartitionAuditOutcome(
        partitionNumber: (json['partitionNumber'] as num?)?.toInt() ?? 0,
        startSector: (json['startSector'] as num?)?.toInt() ?? 0,
        sizeSectors: (json['sizeSectors'] as num?)?.toInt() ?? 0,
        status: json['status'] as String? ?? 'UNKNOWN',
        bytesWiped: (json['bytesWiped'] as num?)?.toInt() ?? 0,
      );
}

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

  // Enriched schema fields
  final String? deviceName;
  final String scope; // "full" or "partial" (defaults to "full")
  final String? methodClass; // null in legacy
  final String? certificateId; // null in legacy
  final String? certificateSha256; // SHA-256 of certificate/report file
  final bool isSimulated;
  final bool? verificationPassed; // null in legacy
  final List<PartitionAuditOutcome>? partitions;

  // Hash chain fields
  final String? previousHash;
  final String? entryHash;

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
    this.deviceName,
    this.scope = 'full',
    this.methodClass,
    this.certificateId,
    this.certificateSha256,
    this.isSimulated = false,
    this.verificationPassed,
    this.partitions,
    this.previousHash,
    this.entryHash,
  });

  /// Canonical JSON string for hash calculation (sorted keys, excludes previousHash & entryHash)
  String toCanonicalJson() {
    final map = SplayTreeMap<String, dynamic>();
    map['commandLog'] = commandLog;
    map['devicePath'] = devicePath;
    map['deviceSerial'] = deviceSerial;
    map['entropyScore'] = entropyScore;
    map['fingerprintHash'] = fingerprintHash;
    map['isSimulated'] = isSimulated;
    map['jobId'] = jobId;
    map['method'] = method;
    map['nistCategory'] = nistCategory;
    map['sampleCount'] = sampleCount;
    map['scope'] = scope;
    map['standardReference'] = standardReference;
    map['success'] = success;
    map['timestamp'] = timestamp;

    if (deviceName != null) map['deviceName'] = deviceName;
    if (methodClass != null) map['methodClass'] = methodClass;
    if (certificateId != null) map['certificateId'] = certificateId;
    if (certificateSha256 != null) map['certificateSha256'] = certificateSha256;
    if (verificationPassed != null) map['verificationPassed'] = verificationPassed;
    if (partitions != null) {
      map['partitions'] = partitions!.map((p) => p.toJson()).toList();
    }

    return jsonEncode(map);
  }

  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{
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
      'scope': scope,
      'isSimulated': isSimulated,
    };

    if (deviceName != null) map['deviceName'] = deviceName;
    if (methodClass != null) map['methodClass'] = methodClass;
    if (certificateId != null) map['certificateId'] = certificateId;
    if (certificateSha256 != null) map['certificateSha256'] = certificateSha256;
    if (verificationPassed != null) map['verificationPassed'] = verificationPassed;
    if (partitions != null) {
      map['partitions'] = partitions!.map((p) => p.toJson()).toList();
    }
    if (previousHash != null) map['previousHash'] = previousHash;
    if (entryHash != null) map['entryHash'] = entryHash;

    return map;
  }

  factory AuditLogEntry.fromJson(Map<String, dynamic> json) {
    final rawParts = json['partitions'] as List<dynamic>?;
    final partitions = rawParts
        ?.map((p) => PartitionAuditOutcome.fromJson(Map<String, dynamic>.from(p as Map)))
        .toList();

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
      deviceName: json['deviceName'] as String?,
      scope: json['scope'] as String? ?? 'full', // defaults to full for legacy
      methodClass: json['methodClass'] as String?, // null in legacy -> renders "—"
      certificateId: json['certificateId'] as String?, // null in legacy -> renders "—"
      certificateSha256: json['certificateSha256'] as String?,
      isSimulated: json['isSimulated'] as bool? ?? false,
      verificationPassed: json['verificationPassed'] as bool?, // null in legacy -> renders "—"
      partitions: partitions,
      previousHash: json['previousHash'] as String?,
      entryHash: json['entryHash'] as String?,
    );
  }

  AuditLogEntry copyWithChain({
    required String previousHash,
    required String entryHash,
  }) {
    return AuditLogEntry(
      timestamp: timestamp,
      jobId: jobId,
      deviceSerial: deviceSerial,
      devicePath: devicePath,
      method: method,
      standardReference: standardReference,
      nistCategory: nistCategory,
      success: success,
      fingerprintHash: fingerprintHash,
      entropyScore: entropyScore,
      sampleCount: sampleCount,
      commandLog: commandLog,
      deviceName: deviceName,
      scope: scope,
      methodClass: methodClass,
      certificateId: certificateId,
      certificateSha256: certificateSha256,
      isSimulated: isSimulated,
      verificationPassed: verificationPassed,
      partitions: partitions,
      previousHash: previousHash,
      entryHash: entryHash,
    );
  }
}

enum ChainIntegrityStatus {
  valid,
  validWithLegacy,
  broken,
}

class ChainIntegrityResult {
  final ChainIntegrityStatus status;
  final int totalEntries;
  final int legacyCount;
  final int? brokenLineNumber;
  final String? failureReason;

  const ChainIntegrityResult({
    required this.status,
    required this.totalEntries,
    this.legacyCount = 0,
    this.brokenLineNumber,
    this.failureReason,
  });

  String get summary {
    switch (status) {
      case ChainIntegrityStatus.valid:
        return 'Chain integrity verified ($totalEntries chained entries valid)';
      case ChainIntegrityStatus.validWithLegacy:
        return 'Chain integrity verified ($legacyCount legacy unchained entries tolerated)';
      case ChainIntegrityStatus.broken:
        return 'Integrity check failed at entry line $brokenLineNumber: $failureReason';
    }
  }
}

class AuditLogService {
  static const String genesisHash =
      '0000000000000000000000000000000000000000000000000000000000000000';

  final AppPaths paths;

  AuditLogService({required this.paths});

  File get _logFile => paths.auditLogFile;

  Directory get _certificatesDir {
    final dir = paths.certificatesDir;
    if (!dir.existsSync()) dir.createSync(recursive: true);
    return dir;
  }

  Directory get _reportsDir {
    final dir = paths.reportsDir;
    if (!dir.existsSync()) dir.createSync(recursive: true);
    return dir;
  }

  /// Calculates entryHash = SHA-256(previousHash || canonicalJson)
  static String calculateEntryHash(String previousHash, String canonicalJson) {
    final input = utf8.encode('$previousHash$canonicalJson');
    return sha256.convert(input).toString();
  }

  /// Atomically writes content to target file with mode 0600 on POSIX platforms.
  Future<File> _writeAtomic(String targetPath, String content) async {
    final tmpFile = File('$targetPath.tmp.${DateTime.now().microsecondsSinceEpoch}');
    tmpFile.writeAsStringSync(content, flush: true);

    if (Platform.isLinux || Platform.isMacOS) {
      try {
        Process.runSync('chmod', ['600', tmpFile.path]);
      } catch (_) {}
    }

    return tmpFile.renameSync(targetPath);
  }

  /// Persists certificate to certificates/ directory with mode 0600 and returns (File, SHA-256).
  Future<(File, String)> saveCertificate(SanitizationCertificate cert) async {
    final targetPath = '${_certificatesDir.path}/${cert.certificateId}.json';
    final content = jsonEncode(cert.toJson());
    final file = await _writeAtomic(targetPath, content);
    final fileSha = sha256.convert(file.readAsBytesSync()).toString();
    return (file, fileSha);
  }

  /// Persists failure report to reports/ directory with mode 0600 and returns (File, SHA-256).
  Future<(File, String)> saveFailureReport(SanitizationCertificate report) async {
    final targetPath = '${_reportsDir.path}/${report.certificateId}.json';
    final content = jsonEncode(report.toJson());
    final file = await _writeAtomic(targetPath, content);
    final fileSha = sha256.convert(file.readAsBytesSync()).toString();
    return (file, fileSha);
  }

  /// Loads certificate or failure report by ID from disk.
  Future<SanitizationCertificate?> getCertificateById(String certificateId) async {
    try {
      final certFile = File('${_certificatesDir.path}/$certificateId.json');
      if (certFile.existsSync()) {
        final json = jsonDecode(certFile.readAsStringSync());
        return SanitizationCertificate.fromJson(Map<String, dynamic>.from(json));
      }
      final reportFile = File('${_reportsDir.path}/$certificateId.json');
      if (reportFile.existsSync()) {
        final json = jsonDecode(reportFile.readAsStringSync());
        return SanitizationCertificate.fromJson(Map<String, dynamic>.from(json));
      }
    } catch (_) {}
    return null;
  }

  /// Appends a new sanitization operation entry to the hash-chained audit log.
  Future<AuditLogEntry> appendEntry(AuditLogEntry entry) async {
    try {
      paths.baseDir.createSync(recursive: true);
      final file = _logFile;

      // Find the last chained entry's hash to determine previousHash
      String prevHash = genesisHash;
      if (file.existsSync()) {
        final lines = file.readAsLinesSync();
        for (int i = lines.length - 1; i >= 0; i--) {
          final line = lines[i].trim();
          if (line.isEmpty) continue;
          try {
            final parsed = jsonDecode(line);
            if (parsed is Map && parsed['entryHash'] != null) {
              prevHash = parsed['entryHash'] as String;
              break;
            }
          } catch (_) {
            // Torn or legacy line, continue looking back
          }
        }
      }

      final canonicalJson = entry.toCanonicalJson();
      final currentEntryHash = calculateEntryHash(prevHash, canonicalJson);

      final chainedEntry = entry.copyWithChain(
        previousHash: prevHash,
        entryHash: currentEntryHash,
      );

      final line = '${jsonEncode(chainedEntry.toJson())}\n';
      final raf = file.openSync(mode: FileMode.append);
      try {
        raf.lockSync(FileLock.exclusive);
        raf.writeStringSync(line);
        raf.flushSync();
      } finally {
        raf.unlockSync();
        raf.closeSync();
      }

      if (Platform.isLinux || Platform.isMacOS) {
        try {
          Process.runSync('chmod', ['600', file.path]);
        } catch (_) {}
      }

      return chainedEntry;
    } catch (_) {
      return entry;
    }
  }

  /// Verifies integrity of the audit log hash chain.
  /// Tolerates legacy unchained lines at the head and a torn last line.
  Future<ChainIntegrityResult> verifyChainIntegrity() async {
    final file = _logFile;
    if (!file.existsSync()) {
      return const ChainIntegrityResult(
        status: ChainIntegrityStatus.valid,
        totalEntries: 0,
      );
    }

    final rawLines = file.readAsLinesSync();
    if (rawLines.isEmpty) {
      return const ChainIntegrityResult(
        status: ChainIntegrityStatus.valid,
        totalEntries: 0,
      );
    }

    String expectedPrevHash = genesisHash;
    int legacyCount = 0;
    int chainedCount = 0;
    int totalValid = 0;

    for (int i = 0; i < rawLines.length; i++) {
      final lineNum = i + 1;
      final line = rawLines[i].trim();
      if (line.isEmpty) continue;

      Map<String, dynamic> json;
      try {
        json = Map<String, dynamic>.from(jsonDecode(line) as Map);
      } catch (e) {
        // Tolerates torn last line
        if (i == rawLines.length - 1) {
          break;
        }
        return ChainIntegrityResult(
          status: ChainIntegrityStatus.broken,
          totalEntries: totalValid,
          brokenLineNumber: lineNum,
          failureReason: 'Malformed JSON on non-terminal line',
        );
      }

      final entryHash = json['entryHash'] as String?;
      final previousHash = json['previousHash'] as String?;

      if (entryHash == null || previousHash == null) {
        // Legacy line
        if (chainedCount > 0) {
          return ChainIntegrityResult(
            status: ChainIntegrityStatus.broken,
            totalEntries: totalValid,
            brokenLineNumber: lineNum,
            failureReason: 'Legacy unchained entry found after chained entries',
          );
        }
        legacyCount++;
        totalValid++;
        continue;
      }

      // Chained entry verification
      if (previousHash != expectedPrevHash) {
        return ChainIntegrityResult(
          status: ChainIntegrityStatus.broken,
          totalEntries: totalValid,
          brokenLineNumber: lineNum,
          failureReason:
              'previousHash mismatch: expected $expectedPrevHash, found $previousHash',
        );
      }

      final entry = AuditLogEntry.fromJson(json);
      final computed = calculateEntryHash(previousHash, entry.toCanonicalJson());
      if (computed != entryHash) {
        return ChainIntegrityResult(
          status: ChainIntegrityStatus.broken,
          totalEntries: totalValid,
          brokenLineNumber: lineNum,
          failureReason:
              'entryHash mismatch: computed $computed does not match recorded $entryHash',
        );
      }

      expectedPrevHash = entryHash;
      chainedCount++;
      totalValid++;
    }

    if (legacyCount > 0) {
      return ChainIntegrityResult(
        status: ChainIntegrityStatus.validWithLegacy,
        totalEntries: totalValid,
        legacyCount: legacyCount,
      );
    }

    return ChainIntegrityResult(
      status: ChainIntegrityStatus.valid,
      totalEntries: totalValid,
    );
  }

  /// Retrieve recorded audit logs, optionally capped to the latest [limit] entries.
  Future<List<AuditLogEntry>> getEntries({
    int? limit,
    bool includeSimulated = false,
  }) async {
    try {
      final file = _logFile;
      if (!file.existsSync()) return [];

      final lines = file.readAsLinesSync();
      final entries = <AuditLogEntry>[];

      for (int i = 0; i < lines.length; i++) {
        final line = lines[i].trim();
        if (line.isEmpty) continue;
        try {
          final parsed = jsonDecode(line);
          if (parsed is Map) {
            final entry = AuditLogEntry.fromJson(Map<String, dynamic>.from(parsed));
            if (!includeSimulated && entry.isSimulated) {
              continue;
            }
            entries.add(entry);
          }
        } catch (_) {
          // Torn line tolerated
        }
      }

      // Return reverse chronological (newest first)
      final reversed = entries.reversed.toList();
      if (limit != null && reversed.length > limit) {
        return reversed.take(limit).toList();
      }
      return reversed;
    } catch (_) {
      return [];
    }
  }

  /// Find audit log entry by job ID.
  Future<AuditLogEntry?> getEntryByJobId(String jobId) async {
    final entries = await getEntries(includeSimulated: true);
    for (final entry in entries) {
      if (entry.jobId == jobId) {
        return entry;
      }
    }
    return null;
  }
}
