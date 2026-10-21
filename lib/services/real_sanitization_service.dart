import 'dart:convert';
import 'dart:io';

import '../core/app_paths.dart';
import '../models/device_profile.dart';
import '../models/partition_info.dart';
import '../models/sanitization_job.dart';
import 'platform_backend.dart';
import 'partition_table_service.dart';

class RealExecutionReport {
  final bool success;
  final String methodUsed;
  final List<String> commandLog;
  final String stdout;
  final String stderr;
  final int exitCode;
  final int durationMs;
  final bool dryRun;
  final int bytesWritten;
  final String ioMode;
  final String? scope;
  final int? targetPartition;
  final String? limitation;

  RealExecutionReport({
    required this.success,
    required this.methodUsed,
    required this.commandLog,
    required this.stdout,
    required this.stderr,
    required this.exitCode,
    required this.durationMs,
    required this.dryRun,
    this.bytesWritten = 0,
    this.ioMode = '',
    this.scope,
    this.targetPartition,
    this.limitation,
  });

  factory RealExecutionReport.fromJson(Map<String, dynamic> json) {
    return RealExecutionReport(
      success: json['success'] as bool? ?? false,
      methodUsed: json['method_used'] as String? ?? 'Unknown',
      commandLog: List<String>.from(json['command_log'] ?? []),
      stdout: json['stdout'] as String? ?? '',
      stderr: json['stderr'] as String? ?? '',
      exitCode: json['exit_code'] as int? ?? 0,
      durationMs: json['duration_ms'] as int? ?? 0,
      dryRun: json['dry_run'] as bool? ?? false,
      bytesWritten: (json['bytes_written'] as num? ?? 0).toInt(),
      ioMode: json['io_mode'] as String? ?? '',
      scope: json['scope'] as String?,
      targetPartition: (json['target_partition'] as num?)?.toInt(),
      limitation: json['limitation'] as String?,
    );
  }
}

class RealProgressEvent {
  final int schemaVersion;
  final String phase;
  final int bytesDone;
  final int bytesTotal;
  final double? percent;
  final double speedBytesPerSec;
  final int? etaSeconds;
  final String message;
  final bool isHeartbeat;

  RealProgressEvent({
    this.schemaVersion = 2,
    required this.phase,
    this.bytesDone = 0,
    this.bytesTotal = 0,
    this.percent,
    this.speedBytesPerSec = 0.0,
    this.etaSeconds,
    required this.message,
    this.isHeartbeat = false,
  });

  factory RealProgressEvent.fromJson(Map<String, dynamic> json) {
    final num? pct = json['percent'] as num?;
    return RealProgressEvent(
      schemaVersion: json['schema_version'] as int? ?? 2,
      phase: json['phase'] as String? ?? 'Unknown',
      bytesDone: (json['bytes_done'] as num? ?? 0).toInt(),
      bytesTotal: (json['bytes_total'] as num? ?? 0).toInt(),
      percent: pct?.toDouble(),
      speedBytesPerSec: (json['speed_bytes_per_sec'] as num? ?? 0.0).toDouble(),
      etaSeconds: json['eta_seconds'] as int?,
      message: json['message'] as String? ?? '',
      isHeartbeat: json['is_heartbeat'] as bool? ?? false,
    );
  }
}

class RealVerificationReport {
  final bool pass;
  final int sampleCount;
  final List<dynamic> samples;
  final double entropyScore;
  final String fingerprintHash;
  final int rngSeed;
  final int? totalDeviceSize;
  final int? partitionSize;
  final String? scope;
  final String? limitation;

  RealVerificationReport({
    required this.pass,
    required this.sampleCount,
    required this.samples,
    required this.entropyScore,
    required this.fingerprintHash,
    required this.rngSeed,
    this.totalDeviceSize,
    this.partitionSize,
    this.scope,
    this.limitation,
  });

  factory RealVerificationReport.fromJson(Map<String, dynamic> json) {
    return RealVerificationReport(
      pass: json['pass'] as bool? ?? false,
      sampleCount: json['sample_count'] as int? ?? 0,
      samples: json['samples'] as List<dynamic>? ?? [],
      entropyScore: (json['entropy_score'] as num? ?? 0.0).toDouble(),
      fingerprintHash: json['fingerprint_hash'] as String? ?? '',
      rngSeed: json['rng_seed'] as int? ?? 0,
      totalDeviceSize: (json['total_device_size'] as num?)?.toInt(),
      partitionSize: (json['partition_size'] as num?)?.toInt(),
      scope: json['scope'] as String?,
      limitation: json['limitation'] as String?,
    );
  }
}

class RealSanitizationService {
  RealSanitizationService({required this.paths});

  /// Dart is authoritative for the engine checkpoint directory: it exports
  /// `ZT_CHECKPOINT_DIR=<paths.checkpointDir>` on spawn and never re-derives the
  /// engine's own fallback logic.
  final AppPaths paths;

  Process? _activeProcess;

  Process? get activeProcess => _activeProcess;

  /// Resolves the compiled zt_engine binary path through the platform
  /// backend (C6) so discovery enrichment and execution always agree on
  /// which engine runs; unsupported platforms refuse with a clear reason.
  Future<String> getBinaryPath() =>
      currentPlatformBackend().resolveEngineBinaryPath();

  /// Maps the recommended sanitization method to the corresponding CLI action parameter.
  String mapMethodToCliArg(SanitizationMethod method, DeviceProfile device) {
    switch (method) {
      case SanitizationMethod.cryptographicErase:
        if (device.mediaType == MediaType.nvmeSsd) {
          return 'nvme-sanitize-crypto';
        } else if (device.mediaType == MediaType.sataSsd) {
          // Samsung 870 EVO has hardware encryption / OPAL revert
          return 'opal-revert';
        }
        return 'ata-sanitize-crypto';

      case SanitizationMethod.ataSecureErase:
        return 'ata-secure-erase';

      case SanitizationMethod.ataSanitizeBlockErase:
        return 'ata-sanitize-block';

      case SanitizationMethod.nvmeSanitize:
        return 'nvme-sanitize-block';

      case SanitizationMethod.emmcSanitize:
        return 'emmc-sanitize';

      case SanitizationMethod.singlePassOverwrite:
        return 'overwrite-zero';

      case SanitizationMethod.multiPassOverwrite:
        return 'overwrite-3pass';

      default:
        return 'overwrite-zero';
    }
  }

  /// Unified cancellation interface:
  /// Sends SIGTERM to allow engine to gracefully sync buffers, write checkpoint, and exit with code 130.
  /// Does NOT automatically SIGKILL; UI prompts the user if the drive takes time to finish writes.
  void cancelActiveProcess() {
    final proc = _activeProcess;
    if (proc == null) return;
    try {
      proc.kill(ProcessSignal.sigterm);
    } catch (_) {}
  }

  /// Force stop the process via SIGKILL upon explicit user confirmation.
  void forceKillActiveProcess() {
    final proc = _activeProcess;
    if (proc == null) return;
    try {
      proc.kill(ProcessSignal.sigkill);
    } catch (_) {}
  }

  /// Builds the exact `zt_engine sanitize ...` argument vector.
  ///
  /// Extracted so the CLI contract is unit-testable without spawning a process.
  /// The partition-table fingerprint (SHA-256 over sorted
  /// `"number:start:size\n"` lines in 512-byte sectors) is passed to EVERY
  /// engine run that has a known partition table — partition and whole-disk
  /// alike. The engine enforces it in partition mode and ignores it otherwise;
  /// Dart never silently drops it.
  List<String> buildSanitizeArgs({
    required DeviceProfile device,
    required SanitizationMethod method,
    required String confirmationToken,
    required String deviceSerial,
    PartitionInfo? targetPartition,
    bool dryRun = false,
    String? psid,
  }) {
    final cliMethod = mapMethodToCliArg(method, device);

    // Map device or partition name to a linux path (e.g. /dev/sdb or /dev/sdb1).
    final String devPath = targetPartition != null
        ? targetPartition.devicePath
        : (device.id.startsWith('real_')
            ? '/dev/${device.id.substring(5)}'
            : '/dev/null'); // safe fallback for simulator/dry run

    final List<String> args = [
      'sanitize',
      devPath,
      cliMethod,
      confirmationToken,
      deviceSerial,
    ];

    if (dryRun) {
      args.add('--dry-run');
    }
    if (psid != null && psid.isNotEmpty) {
      args.add('--psid');
      args.add(psid);
    }

    final fingerprint = device.partitionTableFingerprint ??
        PartitionTableService.computeFingerprint(device.partitions);
    final bool hasFingerprint = fingerprint.isNotEmpty;

    if (targetPartition != null) {
      args.addAll([
        '--mode',
        'partition',
        '--expected-part-num',
        targetPartition.partitionNumber.toString(),
        '--expected-start-sector',
        targetPartition.startSector.toString(),
        '--expected-size-sectors',
        targetPartition.sizeSectors.toString(),
      ]);
      if (hasFingerprint) {
        args.addAll(['--expected-table-fingerprint', fingerprint]);
      }
      if (targetPartition.partUuid != null && targetPartition.partUuid!.isNotEmpty) {
        args.addAll(['--expected-partuuid', targetPartition.partUuid!]);
      }
    } else if (hasFingerprint) {
      args.addAll(['--expected-table-fingerprint', fingerprint]);
    }

    return args;
  }

  /// Spawn zt_engine binary for real-time sanitization, updating progress via callback.
  Future<RealExecutionReport> executeSanitization({
    required DeviceProfile device,
    required SanitizationMethod method,
    required String confirmationToken,
    required String deviceSerial,
    PartitionInfo? targetPartition,
    bool dryRun = false,
    String? psid,
    required Function(RealProgressEvent) onProgress,
    required Function(String) onRawLog,
  }) async {
    final binary = await getBinaryPath();
    final List<String> args = buildSanitizeArgs(
      device: device,
      method: method,
      confirmationToken: confirmationToken,
      deviceSerial: deviceSerial,
      targetPartition: targetPartition,
      dryRun: dryRun,
      psid: psid,
    );

    onRawLog('EXECUTION: Launching $binary ${args.join(' ')}');

    final Process process = await Process.start(
      binary,
      args,
      environment: {
        ...Platform.environment,
        'ZT_CHECKPOINT_DIR': paths.checkpointDir.path,
      },
    );
    _activeProcess = process;
    RealExecutionReport? finalReport;
    final StringBuffer stderrBuffer = StringBuffer();

    try {
      // Handle stdout line-by-line
      final stdoutStream = process.stdout
          .transform(utf8.decoder)
          .transform(const LineSplitter());

      await for (final line in stdoutStream) {
        onRawLog(line);
        if (line.startsWith('PROGRESS:')) {
          try {
            final jsonStr = line.substring('PROGRESS:'.length);
            final parsed = jsonDecode(jsonStr);
            final event = RealProgressEvent.fromJson(parsed);
            onProgress(event);
          } catch (e) {
            onRawLog('ERROR parsing progress event: $e');
          }
        } else if (line.startsWith('REPORT:')) {
          try {
            final jsonStr = line.substring('REPORT:'.length);
            final parsed = jsonDecode(jsonStr);
            finalReport = RealExecutionReport.fromJson(parsed);
          } catch (e) {
            onRawLog('ERROR parsing final report: $e');
          }
        }
      }

      // Handle stderr
      process.stderr.transform(utf8.decoder).listen((data) {
        stderrBuffer.write(data);
      });

      final exitCode = await process.exitCode;
      onRawLog('EXECUTION: zt_engine exited with code $exitCode');

      if (finalReport != null) {
        return finalReport;
      }

      // Fallback if binary failed without writing report JSON
      final rawStderr = stderrBuffer.toString();
      return RealExecutionReport(
        success: exitCode == 0,
        methodUsed: mapMethodToCliArg(method, device),
        commandLog: ['$binary ${args.join(' ')}'],
        stdout: '',
        stderr: rawStderr.isNotEmpty ? rawStderr : 'Process exited with code $exitCode',
        exitCode: exitCode,
        durationMs: 0,
        dryRun: dryRun,
      );
    } finally {
      if (_activeProcess == process) {
        _activeProcess = null;
      }
    }
  }

  /// Run post-erase verification LBA sampling on physical device.
  Future<RealVerificationReport> executeVerification({
    required DeviceProfile device,
    required String method,
    required String deviceSerial,
    PartitionInfo? targetPartition,
    int sampleCount = 50,
    bool expectZeros = true,
  }) async {
    final binary = await getBinaryPath();
    final String devPath = targetPartition != null
        ? targetPartition.devicePath
        : (device.id.startsWith('real_') 
            ? '/dev/${device.id.substring(5)}' 
            : '/dev/null');
    final String targetSize = targetPartition != null
        ? targetPartition.sizeBytes.toString()
        : device.capacityBytes.toString();

    final args = [
      'verify',
      devPath,
      targetSize,
      deviceSerial,
      method,
      sampleCount.toString(),
      expectZeros.toString(),
    ];

    if (targetPartition != null) {
      args.addAll(['--total-device-size', device.capacityBytes.toString()]);
    }

    final result = await Process.run(binary, args);

    if (result.exitCode == 0 && result.stdout != null) {
      final lines = (result.stdout as String).split('\n');
      for (final line in lines) {
        if (line.startsWith('VERIFY_REPORT:')) {
          try {
            final jsonStr = line.substring('VERIFY_REPORT:'.length);
            final parsed = jsonDecode(jsonStr);
            return RealVerificationReport.fromJson(parsed);
          } catch (_) {}
        }
      }
    }

    // Fallback if verification report parsing fails
    return RealVerificationReport(
      pass: false,
      sampleCount: 0,
      samples: [],
      entropyScore: 1.0,
      fingerprintHash: 'ERROR_VERIFICATION_FAILED',
      rngSeed: 0,
    );
  }
}
