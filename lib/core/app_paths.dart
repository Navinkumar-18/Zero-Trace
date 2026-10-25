import 'dart:io';

/// Single source of truth for on-disk application state locations.
///
/// This is the ONLY place that reads `HOME` / `USERPROFILE` / XDG-style
/// environment variables. Every other component receives an [AppPaths] (or a
/// directory derived from it) and must not resolve paths itself.
class AppPaths {
  /// App-owned state directory: audit log, certificates, reports and the
  /// active-job marker. `ZT_DATA_DIR` overrides the default `$HOME/.zero_trace`.
  final Directory baseDir;

  /// Directory the native engine writes its in-flight checkpoint into.
  ///
  /// Dart is authoritative for this path: it exports `ZT_CHECKPOINT_DIR` with
  /// this value when spawning the engine, so both sides agree without Dart
  /// re-deriving the engine's own fallback logic. `ZT_CHECKPOINT_DIR` overrides
  /// the default `${baseDir}/checkpoints`.
  final Directory checkpointDir;

  const AppPaths({required this.baseDir, required this.checkpointDir});

  /// Resolves the real, production locations from the process environment.
  factory AppPaths.production() {
    final env = Platform.environment;
    final home = env['HOME'] ?? env['USERPROFILE'] ?? '/root';

    final dataOverride = env['ZT_DATA_DIR'];
    final baseDir = (dataOverride != null && dataOverride.trim().isNotEmpty)
        ? Directory(dataOverride)
        : Directory('$home/.zero_trace');

    final checkpointOverride = env['ZT_CHECKPOINT_DIR'];
    final checkpointDir =
        (checkpointOverride != null && checkpointOverride.trim().isNotEmpty)
        ? Directory(checkpointOverride)
        : Directory('${baseDir.path}/checkpoints');

    return AppPaths(baseDir: baseDir, checkpointDir: checkpointDir);
  }

  File get auditLogFile => File('${baseDir.path}/audit_log.jsonl');

  File get activeJobFile => File('${baseDir.path}/active_job.json');

  Directory get certificatesDir => Directory('${baseDir.path}/certificates');

  Directory get reportsDir => Directory('${baseDir.path}/reports');

  /// Phase F: one-shot receipt proving the target was just wiped and verified,
  /// written by `zt_engine verify` for the separate `format` process. Kept in
  /// the engine checkpoint directory so it shares the same restricted state
  /// root and disappears with the job.
  File verifiedWipeReceiptFile(String jobId, {int? partitionNumber}) => File(
    '${checkpointDir.path}/verified_wipe_$jobId'
    '${partitionNumber == null ? '' : '_p$partitionNumber'}.json',
  );

  /// Phase F: remembered filesystem-recreation choices (last fs/label the
  /// operator confirmed). The "recreate" action itself always defaults to OFF.
  File get filesystemRecreationPreferenceFile =>
      File('${baseDir.path}/filesystem_recreation_preference.json');

  /// Creates the base, certificates and reports directories if missing.
  void ensureDirectories() {
    baseDir.createSync(recursive: true);
    certificatesDir.createSync(recursive: true);
    reportsDir.createSync(recursive: true);
  }
}
