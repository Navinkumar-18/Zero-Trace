import 'dart:io';

/// Resolves the compiled zt_engine binary path. Shared by the sanitization
/// service (execution) and device discovery (B1 partition-type enrichment,
/// B1 Windows-install probe) so both always agree on which engine runs.
///
/// Order:
/// 1. ZT_ENGINE_PATH environment variable.
/// 2. Workspace target directory target/release/zt_engine (development).
/// 3. Target debug build, current folder ./zt_engine.
/// 4. Fallback to global "zt_engine" command.
Future<String> resolveEngineBinaryPath() async {
  final envPath = Platform.environment['ZT_ENGINE_PATH'];
  if (envPath != null && envPath.isNotEmpty) {
    if (await File(envPath).exists()) {
      return envPath;
    }
  }

  final devPaths = [
    '${Directory.current.path}/native/zt_engine/target/release/zt_engine',
    '${Directory.current.path}/native/zt_engine/target/debug/zt_engine',
    '${Directory.current.path}/zt_engine',
    './zt_engine',
  ];

  for (final path in devPaths) {
    if (await File(path).exists()) {
      return path;
    }
  }

  return 'zt_engine';
}
