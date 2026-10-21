import 'dart:io';

import '../models/device_profile.dart';
import 'device_intelligence_service.dart';
import 'engine_binary_resolver.dart' as engine;

/// UI-facing reason shown for every action the current platform cannot run.
/// The spec requires this exact string: unsupported actions are *disabled
/// with a visible reason*, never silently hidden.
const String kPlatformUnsupportedReason = 'Not available on this platform';

/// Mirrors the Rust engine's `BackendCapabilities` flags
/// (zt_engine `src/backend.rs`). The UI and `PolicyLayer` consume these
/// flags to enable or disable actions — backends themselves never make
/// safety decisions (they only report facts).
class PlatformCapabilities {
  final bool rawWrite;
  final bool discard;
  final bool secureErase;
  final bool sanitize;
  final bool nvmeFormat;
  final bool partitionScope;
  final bool liveModePossible;
  final bool supportsSystemVolume;

  const PlatformCapabilities({
    required this.rawWrite,
    required this.discard,
    required this.secureErase,
    required this.sanitize,
    required this.nvmeFormat,
    required this.partitionScope,
    required this.liveModePossible,
    required this.supportsSystemVolume,
  });

  /// All capabilities enabled — mirrors `BackendCapabilities::full()`,
  /// what the Linux backend (the only real backend) reports.
  static const PlatformCapabilities all = PlatformCapabilities(
    rawWrite: true,
    discard: true,
    secureErase: true,
    sanitize: true,
    nvmeFormat: true,
    partitionScope: true,
    liveModePossible: true,
    supportsSystemVolume: true,
  );

  /// No capabilities — mirrors `BackendCapabilities::unsupported()`, what
  /// the Windows/Android compile-only stubs report.
  static const PlatformCapabilities none = PlatformCapabilities(
    rawWrite: false,
    discard: false,
    secureErase: false,
    sanitize: false,
    nvmeFormat: false,
    partitionScope: false,
    liveModePossible: false,
    supportsSystemVolume: false,
  );

  /// Same keys as the Rust `BackendCapabilities` JSON (snake_case).
  Map<String, bool> toJson() => <String, bool>{
        'raw_write': rawWrite,
        'discard': discard,
        'secure_erase': secureErase,
        'sanitize': sanitize,
        'nvme_format': nvmeFormat,
        'partition_scope': partitionScope,
        'live_mode_possible': liveModePossible,
        'supports_system_volume': supportsSystemVolume,
      };
}

/// One UI/policy-facing platform backend. Exactly one implementation is
/// active per platform (chosen by [resolvePlatformBackend]); the Linux one
/// delegates to the existing discovery and engine-binary code paths, the
/// Windows/Android ones are unsupported stubs.
abstract class PlatformBackend {
  /// Machine-readable platform id: "linux", "windows", "android", "unknown".
  String get platformName;

  /// Engine backend id (mirrors Rust `BlockBackend::id()`): "linux",
  /// "windows", "android", "unknown-platform". Signed into v4 certificates.
  String get backendId;

  /// True only where a real engine backend exists (Linux today).
  bool get isSupported;

  /// Empty when supported, [kPlatformUnsupportedReason] when not.
  String get unsupportedReason;

  PlatformCapabilities get capabilities;

  /// Device discovery for this platform. Stubs return an empty list —
  /// with no devices there is nothing the UI could act on, and the reason
  /// is surfaced through [isSupported]/[unsupportedReason].
  Future<List<DeviceProfile>> discoverDevices({bool realMode = false});

  /// Engine binary resolution for this platform. Stubs throw
  /// [UnsupportedError] — a stub can never launch a destructive command.
  Future<String> resolveEngineBinaryPath();
}

/// Linux — the only real backend. Delegates to the existing
/// `lsblk`-based discovery and the shared engine-binary resolver, so
/// behavior is byte-identical to the pre-abstraction code paths.
class LinuxPlatformBackend implements PlatformBackend {
  LinuxPlatformBackend({DeviceIntelligenceService? discovery})
      : _discovery = discovery ?? DeviceIntelligenceService();

  final DeviceIntelligenceService _discovery;

  @override
  String get platformName => 'linux';

  @override
  String get backendId => 'linux';

  @override
  bool get isSupported => true;

  @override
  String get unsupportedReason => '';

  @override
  PlatformCapabilities get capabilities => PlatformCapabilities.all;

  @override
  Future<List<DeviceProfile>> discoverDevices({bool realMode = false}) =>
      _discovery.discoverDevices(realMode: realMode);

  @override
  Future<String> resolveEngineBinaryPath() =>
      engine.resolveEngineBinaryPath();
}

/// Shared implementation for platforms without a real backend
/// (Windows, Android, and anything unknown). Reports the platform id,
/// `isSupported == false` with the spec reason, and zero capabilities.
class _UnsupportedPlatformBackend implements PlatformBackend {
  _UnsupportedPlatformBackend(this.backendId, this.platformName);

  @override
  final String backendId;

  @override
  final String platformName;

  @override
  bool get isSupported => false;

  @override
  String get unsupportedReason => kPlatformUnsupportedReason;

  @override
  PlatformCapabilities get capabilities => PlatformCapabilities.none;

  @override
  Future<List<DeviceProfile>> discoverDevices({bool realMode = false}) async =>
      const <DeviceProfile>[];

  @override
  Future<String> resolveEngineBinaryPath() async => throw UnsupportedError(
      '$kPlatformUnsupportedReason (no $platformName engine backend)');
}

/// Windows — compile-only stub (mirrors Rust `windows_backend()`).
class WindowsPlatformBackend extends _UnsupportedPlatformBackend {
  WindowsPlatformBackend() : super('windows', 'windows');
}

/// Android — compile-only stub (mirrors Rust `android_backend()`).
class AndroidPlatformBackend extends _UnsupportedPlatformBackend {
  AndroidPlatformBackend() : super('android', 'android');
}

/// Picks the backend from `Platform.isX` — the Dart mirror of the Rust
/// `current_backend()` selector.
PlatformBackend resolvePlatformBackend() {
  if (Platform.isLinux) return LinuxPlatformBackend();
  if (Platform.isWindows) return WindowsPlatformBackend();
  if (Platform.isAndroid) return AndroidPlatformBackend();
  return _UnsupportedPlatformBackend('unknown-platform', 'unknown');
}

PlatformBackend? _memoized;

/// App-wide shared instance for UI and `PolicyLayer` (which only need the
/// platform id and capability flags). Services that run discovery pass
/// their own `DeviceIntelligenceService` into [LinuxPlatformBackend]
/// instead, so scan state stays shared.
PlatformBackend currentPlatformBackend() =>
    _memoized ??= resolvePlatformBackend();
