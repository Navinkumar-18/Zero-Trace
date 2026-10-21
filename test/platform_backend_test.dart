import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/platform_backend.dart';
import 'package:zero_trace/services/policy_layer.dart';

DeviceProfile _externalDisk() => const DeviceProfile(
      id: 'real_sdd',
      name: 'USB External',
      serialNumber: 'EXT123',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 64000000000,
      mountPoint: '/mnt/external',
    );

SanitizationJob _allowedJob() => SanitizationJob(
      jobId: 'JOB-PLATFORM-TEST',
      device: _externalDisk(),
      dataSensitivity: DataSensitivity.public,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.internalReuse,
      riskScore: 0.1,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST',
      explanationText: 'Test',
    );

/// Test-only "supported but capped" backend: platform is supported, yet
/// `rawWrite` is disabled — isolates the capability-flag gate from the
/// platform-support gate.
class _CappedTestBackend implements PlatformBackend {
  @override
  String get platformName => 'test-capped';

  @override
  String get backendId => 'test-capped';

  @override
  bool get isSupported => true;

  @override
  String get unsupportedReason => '';

  @override
  PlatformCapabilities get capabilities => const PlatformCapabilities(
        rawWrite: false,
        discard: true,
        secureErase: true,
        sanitize: true,
        nvmeFormat: true,
        partitionScope: true,
        liveModePossible: true,
        supportsSystemVolume: true,
      );

  @override
  Future<List<DeviceProfile>> discoverDevices({bool realMode = false}) async =>
      const <DeviceProfile>[];

  @override
  Future<String> resolveEngineBinaryPath() async => '/nonexistent/engine';
}

void main() {
  group('PlatformBackend stubs (C6)', () {
    test('windows stub refuses: unsupported with the spec reason', () async {
      final backend = WindowsPlatformBackend();
      expect(backend.platformName, 'windows');
      expect(backend.isSupported, isFalse);
      expect(backend.unsupportedReason, kPlatformUnsupportedReason);
      expect(backend.unsupportedReason, 'Not available on this platform');
      expect(await backend.discoverDevices(), isEmpty);
      await expectLater(
        backend.resolveEngineBinaryPath(),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('android stub refuses: unsupported with the spec reason', () async {
      final backend = AndroidPlatformBackend();
      expect(backend.platformName, 'android');
      expect(backend.isSupported, isFalse);
      expect(backend.unsupportedReason, kPlatformUnsupportedReason);
      expect(await backend.discoverDevices(), isEmpty);
      await expectLater(
        backend.resolveEngineBinaryPath(),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('capability flags: stubs report none, provider reports the real '
        'platform', () {
      final stubCaps = WindowsPlatformBackend().capabilities.toJson();
      expect(stubCaps.values.every((enabled) => !enabled), isTrue);

      final resolved = resolvePlatformBackend();
      expect(resolved.platformName, 'linux'); // test host is Linux in CI
      expect(resolved.isSupported, isTrue);
      expect(resolved.unsupportedReason, isEmpty);
      expect(
        resolved.capabilities.toJson().values.every((enabled) => enabled),
        isTrue,
      );
      expect(currentPlatformBackend().platformName, 'linux');
    });
  });

  group('PolicyLayer consumes platform gates (C6)', () {
    test('unsupported platform refuses every job with the spec reason', () {
      final policy = PolicyLayer(platform: WindowsPlatformBackend());
      final result = policy.validateOperation(_allowedJob());
      expect(result.isAllowed, isFalse);
      expect(result.policyMessage, kPlatformUnsupportedReason);
      expect(result.policyMessage, 'Not available on this platform');
    });

    test('linux default behavior is unchanged (platform gate is a no-op)',
        () {
      final policy = PolicyLayer(platform: LinuxPlatformBackend());
      final result = policy.validateOperation(_allowedJob());
      expect(result.isAllowed, isTrue);
    });

    test('method capability flag is consumed: raw-write method refused when '
        'the backend cannot raw-write', () {
      final policy = PolicyLayer(platform: _CappedTestBackend());
      final result = policy.validateOperation(_allowedJob());
      expect(result.isAllowed, isFalse);
      expect(result.policyMessage, contains('Not supported on this platform'));
      expect(result.policyMessage, contains('singlePassOverwrite'));
    });

    test('method capability flag is consumed: firmware method allowed when '
        'the backend reports the matching capability', () {
      final policy = PolicyLayer(platform: _CappedTestBackend());
      final job = SanitizationJob(
        jobId: 'JOB-PLATFORM-FW',
        device: _externalDisk(),
        dataSensitivity: DataSensitivity.public,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.1,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.nvmeSanitize,
        standardReference: 'NIST',
        explanationText: 'Test',
      );
      // sanitize capability is enabled on this backend; the job itself is
      // otherwise valid, so the historic checks apply unchanged.
      final result = policy.validateOperation(job);
      expect(result.isAllowed, isTrue);
    });
  });
}
