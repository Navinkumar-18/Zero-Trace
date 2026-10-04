import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/policy_layer.dart';

void main() {
  group('PolicyLayer mount point allowlist tests', () {
    test('isMountUnmountable correctly allowlists /mnt, /media, /run/media', () {
      expect(PolicyLayer.isMountUnmountable('/mnt'), isTrue);
      expect(PolicyLayer.isMountUnmountable('/mnt/usb'), isTrue);
      expect(PolicyLayer.isMountUnmountable('/media'), isTrue);
      expect(PolicyLayer.isMountUnmountable('/media/user/DRIVE'), isTrue);
      expect(PolicyLayer.isMountUnmountable('/run/media'), isTrue);
      expect(PolicyLayer.isMountUnmountable('/run/media/user/STICK'), isTrue);
    });

    test('isMountUnmountable protects root and critical system paths', () {
      expect(PolicyLayer.isMountUnmountable('/'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/boot'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/boot/efi'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/usr'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/var'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/home'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/opt'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/etc'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/data'), isFalse);
    });

    test('isMountUnmountable protects live-media paths', () {
      expect(PolicyLayer.isMountUnmountable('/run/live/medium'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/run/archiso/bootmnt'), isFalse);
      expect(PolicyLayer.isMountUnmountable('/live/image'), isFalse);
    });

    test('validateOperation refuses device with protected mount point', () {
      final policy = PolicyLayer();
      const protectedDev = DeviceProfile(
        id: 'real_sdc',
        name: 'Protected Disk',
        serialNumber: 'PROT123',
        mediaType: MediaType.sataSsd,
        busType: 'SATA',
        capacityBytes: 500000000000,
        mountPoint: '/home',
      );

      final job = SanitizationJob(
        jobId: 'JOB-TEST',
        device: protectedDev,
        dataSensitivity: DataSensitivity.public,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.1,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST',
        explanationText: 'Test',
      );

      final result = policy.validateOperation(job);
      expect(result.isAllowed, isFalse);
      expect(result.policyMessage, contains('POLICY VIOLATION'));
    });

    test('validateOperation allows device with allowlisted unmountable mount point', () {
      final policy = PolicyLayer();
      const allowedDev = DeviceProfile(
        id: 'real_sdd',
        name: 'USB External',
        serialNumber: 'EXT123',
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        capacityBytes: 64000000000,
        mountPoint: '/mnt/external',
      );

      final job = SanitizationJob(
        jobId: 'JOB-TEST-2',
        device: allowedDev,
        dataSensitivity: DataSensitivity.public,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 0.1,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST',
        explanationText: 'Test',
      );

      final result = policy.validateOperation(job);
      expect(result.isAllowed, isTrue);
    });
  });
}
