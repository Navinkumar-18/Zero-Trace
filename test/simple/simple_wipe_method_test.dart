import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/job_state_file.dart';
import 'package:zero_trace/services/orphaned_process_checker.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/confirm_wipe_dialog.dart';

void main() {
  const sataSsd = DeviceProfile(
    id: 'sda',
    name: 'Crucial MX500 500GB',
    serialNumber: '2105E445B876',
    mediaType: MediaType.sataSsd,
    busType: 'SATA',
    capacityBytes: 500000000000,
    supportsAtaSecureErase: true,
    supportsAtaSanitize: false,
    isHardwareEncrypted: false,
    isRemovable: false,
  );

  const nvmeSsd = DeviceProfile(
    id: 'nvme0n1',
    name: 'WD Black SN750 1TB',
    serialNumber: '204987123456',
    mediaType: MediaType.nvmeSsd,
    busType: 'NVMe',
    capacityBytes: 1000000000000,
    supportsNvmeSanitize: true,
    isHardwareEncrypted: false,
    isRemovable: false,
  );

  const usbFlash = DeviceProfile(
    id: 'sdb',
    name: 'SanDisk Cruzer Blade 16GB',
    serialNumber: '4C530000151121111494',
    mediaType: MediaType.usbFlash,
    busType: 'USB',
    capacityBytes: 16000000000,
    isRemovable: true,
  );

  group('Item 1: Strongest engine-supported method selection in startSimpleWipe', () {
    test('SATA drive always selects ATA Secure Erase regardless of disposal intent', () {
      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());
      controller.setMockDevices([sataSsd]);

      for (final intent in DisposalIntent.values) {
        final rec = controller.getAutoMethod(sataSsd, intent);
        expect(
          rec.method,
          equals(SanitizationMethod.ataSecureErase),
          reason: 'Intent ${intent.name} must not downgrade method from ataSecureErase',
        );
        expect(rec.method.nistCategory, equals(NistCategory.purge));
      }
    });

    test('NVMe drive always selects NVMe Sanitize regardless of disposal intent', () {
      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());
      controller.setMockDevices([nvmeSsd]);

      for (final intent in DisposalIntent.values) {
        final rec = controller.getAutoMethod(nvmeSsd, intent);
        expect(
          rec.method,
          equals(SanitizationMethod.nvmeSanitize),
          reason: 'Intent ${intent.name} must not downgrade method from nvmeSanitize',
        );
        expect(rec.method.nistCategory, equals(NistCategory.purge));
      }
    });

    test('USB flash drive selects singlePassOverwrite for internal reuse, recommends destruction for disposal/resale', () {
      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());
      controller.setMockDevices([usbFlash]);

      // Reuse myself: single-pass overwrite (Clear)
      final recReuse = controller.getAutoMethod(usbFlash, DisposalIntent.reuseMyself);
      expect(recReuse.method, equals(SanitizationMethod.singlePassOverwrite));

      // Resale or dispose: physical destruction recommended (Flash caveat)
      final recSell = controller.getAutoMethod(usbFlash, DisposalIntent.giveAwayOrSell);
      expect(recSell.method, equals(SanitizationMethod.physicalDestructionRecommended));

      final recDispose = controller.getAutoMethod(usbFlash, DisposalIntent.dispose);
      expect(recDispose.method, equals(SanitizationMethod.physicalDestructionRecommended));
    });

    test('startSimpleWipe uses auto-selected strongest method even with reuseMyself intent', () async {
      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());
      controller.setMockDevices([sataSsd]);

      // Launch simple wipe with reuseMyself (low sensitivity intent)
      // Must NOT downgrade to singlePassOverwrite
      await controller.startSimpleWipe(
        sataSsd,
        DisposalIntent.reuseMyself,
        authorization: WipeAuthorization.forTesting(deviceSerial: sataSsd.serialNumber),
      );

      final job = controller.currentJob;
      expect(job, isNotNull);
      expect(job!.effectiveMethod, equals(SanitizationMethod.ataSecureErase));
      expect(job.effectiveNistCategory, equals(NistCategory.purge));
    });
  });

  group('Item 8: Interrupted run dismiss marks drive partially wiped and preserves audit', () {
    test('acknowledgeOrphan marks target drive partially wiped and hides orphan banner', () {
      final controller = SanitizationController(enableAutoPolling: false, deferInitialDiscovery: true);
      addTearDown(() => controller.dispose());
      controller.setMockDevices([usbFlash]);

      controller.setMockOrphanResult(
        OrphanCheckResult(
          status: OrphanCheckStatus.interrupted,
          activeJobState: ActiveJobState(
            jobId: 'JOB-ORPHAN-123',
            devicePath: 'sdb',
            deviceSerial: '4C530000151121111494',
            deviceName: 'SanDisk Cruzer Blade 16GB',
            method: 'Single-Pass Overwrite',
            startedAt: '2026-10-04T12:00:00Z',
          ),
          pid: '1234',
        ),
      );

      expect(controller.orphanResult, isNotNull);

      // Dismiss the interrupted run
      controller.acknowledgeOrphan();

      // Card is hidden
      expect(controller.orphanResult, isNull);

      // Target drive is marked as potentially partially wiped
      final target = controller.devices.firstWhere((d) => d.id == 'sdb');
      expect(target.notes, contains('May be partially wiped'));
    });
  });
}
