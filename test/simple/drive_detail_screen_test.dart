import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/partition_info.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/models/untrusted_text.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/drive_detail_screen.dart';

void main() {
  const usbDevice = DeviceProfile(
    id: 'sdb',
    name: 'SanDisk Cruzer Blade',
    serialNumber: '4C530000151121111494',
    mediaType: MediaType.usbFlash,
    busType: 'USB',
    capacityBytes: 16000000000,
    isRemovable: true,
  );

  const wipedPartition = PartitionInfo(
    partitionNumber: 1,
    name: 'sdb1',
    devicePath: '/dev/sdb1',
    startSector: 2048,
    sizeSectors: 2048000,
    sizeBytes: 1048576000,
    label: UntrustedText('DATA'),
    fsType: 'vfat',
  );

  const partitionDevice = DeviceProfile(
    id: 'sdb',
    name: 'SanDisk Cruzer Blade',
    serialNumber: '4C530000151121111494',
    mediaType: MediaType.usbFlash,
    busType: 'USB',
    capacityBytes: 16000000000,
    isRemovable: true,
    partitions: [wipedPartition],
    partitionTableType: 'gpt',
  );

  SanitizationJob completedPartitionJob() => SanitizationJob(
        jobId: 'JOB-VERIFY-IN-PLACE',
        device: partitionDevice,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 50,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
        explanationText: 'Partition wipe completed',
        targetPartition: wipedPartition,
        targetPartitions: const [wipedPartition],
        status: JobStatus.completed,
        progress: 1.0,
        currentStageDescription: 'Sanitization & Audit Verification Complete.',
        wipeCompleted: true,
      );

  SanitizationCertificate passedCertificate(SanitizationJob job) =>
      SanitizationCertificate(
        certificateId: 'CERT-VERIFY-IN-PLACE',
        jobId: job.jobId,
        deviceSerial: job.device.serialNumber,
        deviceModel: job.device.name,
        mediaType: 'USB Flash',
        capacity: '16 GB',
        method: 'Single-Pass Overwrite',
        sanitizationCategory: 'CLEAR',
        standardReference: 'NIST SP 800-88 Rev. 1',
        startTime: DateTime.now().subtract(const Duration(minutes: 5)),
        endTime: DateTime.now(),
        result: 'PASSED',
        verificationSummary: 'Verified 50 samples',
        softwareVersion: '2.0.0',
        signature: 'MOCK-SIG',
        publicKeyPem: 'MOCK-KEY',
        evidence: VerificationEvidence(
          statusCode: 0,
          controllerConfirmation: 'Confirmed',
          sampleOffsets: const [0, 512, 1024],
          sampleHashes: const {0: 'hash0'},
          evidenceHash: 'evidence-hash',
          limitations: 'None',
          verifiedPassed: true,
        ),
      );

  Widget createSubject(SanitizationController controller, {String deviceId = '4C530000151121111494'}) {
    return ChangeNotifierProvider<SanitizationController>.value(
      value: controller,
      child: MaterialApp(
        home: Scaffold(
          body: DriveDetailScreen(deviceId: deviceId),
        ),
      ),
    );
  }

  Widget createRoutedSubject(SanitizationController controller, GoRouter router) {
    return ChangeNotifierProvider<SanitizationController>.value(
      value: controller,
      child: MaterialApp.router(routerConfig: router),
    );
  }

  GoRouter createDriveRouter() => GoRouter(
        initialLocation: '/drive/${partitionDevice.stableId}',
        routes: [
          GoRoute(
            path: '/',
            builder: (context, state) => const Scaffold(
              body: Center(child: Text('HOME ROUTE')),
            ),
          ),
          GoRoute(
            path: '/drive/:deviceId',
            builder: (context, state) => Scaffold(
              body: DriveDetailScreen(
                deviceId: state.pathParameters['deviceId'] ?? '',
              ),
            ),
          ),
          // The legacy verification route used to swallow the Verify action
          // after a completed wipe by redirecting to home.
          GoRoute(
            path: '/advanced/verification',
            redirect: (context, state) => '/',
          ),
        ],
      );

  testWidgets('Idle state shows Method: Decided at confirmation, Wipe enabled, Verify and Certificate disabled', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Verify info card contents
    expect(find.text('SanDisk Cruzer Blade'), findsOneWidget);
    expect(find.text('Decided at confirmation'), findsOneWidget);
    expect(find.textContaining('Flash media: Clear level only'), findsOneWidget);

    // Verify button states
    final wipeButton = tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Secure Wipe'));
    expect(wipeButton.onPressed, isNotNull);

    final verifyButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Verify'));
    expect(verifyButton.onPressed, isNull);

    final certButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Certificate'));
    expect(certButton.onPressed, isNull);
  });

  testWidgets('Running/Sanitizing state shows progress and disables all 3 buttons', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    final runningJob = SanitizationJob(
      jobId: 'JOB-TEST-1',
      device: usbDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 50,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
      explanationText: 'Sanitizing USB flash device',
      status: JobStatus.sanitizing,
      progress: 0.45,
      currentStageDescription: 'Writing zeros to sector 1420000...',
    );
    controller.setMockJob(runningJob);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Progress percentage and message should appear
    expect(find.text('45%'), findsOneWidget);
    expect(find.text('Writing zeros to sector 1420000...'), findsOneWidget);

    // Wipe button should show "Wiping..." and be disabled
    final wipeButton = tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Wiping...'));
    expect(wipeButton.onPressed, isNull);

    final verifyButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Verify'));
    expect(verifyButton.onPressed, isNull);

    final certButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Certificate'));
    expect(certButton.onPressed, isNull);
  });

  testWidgets('Completed and passed state enables Verify and Certificate, shows success badge', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    final completedJob = SanitizationJob(
      jobId: 'JOB-TEST-2',
      device: usbDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 50,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
      explanationText: 'Sanitizing USB flash device',
      status: JobStatus.completed,
      progress: 1.0,
      currentStageDescription: 'Verification passed',
    );
    controller.setMockJob(completedJob);

    final cert = SanitizationCertificate(
      certificateId: 'CERT-001',
      jobId: 'JOB-TEST-2',
      deviceSerial: '4C530000151121111494',
      deviceModel: 'SanDisk Cruzer Blade',
      mediaType: 'USB Flash',
      capacity: '16 GB',
      method: 'Single-Pass Overwrite',
      sanitizationCategory: 'CLEAR',
      standardReference: 'NIST SP 800-88 Rev. 1',
      startTime: DateTime.now().subtract(const Duration(minutes: 5)),
      endTime: DateTime.now(),
      result: 'PASSED',
      verificationSummary: 'Verified 50 samples',
      softwareVersion: '2.0.0',
      signature: 'MOCK-SIG',
      publicKeyPem: 'MOCK-KEY',
      evidence: VerificationEvidence(
        statusCode: 0,
        controllerConfirmation: 'Confirmed',
        sampleOffsets: [0, 512, 1024],
        sampleHashes: {0: 'hash0'},
        evidenceHash: 'evidence-hash',
        limitations: 'None',
        verifiedPassed: true,
      ),
    );
    controller.setMockCompletedCertificate(cert);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Success badge showing Wiped (Clear) ⚠
    expect(find.text('Wiped (Clear) ⚠'), findsOneWidget);

    // Wipe disabled, Verify enabled, Certificate enabled
    final wipeButton = tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Secure Wipe'));
    expect(wipeButton.onPressed, isNull);

    final verifyButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Verify'));
    expect(verifyButton.onPressed, isNotNull);

    final certButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Certificate'));
    expect(certButton.onPressed, isNotNull);
  });

  testWidgets('Verify after a completed partition wipe runs in place and reaches passed', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final dir = Directory.systemTemp.createTempSync('zt_verify_in_place_');
    addTearDown(() => dir.deleteSync(recursive: true));
    final controller = SanitizationController(
      appPaths: AppPaths(
        baseDir: dir,
        checkpointDir: Directory('${dir.path}/checkpoints'),
      ),
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(controller.dispose);
    controller.setMockDevices([partitionDevice]);
    controller.isSimulated = true;

    final job = completedPartitionJob();
    controller.setMockJob(job);

    final router = createDriveRouter();
    addTearDown(router.dispose);

    await tester.pumpWidget(createRoutedSubject(controller, router));
    await tester.pumpAndSettle();

    expect(find.byType(DriveDetailScreen), findsOneWidget);
    expect(find.text('HOME ROUTE'), findsNothing);

    final verifyButton = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Verify'),
    );
    expect(verifyButton.onPressed, isNotNull);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Verify'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));

    // The verify runs in place: no home/legacy route, still on drive detail.
    expect(find.byType(DriveDetailScreen), findsOneWidget);
    expect(find.text('HOME ROUTE'), findsNothing);
    expect(controller.currentJob!.status, JobStatus.verifying);

    await tester.pumpAndSettle();

    expect(find.byType(DriveDetailScreen), findsOneWidget);
    expect(find.text('HOME ROUTE'), findsNothing);
    expect(controller.currentJob!.status, JobStatus.completed);
    expect(controller.completedCertificate?.evidence.verifiedPassed, isTrue);
  });

  testWidgets('Verify still works after the Recreate filesystem prompt is dismissed with Not now', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final dir = Directory.systemTemp.createTempSync('zt_verify_after_not_now_');
    addTearDown(() => dir.deleteSync(recursive: true));
    final controller = SanitizationController(
      appPaths: AppPaths(
        baseDir: dir,
        checkpointDir: Directory('${dir.path}/checkpoints'),
      ),
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(controller.dispose);
    controller.setMockDevices([partitionDevice]);
    controller.isSimulated = true;

    final job = completedPartitionJob();
    controller.setMockJob(job);
    controller.setMockCompletedCertificate(passedCertificate(job));
    controller.setMockVerifiedFormatReceipts({
      wipedPartition.devicePath: '${dir.path}/verified_wipe.json',
    });

    final router = createDriveRouter();
    addTearDown(router.dispose);

    await tester.pumpWidget(createRoutedSubject(controller, router));
    await tester.pumpAndSettle();

    expect(find.text('Recreate filesystem?'), findsOneWidget);
    await tester.tap(find.text('Not now'));
    await tester.pump();
    expect(find.text('Recreate filesystem?'), findsNothing);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Verify'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));

    expect(find.byType(DriveDetailScreen), findsOneWidget);
    expect(find.text('HOME ROUTE'), findsNothing);
    expect(controller.currentJob!.status, JobStatus.verifying);

    await tester.pumpAndSettle();

    expect(find.byType(DriveDetailScreen), findsOneWidget);
    expect(find.text('HOME ROUTE'), findsNothing);
    expect(controller.currentJob!.status, JobStatus.completed);
    expect(controller.completedCertificate?.evidence.verifiedPassed, isTrue);
    expect(find.text('Recreate filesystem?'), findsNothing);
  });

  testWidgets('Failed in-place Verify stays on drive detail and shows the reason', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final dir = Directory.systemTemp.createTempSync('zt_verify_failure_');
    addTearDown(() => dir.deleteSync(recursive: true));
    final controller = SanitizationController(
      appPaths: AppPaths(
        baseDir: dir,
        checkpointDir: Directory('${dir.path}/checkpoints'),
      ),
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(controller.dispose);
    controller.setMockDevices([partitionDevice]);
    controller.isSimulated = true;

    final job = completedPartitionJob()..shouldSimulateFailure = true;
    controller.setMockJob(job);

    final router = createDriveRouter();
    addTearDown(router.dispose);

    await tester.pumpWidget(createRoutedSubject(controller, router));
    await tester.pumpAndSettle();

    await tester.tap(find.widgetWithText(OutlinedButton, 'Verify'));
    await tester.pumpAndSettle();

    expect(find.byType(DriveDetailScreen), findsOneWidget);
    expect(find.text('HOME ROUTE'), findsNothing);
    expect(controller.currentJob!.status, JobStatus.failed);
    expect(controller.completedCertificate?.evidence.verifiedPassed, isFalse);
    expect(
      find.textContaining('Verification failed: non-zero data detected'),
      findsOneWidget,
    );
  });

  testWidgets('Device not found state when ID does not match', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    await tester.pumpWidget(createSubject(controller, deviceId: 'NON_EXISTENT_ID'));
    await tester.pumpAndSettle();

    expect(find.text('Drive not found'), findsOneWidget);
    expect(find.text('It may have been unplugged.'), findsOneWidget);
  });

  testWidgets('Verifying state shows Verifying... button and disables all 3 buttons', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    final verifyingJob = SanitizationJob(
      jobId: 'JOB-VERIF-1',
      device: usbDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 50,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
      explanationText: 'Verifying sector erasure',
      status: JobStatus.verifying,
      progress: 0.90,
      currentStageDescription: 'Verifying sector erasure via 50-point readback sampling...',
      wipeCompleted: true,
    );
    controller.setMockJob(verifyingJob);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Verifying button text should be shown and disabled
    final wipeButton = tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Verifying...'));
    expect(wipeButton.onPressed, isNull);

    final verifyButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Verify'));
    expect(verifyButton.onPressed, isNull);

    final certButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Certificate'));
    expect(certButton.onPressed, isNull);
  });

  testWidgets('Wipe-failed state disables Verify and enables Retry Wipe with Wipe failed badge', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    final failedJob = SanitizationJob(
      jobId: 'JOB-FAIL-WIPE',
      device: usbDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 50,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
      explanationText: 'Failed during write pass',
      status: JobStatus.failed,
      progress: 0.30,
      currentStageDescription: 'I/O error during sector write pass',
      wipeCompleted: false, // FAILED DURING WIPE
    );
    controller.setMockJob(failedJob);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Badge shows "Wipe failed"
    expect(find.text('Wipe failed'), findsOneWidget);

    // Retry Wipe enabled
    final retryButton = tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Retry Wipe'));
    expect(retryButton.onPressed, isNotNull);

    // Verify button DISABLED because wipe itself did not complete
    final verifyButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Verify'));
    expect(verifyButton.onPressed, isNull);
  });

  testWidgets('Verify-failed state enables Verify and enables Retry Wipe with Verification failed badge', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);

    final failedVerifyJob = SanitizationJob(
      jobId: 'JOB-FAIL-VERIFY',
      device: usbDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 50,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
      explanationText: 'Failed during verification',
      status: JobStatus.failed,
      progress: 0.95,
      currentStageDescription: 'Verification failed: non-zero bytes detected at sector 4096',
      wipeCompleted: true, // WIPE COMPLETED, ONLY VERIFY FAILED
    );
    controller.setMockJob(failedVerifyJob);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // Badge shows "Verification failed"
    expect(find.text('Verification failed'), findsOneWidget);

    // Retry Wipe enabled
    final retryButton = tester.widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Retry Wipe'));
    expect(retryButton.onPressed, isNotNull);

    // Verify button ENABLED because wipe itself completed
    final verifyButton = tester.widget<OutlinedButton>(find.widgetWithText(OutlinedButton, 'Verify'));
    expect(verifyButton.onPressed, isNotNull);
  });

  testWidgets('Direct navigation to system drive is refused with Protected System Drive view', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    const systemDisk = DeviceProfile(
      id: 'nvme0n1',
      name: 'Samsung SSD 980 500GB',
      serialNumber: 'S649NF0R123456',
      mediaType: MediaType.nvmeSsd,
      busType: 'NVMe',
      capacityBytes: 500000000000,
      isSystemDisk: true,
      mountPoint: '/',
    );

    final controller = SanitizationController(enableAutoPolling: false);
    addTearDown(() => controller.dispose());
    controller.setMockDevices([systemDisk]);

    await tester.pumpWidget(createSubject(controller, deviceId: 'S649NF0R123456'));
    await tester.pumpAndSettle();

    // Protected System Drive refusal screen
    expect(find.text('Protected System Drive'), findsOneWidget);
    expect(find.textContaining('Direct wiping is refused'), findsOneWidget);
    expect(find.text('Back to Drives'), findsOneWidget);
    expect(find.byType(ElevatedButton), findsOneWidget); // Back button only, NO wipe button
    expect(find.text('Secure Wipe'), findsNothing);
  });

  testWidgets('Unknown-media USB device shows neutral Clear-only wording, no flash or HDD claim (Item 4)', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    const unknownUsb = DeviceProfile(
      id: 'sdc',
      name: 'Generic USB Storage Bridge',
      serialNumber: 'USB-BRIDGE-999',
      mediaType: MediaType.unknown,
      busType: 'USB',
      capacityBytes: 64000000000,
      rotationalRpm: 0,
      isRemovable: true,
    );

    final controller = SanitizationController(
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(() => controller.dispose());
    controller.setMockDevices([unknownUsb]);

    await tester.pumpWidget(createSubject(controller, deviceId: 'USB-BRIDGE-999'));
    await tester.pumpAndSettle();

    // Verify neutral Clear-only warning is present
    expect(
      find.text('Clear level only. Logical overwrite cannot guarantee firmware-level purge.'),
      findsOneWidget,
    );

    // Verify no Flash or HDD claims are made
    expect(find.textContaining('Flash media:'), findsNothing);
    expect(find.textContaining('magnetic'), findsNothing);
    expect(find.textContaining('HDD'), findsNothing);
  });

  testWidgets('canCancelJob is false during firmware sanitize (NVMe sanitize/ATA erase) and true during overwrite (Item 5)', (tester) async {
    final controller = SanitizationController(
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(() => controller.dispose());

    const nvmeDevice = DeviceProfile(
      id: 'nvme0n1',
      name: 'Samsung 980 Pro',
      serialNumber: 'NVME-PRO-1',
      mediaType: MediaType.nvmeSsd,
      busType: 'NVMe',
      capacityBytes: 500000000000,
      supportsNvmeSanitize: true,
    );

    final firmwareJob = SanitizationJob(
      jobId: 'firmware-job-1',
      device: nvmeDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 0.5,
      targetCategory: NistCategory.purge,
      recommendedMethod: SanitizationMethod.nvmeSanitize,
      standardReference: 'NIST SP 800-88 Purge',
      explanationText: 'NVMe Sanitize Crypto Erase',
      status: JobStatus.sanitizing,
      progress: 0.30,
      currentStageDescription: 'Firmware Sanitize in progress',
      startTime: DateTime.now(),
    );
    controller.setMockJob(firmwareJob);

    // Firmware sanitize cannot be cancelled
    expect(controller.canCancelJob, false);

    // Overwrite job CAN be cancelled
    final overwriteJob = SanitizationJob(
      jobId: 'overwrite-job-1',
      device: usbDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 0.5,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 Clear',
      explanationText: 'Single-Pass Zero Overwrite',
      status: JobStatus.sanitizing,
      progress: 0.30,
      currentStageDescription: 'Writing zeros',
      startTime: DateTime.now(),
    );
    controller.setMockJob(overwriteJob);

    expect(controller.canCancelJob, true);
  });

  testWidgets('SIMULATION banner is displayed on Screen 2 and in progress area (Item 5)', (tester) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = SanitizationController(
      enableAutoPolling: false,
      deferInitialDiscovery: true,
    );
    addTearDown(() => controller.dispose());
    controller.setMockDevices([usbDevice]);
    controller.isSimulated = true;

    final simJob = SanitizationJob(
      jobId: 'sim-job-1',
      device: usbDevice,
      dataSensitivity: DataSensitivity.confidential,
      deviceCondition: DeviceCondition.functional,
      disposalPath: DisposalPath.recycling,
      riskScore: 0.5,
      targetCategory: NistCategory.clear,
      recommendedMethod: SanitizationMethod.singlePassOverwrite,
      standardReference: 'NIST SP 800-88 Clear',
      explanationText: 'Simulated Wipe',
      status: JobStatus.sanitizing,
      progress: 0.5,
      currentStageDescription: 'Simulating zero write (50%)',
      startTime: DateTime.now(),
    );
    controller.setMockJob(simJob);

    await tester.pumpWidget(createSubject(controller));
    await tester.pumpAndSettle();

    // 1. Screen 2 banner
    expect(
      find.text('SIMULATION MODE — No real drives will be modified'),
      findsOneWidget,
    );

    // 2. Progress area banner
    expect(
      find.text('SIMULATION MODE'),
      findsWidgets,
    );
  });
}

