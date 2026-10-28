//! Phase G — result-screen notice for a drive left blank after a verified
//! wipe (operator chose "Leave blank", or the automatic restore failed).

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/certificate.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/partition_info.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/models/untrusted_text.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/simple/drive_detail_screen.dart';
import 'package:zero_trace/simple/filesystem_recreation_dialog.dart';

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

  SanitizationJob completedJob(DeviceProfile device, {PartitionInfo? part}) =>
      SanitizationJob(
        jobId: 'JOB-DRIVE-BLANK',
        device: device,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 50,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
        explanationText: 'Wipe completed',
        targetPartition: part,
        targetPartitions: part == null ? const [] : [part],
        status: JobStatus.completed,
        progress: 1.0,
        currentStageDescription: 'Sanitization & Audit Verification Complete.',
        wipeCompleted: true,
      );

  SanitizationCertificate passedCertificate(SanitizationJob job) =>
      SanitizationCertificate(
        certificateId: 'CERT-DRIVE-BLANK',
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

  Widget subject(SanitizationController controller) =>
      ChangeNotifierProvider<SanitizationController>.value(
        value: controller,
        child: MaterialApp(
          home: Scaffold(
            body: DriveDetailScreen(deviceId: usbDevice.serialNumber),
          ),
        ),
      );

  Future<SanitizationController> pumpBlankDrive(
    WidgetTester tester, {
    required bool partitionScope,
    required bool restoreFilesystem,
    required bool autoRestoreFailed,
  }) async {
    tester.view.physicalSize = const Size(1920, 1080);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final dir = Directory.systemTemp.createTempSync('zt_blank_notice_');
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

    final device = partitionScope ? partitionDevice : usbDevice;
    controller.setMockDevices([device]);
    controller.isSimulated = true;

    final job = completedJob(device, part: partitionScope ? wipedPartition : null);
    controller.setMockJob(job);
    controller.setMockCompletedCertificate(passedCertificate(job));

    // Keep the receipt alive so "Restore now" can open the format dialog.
    final receiptFile = File('${dir.path}/verified_wipe.json')
      ..writeAsStringSync('{"canonical_path": "/dev/sdb"}');
    controller.setMockVerifiedFormatReceipts({
      partitionScope ? wipedPartition.devicePath : '/dev/sdb': receiptFile.path,
    });
    controller.setMockRestoreChoice(
      restoreFilesystem: restoreFilesystem,
      autoRestoreFailed: autoRestoreFailed,
    );

    await tester.pumpWidget(subject(controller));
    await tester.pumpAndSettle();
    return controller;
  }

  testWidgets('Leave blank shows the blank-drive notice and a Restore now '
      'button', (tester) async {
    final controller = await pumpBlankDrive(
      tester,
      partitionScope: true,
      restoreFilesystem: false,
      autoRestoreFailed: false,
    );

    expect(controller.driveLeftBlank, isTrue);
    expect(find.byKey(const Key('drive-blank-notice')), findsOneWidget);
    expect(
      find.text("Drive is blank and won't appear in your file manager."),
      findsOneWidget,
    );
    expect(find.text('Restore now'), findsOneWidget);
    // Partition scope: no whole-device layout warning.
    expect(find.byKey(const Key('drive-blank-layout-note')), findsNothing);
    expect(find.text('Recreate filesystem?'), findsNothing);

    // The button opens the existing dialog.
    await tester.tap(find.byKey(const Key('drive-blank-restore-now')));
    await tester.pumpAndSettle();
    expect(find.byType(FilesystemRecreationDialog), findsOneWidget);
    expect(find.text('Recreate filesystem?'), findsOneWidget);
  });

  testWidgets('a failed automatic whole-device restore shows the notice with '
      'the one-partition layout warning', (tester) async {
    final controller = await pumpBlankDrive(
      tester,
      partitionScope: false,
      restoreFilesystem: true,
      autoRestoreFailed: true,
    );

    expect(controller.restoreAfterWipe, isTrue);
    expect(controller.autoRestoreFailed, isTrue);
    expect(controller.driveLeftBlank, isTrue);
    expect(find.byKey(const Key('drive-blank-notice')), findsOneWidget);
    expect(
      find.text(
        'A restore creates a new partition table with ONE partition. '
        'The original partition layout is not restored.',
      ),
      findsOneWidget,
    );
    expect(find.text('Restore now'), findsOneWidget);
  });

  testWidgets('a successful automatic restore shows the record, not the blank '
      'notice', (tester) async {
    final controller = await pumpBlankDrive(
      tester,
      partitionScope: false,
      restoreFilesystem: true,
      autoRestoreFailed: false,
    );

    // No record was produced by the seed, but the restore was not marked as
    // failed either: the historic prompt is still offered instead of a false
    // "blank" claim.
    expect(controller.driveLeftBlank, isFalse);
    expect(find.byKey(const Key('drive-blank-notice')), findsNothing);
    expect(find.text('Recreate filesystem?'), findsOneWidget);
  });
}
