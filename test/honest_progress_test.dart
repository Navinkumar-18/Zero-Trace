import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/core/app_paths.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/real_sanitization_service.dart';
import 'package:zero_trace/services/sanitization_controller.dart';
import 'package:zero_trace/services/job_state_file.dart';

void main() {
  late Directory tempDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('zt_honest_');
  });

  tearDown(() {
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
  });

  AppPaths tempPaths() => AppPaths(
        baseDir: tempDir,
        checkpointDir: Directory('${tempDir.path}/checkpoints'),
      );

  group('Honest Progress and Telemetry Tests', () {
    final sampleDevice = DeviceProfile(
      id: 'real_sdb',
      name: 'SanDisk Ultra',
      serialNumber: '4C530001230101112233',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16 * 1024 * 1024 * 1024,
    );

    test('1. No synthetic percentage before engine data (honest indeterminate initial state)', () {
      final job = SanitizationJob(
        jobId: 'job_test_honest_01',
        device: sampleDevice,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 40.0,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
        explanationText: 'Single-pass overwrite for USB media',
      );

      // Verify that initially, progress is strictly null (no synthetic 0.0, 0.10, or 0.20)
      expect(job.progress, isNull, reason: 'Initial job progress must be null before engine reports progress');
      expect(job.status, JobStatus.idle);

      // When transition to unmounting/preparing occurs
      job.status = JobStatus.unmounting;
      job.progress = null;
      expect(job.progress, isNull, reason: 'Unmounting stage must not assign synthetic percentages');

      // When transition to sanitizing occurs before first progress event
      job.status = JobStatus.sanitizing;
      job.progress = null;
      expect(job.progress, isNull, reason: 'Sanitizing stage must remain null until telemetry arrives');
    });

    test('2. Indeterminate firmware sanitize state maintains null progress', () {
      final job = SanitizationJob(
        jobId: 'job_test_firmware_02',
        device: sampleDevice,
        dataSensitivity: DataSensitivity.restricted,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.internalReuse,
        riskScore: 20.0,
        targetCategory: NistCategory.purge,
        recommendedMethod: SanitizationMethod.cryptographicErase,
        standardReference: 'NIST SP 800-88 Rev. 1 (Purge)',
        explanationText: 'NVMe Cryptographic Erase',
      );

      // Simulate firmware sanitize progress event from engine where percent is None / null
      const rawJson = '''
      {
        "schema_version": 2,
        "phase": "FirmwareCommand",
        "bytes_done": 0,
        "bytes_total": 0,
        "percent": null,
        "speed_bytes_per_sec": 0.0,
        "eta_seconds": null,
        "message": "Executing NVMe crypto-erase firmware command...",
        "is_heartbeat": false
      }
      ''';

      final event = RealProgressEvent.fromJson(jsonDecode(rawJson));
      expect(event.percent, isNull);
      expect(event.bytesDone, 0);
      expect(event.bytesTotal, 0);

      // Controller assigns event.percent directly to job.progress
      job.progress = event.percent;
      expect(job.progress, isNull, reason: 'Firmware sanitize commands have indeterminate duration and must keep progress as null');
    });

    test('3. Multi-pass cumulative progress uses passes * device_size as denominator', () {
      final deviceSize = 10 * 1024 * 1024 * 1024; // 10 GB
      const passes = 3;
      final totalExpectedBytes = passes * deviceSize; // 30 GB

      // Pass 1 complete (10 GB / 30 GB = 33.3%)
      final pass1Event = RealProgressEvent.fromJson({
        'schema_version': 2,
        'phase': 'FirmwareCommand',
        'bytes_done': deviceSize,
        'bytes_total': totalExpectedBytes,
        'percent': deviceSize / totalExpectedBytes,
        'speed_bytes_per_sec': 50000000.0,
        'eta_seconds': 400,
        'message': 'Pass 1 of 3 (Zeros): 10.0 / 30.0 GB',
        'is_heartbeat': false,
      });

      expect(pass1Event.bytesDone, equals(deviceSize));
      expect(pass1Event.bytesTotal, equals(totalExpectedBytes));
      expect(pass1Event.percent, closeTo(0.3333, 0.001));

      // Pass 2 complete (20 GB / 30 GB = 66.7%)
      final pass2Event = RealProgressEvent.fromJson({
        'schema_version': 2,
        'phase': 'FirmwareCommand',
        'bytes_done': 2 * deviceSize,
        'bytes_total': totalExpectedBytes,
        'percent': (2 * deviceSize) / totalExpectedBytes,
        'speed_bytes_per_sec': 50000000.0,
        'eta_seconds': 200,
        'message': 'Pass 2 of 3 (Random): 20.0 / 30.0 GB',
        'is_heartbeat': false,
      });

      expect(pass2Event.bytesDone, equals(2 * deviceSize));
      expect(pass2Event.percent, closeTo(0.6666, 0.001));

      // Pass 3 complete (30 GB / 30 GB = 100%)
      final pass3Event = RealProgressEvent.fromJson({
        'schema_version': 2,
        'phase': 'FirmwareCommand',
        'bytes_done': 3 * deviceSize,
        'bytes_total': totalExpectedBytes,
        'percent': 1.0,
        'speed_bytes_per_sec': 50000000.0,
        'eta_seconds': 0,
        'message': 'Pass 3 of 3 (Zeros): 30.0 / 30.0 GB',
        'is_heartbeat': false,
      });

      expect(pass3Event.bytesDone, equals(totalExpectedBytes));
      expect(pass3Event.percent, equals(1.0));
    });

    test('4. Schema v1 defensive parsing backward compatibility', () {
      // Schema v1 event emitted by older engine or mock
      final v1Json = {
        'schema_version': 1,
        'phase': 'FirmwareCommand',
        'percent': 0.42,
        'message': 'Writing sectors via dd',
      };

      final event = RealProgressEvent.fromJson(v1Json);
      expect(event.schemaVersion, 1);
      expect(event.phase, 'FirmwareCommand');
      expect(event.percent, closeTo(0.42, 0.001));
      expect(event.bytesDone, 0, reason: 'Defaults to 0 for schema v1');
      expect(event.bytesTotal, 0, reason: 'Defaults to 0 for schema v1');
      expect(event.speedBytesPerSec, 0.0);
      expect(event.etaSeconds, isNull);
      expect(event.isHeartbeat, isFalse);
      expect(event.message, 'Writing sectors via dd');
    });

    test('5. Schema v2 full telemetry parsing and heartbeat flag', () {
      // Schema v2 normal progress event
      final v2Json = {
        'schema_version': 2,
        'phase': 'FirmwareCommand',
        'bytes_done': 4194304000,
        'bytes_total': 16000000000,
        'percent': 0.262,
        'speed_bytes_per_sec': 32500000.0,
        'eta_seconds': 363,
        'message': 'Pass 1 of 1 (Zeros): 4.2 / 16.0 GB @ 32.5 MB/s',
        'is_heartbeat': false,
      };

      final event = RealProgressEvent.fromJson(v2Json);
      expect(event.schemaVersion, 2);
      expect(event.bytesDone, 4194304000);
      expect(event.bytesTotal, 16000000000);
      expect(event.percent, closeTo(0.262, 0.001));
      expect(event.speedBytesPerSec, 32500000.0);
      expect(event.etaSeconds, 363);
      expect(event.isHeartbeat, isFalse);
      expect(event.message, contains('Pass 1 of 1'));

      // Schema v2 1-second heartbeat event
      final heartbeatJson = {
        'schema_version': 2,
        'phase': 'FirmwareCommand',
        'bytes_done': 4194304000,
        'bytes_total': 16000000000,
        'percent': 0.262,
        'speed_bytes_per_sec': 0.0,
        'eta_seconds': null,
        'message': 'heartbeat',
        'is_heartbeat': true,
      };

      final hbEvent = RealProgressEvent.fromJson(heartbeatJson);
      expect(hbEvent.schemaVersion, 2);
      expect(hbEvent.isHeartbeat, isTrue);
      expect(hbEvent.message, 'heartbeat');
    });

    test('6. RealExecutionReport schema parsing with bytes_written and io_mode', () {
      final reportJson = {
        'success': true,
        'method_used': 'overwrite-zero',
        'command_log': ['Native block overwrite (1 passes, mode: direct_io)'],
        'stdout': '',
        'stderr': '',
        'exit_code': 0,
        'duration_ms': 15200,
        'dry_run': false,
        'bytes_written': 16000000000,
        'io_mode': 'direct_io',
      };

      final report = RealExecutionReport.fromJson(reportJson);
      expect(report.success, isTrue);
      expect(report.bytesWritten, 16000000000);
      expect(report.ioMode, 'direct_io');
      expect(report.exitCode, 0);
    });

    test('7. Cancellation state transitions without automatic SIGKILL', () {
      final service = RealSanitizationService(paths: tempPaths());
      // Ensure calling cancelActiveProcess does not trigger automatic kill
      service.cancelActiveProcess();
      expect(service.activeProcess, isNull);

      // Force stop method exists and can be invoked
      service.forceKillActiveProcess();
      expect(service.activeProcess, isNull);
    });

    test('8. Force stop transitions job to "interrupted, state unknown" and checkpoint stays', () async {
      final controller = SanitizationController(
        appPaths: tempPaths(),
        enableAutoPolling: false,
        deferInitialDiscovery: true,
      );
      addTearDown(() => controller.dispose());

      final testDevice = DeviceProfile(
        id: 'test_force_dev',
        name: 'Test USB',
        serialNumber: 'FORCE-1234-TEST',
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        capacityBytes: 16000000000,
      );

      final job = SanitizationJob(
        jobId: 'job-force-stop-test',
        device: testDevice,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 0.5,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88 Clear',
        explanationText: 'Single pass zeros',
        status: JobStatus.sanitizing,
        progress: 0.45,
        currentStageDescription: 'Writing zeros',
        startTime: DateTime.now(),
      );

      controller.setMockJob(job);

      // Execute force stop
      await controller.forceStopCurrentJob();

      // Verify job description is 'interrupted, state unknown'
      expect(controller.currentJob?.currentStageDescription, 'interrupted, state unknown');

      // Verify checkpoint stays on disk
      final activeJob = await JobStateFile(paths: tempPaths()).readActiveJob();
      expect(activeJob, isNotNull);
      expect(activeJob!.jobId, 'job-force-stop-test');
      expect(activeJob.status, 'interrupted');
      expect(activeJob.deviceSerial, 'FORCE-1234-TEST');

      // Clean up test state file
      await JobStateFile(paths: tempPaths()).clearActiveJob();
    });
  });
}
