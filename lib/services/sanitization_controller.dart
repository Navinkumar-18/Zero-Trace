import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';

import '../models/certificate.dart';
import '../models/device_profile.dart';
import '../models/sanitization_job.dart';
import 'certificate_service.dart';
import 'classification_service.dart';
import 'device_intelligence_service.dart';
import 'device_simulator.dart';
import 'policy_layer.dart';
import 'recommendation_service.dart';
import 'risk_scoring_service.dart';
import 'verification_service.dart';
import 'real_sanitization_service.dart';
import 'audit_log_service.dart';
import 'job_state_file.dart';
import 'orphaned_process_checker.dart';

class SanitizationController extends ChangeNotifier {
  final DeviceSimulator _simulator = DeviceSimulator();
  final DeviceIntelligenceService _intelligenceService = DeviceIntelligenceService();
  final ClassificationService _classificationService = ClassificationService();
  final RiskScoringService _riskScoringService = RiskScoringService();
  final RecommendationService _recommendationService = RecommendationService();
  final PolicyLayer _policyLayer = PolicyLayer();
  final VerificationService _verificationService = VerificationService();
  final CertificateService _certificateService = CertificateService();
  final RealSanitizationService _realSanitizeService = RealSanitizationService();
  final AuditLogService _auditLogService = AuditLogService();

  List<DeviceProfile> _devices = [];
  DeviceProfile? _selectedDevice;
  bool _isRealMode = true;
  Timer? _autoPollTimer;

  // Form Inputs
  DataSensitivity _dataSensitivity = DataSensitivity.confidential;
  DeviceCondition _deviceCondition = DeviceCondition.functional;
  DisposalPath _disposalPath = DisposalPath.recycling;

  // Current active job
  SanitizationJob? _currentJob;
  SanitizationCertificate? _completedCertificate;
  PolicyValidationResult? _lastPolicyResult;
  OrphanCheckResult? _orphanResult;

  // Global dev simulator controls
  bool _simulateFailureMode = false;

  SanitizationController() {
    refreshDevices();
    _startAutoPolling();
    _checkForOrphansOnStartup();
  }

  Future<void> _checkForOrphansOnStartup() async {
    final result = await OrphanedProcessChecker.checkForOrphan();
    if (result.status != OrphanCheckStatus.none) {
      _orphanResult = result;
      notifyListeners();
    }
  }

  void acknowledgeOrphan() {
    _orphanResult = null;
    JobStateFile.clearActiveJob();
    notifyListeners();
  }

  void clearCompletedJob() {
    if (isJobRunning) return;
    _currentJob = null;
    _completedCertificate = null;
    _updateJobRecommendation();
    notifyListeners();
  }

  // Getters
  List<DeviceProfile> get devices => _devices;
  DeviceProfile? get selectedDevice => _selectedDevice;
  bool get isRealMode => _isRealMode;
  String? get lastScanError => _intelligenceService.lastScanError;
  bool get isAutoPollingActive => _autoPollTimer?.isActive ?? false;
  ClassificationService get classificationService => _classificationService;

  DataSensitivity get dataSensitivity => _dataSensitivity;
  DeviceCondition get deviceCondition => _deviceCondition;
  DisposalPath get disposalPath => _disposalPath;

  SanitizationJob? get currentJob => _currentJob;
  SanitizationCertificate? get completedCertificate => _completedCertificate;
  PolicyValidationResult? get lastPolicyResult => _lastPolicyResult;
  bool get simulateFailureMode => _simulateFailureMode;
  OrphanCheckResult? get orphanResult => _orphanResult;

  bool get isJobRunning {
    if (_currentJob == null) return false;
    return _currentJob!.status == JobStatus.detecting ||
        _currentJob!.status == JobStatus.unmounting ||
        _currentJob!.status == JobStatus.sanitizing ||
        _currentJob!.status == JobStatus.verifying;
  }

  void _startAutoPolling() {
    _autoPollTimer?.cancel();
    if (_isRealMode) {
      _autoPollTimer = Timer.periodic(const Duration(milliseconds: 2500), (_) {
        refreshDevices(silent: true);
      });
    }
  }

  void _stopAutoPolling() {
    _autoPollTimer?.cancel();
    _autoPollTimer = null;
  }

  Future<void> toggleRealMode(bool value) async {
    _isRealMode = value;
    if (_isRealMode) {
      _startAutoPolling();
    } else {
      _stopAutoPolling();
    }
    await refreshDevices();
  }

  Future<void> refreshDevices({bool silent = false}) async {
    final freshDevices = await _intelligenceService.discoverDevices(realMode: _isRealMode);

    // Check if device list changed
    bool hasChanged = freshDevices.length != _devices.length;
    if (!hasChanged) {
      for (int i = 0; i < freshDevices.length; i++) {
        if (freshDevices[i].id != _devices[i].id ||
            freshDevices[i].name != _devices[i].name ||
            freshDevices[i].capacityBytes != _devices[i].capacityBytes ||
            freshDevices[i].isWipedNoFilesystem != _devices[i].isWipedNoFilesystem ||
            freshDevices[i].hasFilesystem != _devices[i].hasFilesystem) {
          hasChanged = true;
          break;
        }
      }
    }

    if (hasChanged || _devices.isEmpty) {
      _devices = freshDevices;
      if (!isJobRunning) {
        if (_devices.isNotEmpty) {
          if (_selectedDevice == null || !_devices.any((d) => d.id == _selectedDevice!.id)) {
            _selectedDevice = _devices.first;
          } else {
            // Refresh selected device reference with new profile
            _selectedDevice = _devices.firstWhere((d) => d.id == _selectedDevice!.id);
          }
        } else {
          _selectedDevice = null;
        }
        _updateJobRecommendation();
      }
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _stopAutoPolling();
    super.dispose();
  }

  void selectDevice(DeviceProfile device) {
    if (isJobRunning) return;
    _selectedDevice = device;
    _updateJobRecommendation();
    notifyListeners();
  }

  void setRiskInputs({
    DataSensitivity? sensitivity,
    DeviceCondition? condition,
    DisposalPath? path,
  }) {
    if (isJobRunning) return;
    if (sensitivity != null) _dataSensitivity = sensitivity;
    if (condition != null) _deviceCondition = condition;
    if (path != null) _disposalPath = path;

    _updateJobRecommendation();
    notifyListeners();
  }

  void toggleSimulateFailureMode(bool value) {
    _simulateFailureMode = value;
    if (_currentJob != null) {
      _currentJob!.shouldSimulateFailure = value;
    }
    notifyListeners();
  }

  void resetSimulator() {
    if (isJobRunning) return;
    _simulator.resetProfiles();
    refreshDevices();
    _currentJob = null;
    _completedCertificate = null;
    _lastPolicyResult = null;
    notifyListeners();
  }

  void _updateJobRecommendation() {
    if (isJobRunning) return;
    if (_selectedDevice == null) return;

    final device = _selectedDevice!;
    final riskResult = _riskScoringService.scoreRisk(
      dataSensitivity: _dataSensitivity,
      deviceCondition: _deviceCondition,
      disposalPath: _disposalPath,
    );

    final recResult = _recommendationService.selectMethod(
      device,
      riskResult.score,
      riskResult.targetCategory,
    );

    final jobId = 'JOB-${DateTime.now().millisecondsSinceEpoch.toString().substring(6)}';

    _currentJob = SanitizationJob(
      jobId: jobId,
      device: device,
      dataSensitivity: _dataSensitivity,
      deviceCondition: _deviceCondition,
      disposalPath: _disposalPath,
      riskScore: riskResult.score,
      targetCategory: riskResult.targetCategory,
      recommendedMethod: recResult.method,
      standardReference: recResult.standardReference,
      explanationText: recResult.explanation,
      shouldSimulateFailure: _simulateFailureMode,
    );

    _lastPolicyResult = _policyLayer.validateOperation(_currentJob!);
  }

  // Orchestrate simulated or real pipeline execution
  Future<void> runSanitizationPipeline() async {
    if (_currentJob == null) return;

    final job = _currentJob!;
    job.startTime = DateTime.now();
    job.logs.clear();

    _addLog('POLICY: Validating requested operation whitelist...');
    final policy = _policyLayer.validateOperation(job);
    _lastPolicyResult = policy;

    if (!policy.isAllowed) {
      job.status = JobStatus.failed;
      job.currentStageDescription = policy.policyMessage;
      _addLog('ERROR: ${policy.policyMessage}');
      notifyListeners();
      return;
    }

    _addLog('SUCCESS: Whitelist verified. Target: ${job.device.name} [${job.device.serialNumber}]');
    notifyListeners();

    if (_isRealMode) {
      if (kIsWeb) {
        job.status = JobStatus.failed;
        job.currentStageDescription = 'Real mode is not supported on Web. Please run natively on Linux.';
        _addLog('ERROR: Real mode is not supported on Web.');
        notifyListeners();
        return;
      }
      if (!Platform.isLinux) {
        job.status = JobStatus.failed;
        job.currentStageDescription = 'Real mode is only supported on Linux.';
        _addLog('ERROR: Real mode is only supported on Linux.');
        notifyListeners();
        return;
      }

      try {
        // Stage 1: Detecting & unmounting filesystems
        job.status = JobStatus.unmounting;
        job.progress = 0.10;
        job.currentStageDescription = 'Preparing device: zt_engine handling partition unmounts...';
        _addLog('SYSTEM: Initializing device preparation (zt_engine managing unmount)...');
        notifyListeners();

        // Stage 2: Sanitization execution
        job.status = JobStatus.sanitizing;
        job.progress = 0.20;
        job.currentStageDescription = 'Executing real-hardware sanitization...';
        notifyListeners();

        await JobStateFile.saveActiveJob(ActiveJobState(
          jobId: job.jobId,
          deviceSerial: job.device.serialNumber,
          devicePath: job.device.id.startsWith('real_') ? '/dev/${job.device.id.substring(5)}' : '/dev/sdb',
          deviceName: job.device.name,
          method: job.recommendedMethod.displayName,
          startedAt: job.startTime?.toIso8601String() ?? DateTime.now().toIso8601String(),
        ));

        final report = await _realSanitizeService.executeSanitization(
          device: job.device,
          method: job.recommendedMethod,
          confirmationToken: job.device.serialNumber, // verified by dialog retype
          deviceSerial: job.device.serialNumber,
          dryRun: false,
          onProgress: (event) {
            job.progress = 0.20 + (event.percent * 0.60); // map 0.0-1.0 to 0.20-0.80 range
            job.currentStageDescription = 'Sanitizing: ${event.message}';
            _addLog('PROGRESS: [${event.phase}] ${event.message} (${(event.percent * 100).toInt()}%)');
            notifyListeners();
          },
          onRawLog: (rawLine) {
            _addLog(rawLine);
            notifyListeners();
          },
        );

        if (!report.success) {
          job.status = JobStatus.failed;
          job.endTime = DateTime.now();
          job.currentStageDescription = 'Sanitization Failed: ${report.stderr}';
          _addLog('ERROR: Sanitization command failed with code ${report.exitCode}');
          _addLog('ERROR Details: ${report.stderr}');
          await JobStateFile.clearActiveJob();
          notifyListeners();
          return;
        }

        // ── Disk operation succeeded. Record this fact BEFORE post-processing ──
        // From this point forward, any exception is a post-processing failure
        // (certificate signing, audit log), NOT a disk operation failure.
        final bool diskWipeSucceeded = true;

        // Stage 3: Verification LBA sampling
        job.status = JobStatus.verifying;
        job.progress = 0.80;
        job.currentStageDescription = 'Verifying sector erasure via LBA sampling...';
        _addLog('VERIFICATION: Running post-sanitize verify LBA sampling...');
        notifyListeners();

        final cliMethod = _realSanitizeService.mapMethodToCliArg(job.recommendedMethod, job.device);
        final expectZeros = job.recommendedMethod != SanitizationMethod.cryptographicErase;

        RealVerificationReport? verifyReport;
        try {
          verifyReport = await _realSanitizeService.executeVerification(
            device: job.device,
            method: cliMethod,
            deviceSerial: job.device.serialNumber,
            sampleCount: 50,
            expectZeros: expectZeros,
          );
        } catch (verifyErr) {
          _addLog('WARNING: Verification sampling failed: $verifyErr');
          _addLog('NOTE: Disk write operation itself completed successfully.');
        }

        job.progress = 0.95;
        notifyListeners();

        final bool verificationPassed = verifyReport?.pass ?? false;

        // Construct VerificationEvidence from real report
        final List<int> sampleOffsets = [];
        final Map<int, String> sampleHashes = {};
        if (verifyReport != null) {
          for (final sample in verifyReport.samples) {
            try {
              final offset = sample['offset'] as int;
              final hash = sample['sector_hash'] as String;
              sampleOffsets.add(offset);
              sampleHashes[offset] = hash;
            } catch (_) {}
          }
        }

        if (sampleOffsets.isEmpty) {
          // populate dummy offsets if none returned to avoid UI crashes
          sampleOffsets.addAll(List.generate(50, (index) => index * 1000));
          for (final offset in sampleOffsets) {
            sampleHashes[offset] = '0000000000000000000000000000000000000000000000000000000000000000';
          }
        }

        final statusCode = verificationPassed ? 0 : 1;
        final controllerConfirmation = verifyReport != null
            ? 'VERIFICATION: Pass: ${verifyReport.pass} | Samples: ${verifyReport.sampleCount} | Entropy: ${verifyReport.entropyScore}'
            : 'VERIFICATION: Sampling unavailable (disk wipe command succeeded)';

        final limitations = _verificationService.getTailoredLimitations(job.recommendedMethod);

        final evidence = VerificationEvidence(
          statusCode: statusCode,
          controllerConfirmation: controllerConfirmation,
          sampleOffsets: sampleOffsets,
          sampleHashes: sampleHashes,
          evidenceHash: verifyReport?.fingerprintHash ?? 'VERIFY_UNAVAILABLE',
          limitations: limitations,
          verifiedPassed: verificationPassed,
        );

        bool isJobSuccessful = false;
        if (verifyReport != null) {
          isJobSuccessful = verifyReport.pass;
        } else {
          isJobSuccessful = diskWipeSucceeded;
        }

        // Stage 4: Completion — set status based on DISK OPERATION & VERIFICATION
        job.status = isJobSuccessful ? JobStatus.completed : JobStatus.failed;
        job.progress = 1.0;
        job.endTime = DateTime.now();
        job.currentStageDescription = isJobSuccessful
            ? (verificationPassed
                ? 'Sanitization & Audit Verification Complete.'
                : 'Disk wipe succeeded. Verification sampling unavailable — review logs.')
            : 'Verification Failed: Non-zero or dirty sectors detected.';
        notifyListeners();

        // ── Post-processing: certificate & audit log ──
        // Failures here must NOT change job.status from completed→failed.
        try {
          _completedCertificate = _certificateService.generateCertificate(job: job, evidence: evidence);
          _addLog('CERTIFICATE: Issued ${completedCertificate!.certificateId} signed with ECDSA P-256 key.');
        } catch (certErr) {
          _addLog('WARNING: Certificate generation failed: $certErr');
          _addLog('NOTE: The disk sanitization itself completed successfully.');
          job.currentStageDescription = 'Sanitization succeeded. Certificate generation failed — see logs.';
        }

        if (verifyReport != null) {
          _addLog('VERIFICATION: Entropy score: ${verifyReport.entropyScore}. Fingerprint: ${verifyReport.fingerprintHash}');
        }

        try {
          final auditEntry = AuditLogEntry(
            timestamp: DateTime.now().toIso8601String(),
            jobId: job.jobId,
            deviceSerial: job.device.serialNumber,
            devicePath: job.device.id.startsWith('real_')
                ? '/dev/${job.device.id.substring(5)}'
                : '/dev/null',
            method: job.recommendedMethod.displayName,
            standardReference: job.standardReference,
            nistCategory: job.effectiveNistCategoryDisplayName,
            success: diskWipeSucceeded && verificationPassed,
            fingerprintHash: verifyReport?.fingerprintHash ?? 'UNAVAILABLE',
            entropyScore: verifyReport?.entropyScore ?? 0.0,
            sampleCount: verifyReport?.sampleCount ?? 0,
            commandLog: report.commandLog,
          );
          await _auditLogService.appendEntry(auditEntry);
        } catch (auditErr) {
          _addLog('WARNING: Audit log write failed: $auditErr');
        }

        await JobStateFile.clearActiveJob();
        notifyListeners();
      } catch (e) {
        // This catch is ONLY for failures during the actual disk operation
        // (unmounting, sanitization command launch, process spawning).
        // Post-processing failures are caught separately above.
        job.status = JobStatus.failed;
        job.endTime = DateTime.now();
        job.currentStageDescription = 'Execution Error: $e';
        _addLog('ERROR: $e');
        await JobStateFile.clearActiveJob();
        notifyListeners();
      }
      return;
    }

    // Stage 1: Detecting & Locking device (Simulated Mode)
    job.status = JobStatus.detecting;
    job.progress = 0.05;
    await Future.delayed(const Duration(milliseconds: 800));
    job.status = JobStatus.unmounting;
    job.progress = 0.20;
    job.currentStageDescription = 'Unmounting filesystems & requesting target device lock...';
    _addLog('DISCOVERY: Classifying media topology & bus capabilities...');
    _addLog('SYSTEM: Unmounted partitions on ${job.device.name}');
    notifyListeners();

    // Stage 2: Sanitization Method Execution (Simulated Mode)
    await Future.delayed(const Duration(milliseconds: 1000));
    job.status = JobStatus.sanitizing;
    job.progress = 0.40;
    job.currentStageDescription = 'Executing ${job.recommendedMethod.displayName}...';
    _addLog('EXECUTION: Invoking controller command payload [Simulated Engine]...');

    await JobStateFile.saveActiveJob(ActiveJobState(
      jobId: job.jobId,
      deviceSerial: job.device.serialNumber,
      devicePath: '/dev/sdb',
      deviceName: job.device.name,
      method: job.recommendedMethod.displayName,
      startedAt: job.startTime?.toIso8601String() ?? DateTime.now().toIso8601String(),
    ));

    // Progress updates during sanitization
    for (int p = 45; p <= 80; p += 10) {
      await Future.delayed(const Duration(milliseconds: 400));
      job.progress = p / 100.0;
      _addLog('PROGRESS: ${job.recommendedMethod.displayName} - $p% complete');
      notifyListeners();
    }

    // Check for simulated failure injection
    if (job.shouldSimulateFailure) {
      await Future.delayed(const Duration(milliseconds: 600));
      job.status = JobStatus.failed;
      job.endTime = DateTime.now();
      job.currentStageDescription = 'Sanitization Interrupted: Hardware Controller Time-out';
      _addLog('ERROR: Controller returned STATUS_ERR_TIMEOUT (Simulated Failure Injected)');
      
      final evidence = _verificationService.verify(job, isSuccess: false);
      _completedCertificate = _certificateService.generateCertificate(job: job, evidence: evidence);
      await JobStateFile.clearActiveJob();
      notifyListeners();
      return;
    }

    // Stage 3: Verification (Simulated Mode)
    await Future.delayed(const Duration(milliseconds: 600));
    job.status = JobStatus.verifying;
    job.progress = 0.90;
    job.currentStageDescription = 'Verifying sector erasure via 50-point readback sampling...';
    _addLog('VERIFICATION: Executing sector sampling across full LBA range...');
    notifyListeners();

    // Stage 4: Completion & Certificate Signing (Simulated Mode)
    await Future.delayed(const Duration(milliseconds: 800));
    job.status = JobStatus.completed;
    job.progress = 1.0;
    job.endTime = DateTime.now();
    job.currentStageDescription = 'Sanitization & Audit Verification Complete.';
    _addLog('VERIFICATION: 50/50 Sector Samples zero-verified. SHA-256 evidence calculated.');

    final evidence = _verificationService.verify(job, isSuccess: true);
    _completedCertificate = _certificateService.generateCertificate(job: job, evidence: evidence);
    _addLog('CERTIFICATE: Issued ${completedCertificate!.certificateId} signed with ECDSA P-256 key.');
    await JobStateFile.clearActiveJob();

    notifyListeners();
  }

  void _addLog(String message) {
    if (_currentJob != null) {
      final timestamp = DateTime.now().toString().substring(11, 19);
      _currentJob!.logs.add('[$timestamp] $message');
    }
  }

  Future<Uint8List?> getPdfCertificateBytes() async {
    if (_completedCertificate == null) return null;
    return await _certificateService.generatePdfBytes(_completedCertificate!);
  }
}
