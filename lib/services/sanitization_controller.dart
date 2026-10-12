import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';

import '../core/app_paths.dart';
import '../models/certificate.dart';
import '../models/device_profile.dart';
import '../models/partition_info.dart';
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
import '../simple/confirm_wipe_dialog.dart';

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
  late final AppPaths _appPaths;
  late final AuditLogService _auditLogService;
  late final JobStateFile _jobStateFile;
  late final OrphanedProcessChecker _orphanChecker;

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

  // Simple Mode shared state (reset on every launch)
  bool _showInternalDrives = false;
  PartitionInfo? _selectedPartition;

  PartitionInfo? get selectedPartition => _selectedPartition;

  // Real-time telemetry and stall watchdog
  DateTime? _lastHeartbeatTime;
  Timer? _stallWatchdogTimer;
  bool _isStalled = false;
  double _currentSpeedBytesPerSec = 0.0;
  int? _currentEtaSeconds;

  // Cancellation and Force Stop escalation state
  bool _isCancelling = false;
  bool _showForceStop = false;
  Timer? _cancelEscalationTimer;

  bool get isStalled => _isStalled;
  double get currentSpeedBytesPerSec => _currentSpeedBytesPerSec;
  int? get currentEtaSeconds => _currentEtaSeconds;
  bool get isCancelling => _isCancelling;
  bool get showForceStop => _showForceStop;

  bool _isDisposed = false;

  SanitizationController({AppPaths? appPaths, bool enableAutoPolling = true, bool deferInitialDiscovery = false}) {
    _appPaths = appPaths ?? AppPaths.production();
    _auditLogService = AuditLogService(paths: _appPaths);
    _jobStateFile = JobStateFile(paths: _appPaths);
    _orphanChecker = OrphanedProcessChecker(paths: _appPaths);
    if (!deferInitialDiscovery) {
      refreshDevices();
    }
    if (enableAutoPolling) {
      _startAutoPolling();
    }
    _checkForOrphansOnStartup();
  }

  bool get showInternalDrives => _showInternalDrives;
  void setShowInternalDrives(bool value) {
    _showInternalDrives = value;
    notifyListeners();
  }

  void resetShowInternalDrives() {
    if (_showInternalDrives) {
      _showInternalDrives = false;
      notifyListeners();
    }
  }

  /// Auto-select the strongest supported method for a device.
  /// Used by Simple Mode to show the method in the confirm dialog.
  /// The disposal intent only affects warnings and the Destroy recommendation.
  RecommendationResult getAutoMethod(DeviceProfile device, DisposalIntent intent) {
    final sensitivity = intent.mappedSensitivity;
    return _recommendationService.selectMethod(
      device,
      0.5,
      NistCategory.purge,
      sensitivity: sensitivity,
    );
  }

  /// Start sanitization in Simple Mode with auto-selected method.
  /// Requires a valid [WipeAuthorization] produced exclusively by confirmation.
  Future<void> startSimpleWipe(
    DeviceProfile device,
    DisposalIntent intent, {
    required WipeAuthorization authorization,
    SanitizationMethod? overrideMethod,
  }) async {
    if (authorization.deviceSerial != device.serialNumber) {
      throw ArgumentError('WipeAuthorization deviceSerial does not match target device serial');
    }
    if (isJobRunning) return;

    // Pin serial + size at selection
    _selectedDevice = device;

    final sensitivity = intent.mappedSensitivity;
    final disposalPath = intent.mappedDisposalPath;

    _dataSensitivity = sensitivity;
    _deviceCondition = DeviceCondition.functional;
    _disposalPath = disposalPath;

    final riskResult = _riskScoringService.scoreRisk(
      dataSensitivity: sensitivity,
      deviceCondition: DeviceCondition.functional,
      disposalPath: disposalPath,
    );

    final recResult = getAutoMethod(device, intent);

    var effectiveRecMethod = recResult.method;
    var standardRef = recResult.standardReference;
    var explanation = recResult.explanation;

    if (_selectedPartition != null) {
      if (effectiveRecMethod != SanitizationMethod.singlePassOverwrite &&
          effectiveRecMethod != SanitizationMethod.multiPassOverwrite) {
        effectiveRecMethod = SanitizationMethod.singlePassOverwrite;
        standardRef = 'NIST SP 800-88 R1 Clear (Partition Scope Overwrite)';
        explanation = 'Partition-scoped wiping only supports overwrite methods.';
      }
    }

    final jobId = 'JOB-${DateTime.now().millisecondsSinceEpoch.toString().substring(6)}';

    _currentJob = SanitizationJob(
      jobId: jobId,
      device: device,
      dataSensitivity: sensitivity,
      deviceCondition: DeviceCondition.functional,
      disposalPath: disposalPath,
      riskScore: riskResult.score,
      targetCategory: riskResult.targetCategory,
      recommendedMethod: effectiveRecMethod,
      standardReference: standardRef,
      explanationText: explanation,
      targetPartition: _selectedPartition,
      shouldSimulateFailure: _simulateFailureMode,
      overriddenMethod: overrideMethod,
    );

    _lastPolicyResult = _policyLayer.validateOperation(_currentJob!);
    notifyListeners();

    await _runSanitizationPipeline();
  }

  String _deriveMethodClass(SanitizationMethod method) {
    switch (method) {
      case SanitizationMethod.nvmeSanitize:
      case SanitizationMethod.ataSanitizeBlockErase:
      case SanitizationMethod.ataSecureErase:
      case SanitizationMethod.emmcSanitize:
        return 'firmwareSanitize';
      case SanitizationMethod.cryptographicErase:
        return 'cryptoErase';
      case SanitizationMethod.singlePassOverwrite:
      case SanitizationMethod.multiPassOverwrite:
        return 'overwrite';
      default:
        return 'other';
    }
  }

  List<PartitionAuditOutcome>? _buildPartitionOutcomes(SanitizationJob job, bool success) {
    if (!job.isPartitionScope || job.targetPartition == null) return null;
    return [
      PartitionAuditOutcome(
        partitionNumber: job.targetPartition!.partitionNumber,
        startSector: job.targetPartition!.startSector,
        sizeSectors: job.targetPartition!.sizeSectors,
        status: success ? 'COMPLETED' : 'FAILED',
        bytesWiped: success ? job.targetPartition!.sizeBytes : 0,
      )
    ];
  }

  Future<void> _checkForOrphansOnStartup() async {
    final result = await _orphanChecker.checkForOrphan();
    if (_isDisposed) return;
    if (result.status != OrphanCheckStatus.none) {
      _orphanResult = result;
      notifyListeners();
    }
  }

  Future<void> acknowledgeOrphan() async {
    final active = _orphanResult?.activeJobState;
    if (active != null) {
      _auditLogService.appendEntry(
        AuditLogEntry(
          timestamp: DateTime.now().toIso8601String(),
          jobId: active.jobId,
          deviceSerial: active.deviceSerial,
          devicePath: active.devicePath,
          deviceName: active.deviceName,
          scope: active.scope ?? 'full',
          method: active.method,
          methodClass: 'firmwareSanitize',
          standardReference: 'NIST SP 800-88 Rev. 1',
          nistCategory: 'INTERRUPTED',
          success: false,
          fingerprintHash: 'INTERRUPTED_ACKNOWLEDGED',
          entropyScore: 0.0,
          sampleCount: 0,
          commandLog: [
            'Interrupted sanitization run dismissed by user.',
            'interrupted, state unknown',
          ],
        ),
      );
      // Mark the device note in _devices
      _devices = _devices.map((d) {
        if (d.serialNumber == active.deviceSerial || d.id == active.devicePath || d.name == active.deviceName) {
          return DeviceProfile(
            id: d.id,
            name: d.name,
            serialNumber: d.serialNumber,
            mediaType: d.mediaType,
            busType: d.busType,
            capacityBytes: d.capacityBytes,
            rotationalRpm: d.rotationalRpm,
            isHardwareEncrypted: d.isHardwareEncrypted,
            supportsAtaSecureErase: d.supportsAtaSecureErase,
            supportsAtaSanitize: d.supportsAtaSanitize,
            supportsNvmeSanitize: d.supportsNvmeSanitize,
            supportsEmmcSanitize: d.supportsEmmcSanitize,
            supportsTrim: d.supportsTrim,
            hpaDcoPresent: d.hpaDcoPresent,
            mountPoint: d.mountPoint,
            isSystemDisk: d.isSystemDisk,
            hasFilesystem: d.hasFilesystem,
            fsType: d.fsType,
            isWipedNoFilesystem: d.isWipedNoFilesystem,
            notes: 'May be partially wiped (interrupted wipe)',
            isRemovable: d.isRemovable,
            disabledReason: d.disabledReason,
          );
        }
        return d;
      }).toList();
    }
    _orphanResult = null;
    notifyListeners();

    await _jobStateFile.clearActiveJob();
  }

  /// Whether the currently running job can be safely cancelled.
  /// Firmware sanitize commands (ATA, NVMe, eMMC, Crypto Erase) CANNOT be cancelled safely.
  bool get canCancelJob {
    if (!isJobRunning || _currentJob == null) return false;
    final method = _currentJob!.effectiveMethod;
    if (method == SanitizationMethod.ataSecureErase ||
        method == SanitizationMethod.ataSanitizeBlockErase ||
        method == SanitizationMethod.nvmeSanitize ||
        method == SanitizationMethod.emmcSanitize ||
        method == SanitizationMethod.cryptographicErase) {
      return false;
    }
    return true;
  }

  /// Cancel an in-progress software overwrite job.
  /// Sends SIGTERM to allow the engine to flush buffers and write a checkpoint.
  /// After 5 seconds without exit, offers a Force stop option if the drive is still writing.
  Future<void> cancelCurrentJob() async {
    if (!canCancelJob || _currentJob == null) return;
    _isCancelling = true;
    _showForceStop = false;
    _addLog('USER CANCEL: Sending cancellation signal to zt_engine (SIGTERM)...');
    _realSanitizeService.cancelActiveProcess();

    // After 5 seconds: show "waiting for the drive to finish its current write" and offer Force stop button
    _cancelEscalationTimer?.cancel();
    _cancelEscalationTimer = Timer(const Duration(seconds: 5), () {
      if (_isCancelling && _currentJob != null && isJobRunning) {
        _showForceStop = true;
        _currentJob!.currentStageDescription = 'waiting for the drive to finish its current write';
        _addLog('CANCEL NOTICE: waiting for the drive to finish its current write');
        notifyListeners();
      }
    });

    final job = _currentJob!;
    job.status = JobStatus.failed;
    job.endTime = DateTime.now();
    job.currentStageDescription = 'Sanitization Cancelled: Partially Wiped';
    _addLog('USER CANCEL: Job cancelled by user. Warning: Drive may be partially wiped.');

    await _auditLogService.appendEntry(
      AuditLogEntry(
        timestamp: DateTime.now().toIso8601String(),
        jobId: job.jobId,
        deviceSerial: job.device.serialNumber,
        devicePath: job.device.id,
        deviceName: job.device.name,
        scope: job.isPartitionScope ? 'partial' : 'full',
        method: job.effectiveMethod.displayName,
        methodClass: _deriveMethodClass(job.effectiveMethod),
        standardReference: job.standardReference,
        nistCategory: 'INTERRUPTED',
        success: false,
        fingerprintHash: 'CANCELLED_PARTIALLY_WIPED',
        entropyScore: 0.0,
        sampleCount: 0,
        commandLog: List<String>.from(job.logs)
          ..add('User cancelled sanitization - interrupted, state unknown.'),
        partitions: _buildPartitionOutcomes(job, false),
      ),
    );

    _devices = _devices.map((d) {
      if (d.stableId == job.device.stableId) {
        return DeviceProfile(
          id: d.id,
          name: d.name,
          serialNumber: d.serialNumber,
          mediaType: d.mediaType,
          busType: d.busType,
          capacityBytes: d.capacityBytes,
          rotationalRpm: d.rotationalRpm,
          isHardwareEncrypted: d.isHardwareEncrypted,
          supportsAtaSecureErase: d.supportsAtaSecureErase,
          supportsAtaSanitize: d.supportsAtaSanitize,
          supportsNvmeSanitize: d.supportsNvmeSanitize,
          supportsEmmcSanitize: d.supportsEmmcSanitize,
          supportsTrim: d.supportsTrim,
          hpaDcoPresent: d.hpaDcoPresent,
          mountPoint: d.mountPoint,
          isSystemDisk: d.isSystemDisk,
          hasFilesystem: d.hasFilesystem,
          fsType: d.fsType,
          isWipedNoFilesystem: d.isWipedNoFilesystem,
          notes: 'May be partially wiped (operation cancelled)',
          isRemovable: d.isRemovable,
          disabledReason: d.disabledReason,
        );
      }
      return d;
    }).toList();

    await _jobStateFile.clearActiveJob();
    notifyListeners();
  }

  /// Force stop the in-progress job immediately via SIGKILL upon user request.
  Future<void> forceStopCurrentJob() async {
    if (_currentJob == null) return;
    _cancelEscalationTimer?.cancel();
    _cancelEscalationTimer = null;
    _isCancelling = false;
    _showForceStop = false;

    _addLog('USER FORCE STOP: Terminating process immediately with SIGKILL...');
    _realSanitizeService.forceKillActiveProcess();

    final job = _currentJob!;
    job.status = JobStatus.failed;
    job.endTime = DateTime.now();
    job.currentStageDescription = 'interrupted, state unknown';
    _addLog('USER FORCE STOP: Job force stopped. Warning: Drive in interrupted, state unknown.');

    await _auditLogService.appendEntry(
      AuditLogEntry(
        timestamp: DateTime.now().toIso8601String(),
        jobId: job.jobId,
        deviceSerial: job.device.serialNumber,
        devicePath: job.device.id,
        deviceName: job.device.name,
        scope: job.isPartitionScope ? 'partial' : 'full',
        method: job.effectiveMethod.displayName,
        methodClass: _deriveMethodClass(job.effectiveMethod),
        standardReference: job.standardReference,
        nistCategory: 'INTERRUPTED',
        success: false,
        fingerprintHash: 'FORCE_STOPPED_UNVERIFIED',
        entropyScore: 0.0,
        sampleCount: 0,
        commandLog: List<String>.from(job.logs)
          ..add('User force stopped sanitization via SIGKILL - interrupted, state unknown.'),
        partitions: _buildPartitionOutcomes(job, false),
      ),
    );

    // Save interrupted state so checkpoint stays and discovery/recovery detects it
    await _jobStateFile.recordInterrupted(ActiveJobState(
      jobId: job.jobId,
      deviceSerial: job.device.serialNumber,
      devicePath: job.device.id,
      deviceName: job.device.name,
      method: job.effectiveMethod.displayName,
      startedAt: job.startTime?.toIso8601String() ?? DateTime.now().toIso8601String(),
    ));

    notifyListeners();
  }

  /// Handle window exit confirmation when a job is active.
  /// Records the job as "interrupted" (NOT cancelled) in JobStateFile.
  /// For software overwrite: child process is aborted / marked interrupted.
  /// For firmware sanitize: commands execute on storage controller firmware;
  /// cannot be aborted without bricking drive, so it is left running on hardware and
  /// recorded as "interrupted" (never reported as "cancelled").
  Future<void> interruptOnExit() async {
    if (_currentJob == null) return;
    final job = _currentJob!;

    // Save interrupted state to JobStateFile so next launch displays interrupted card
    await _jobStateFile.recordInterrupted(ActiveJobState(
      jobId: job.jobId,
      deviceSerial: job.device.serialNumber,
      devicePath: job.device.id,
      deviceName: job.device.name,
      method: job.effectiveMethod.displayName,
      startedAt: job.startTime?.toIso8601String() ?? DateTime.now().toIso8601String(),
    ));

    final isFirmware = !canCancelJob;
    job.status = JobStatus.failed;
    job.endTime = DateTime.now();

    if (isFirmware) {
      job.currentStageDescription = 'Interrupted: Firmware Sanitize in progress on hardware controller';
      _addLog('EXIT INTERRUPT: Firmware sanitize in progress on controller. Not cancelled.');
    } else {
      job.currentStageDescription = 'Interrupted: Partially Wiped';
      _addLog('EXIT INTERRUPT: Overwrite interrupted by user exit. Warning: Drive may be partially wiped.');
    }

    await _auditLogService.appendEntry(
      AuditLogEntry(
        timestamp: DateTime.now().toIso8601String(),
        jobId: job.jobId,
        deviceSerial: job.device.serialNumber,
        devicePath: job.device.id,
        deviceName: job.device.name,
        scope: job.isPartitionScope ? 'partial' : 'full',
        method: job.effectiveMethod.displayName,
        methodClass: _deriveMethodClass(job.effectiveMethod),
        standardReference: job.standardReference,
        nistCategory: 'INTERRUPTED',
        success: false,
        fingerprintHash: isFirmware ? 'INTERRUPTED_FIRMWARE' : 'INTERRUPTED_PARTIALLY_WIPED',
        entropyScore: 0.0,
        sampleCount: 0,
        commandLog: List<String>.from(job.logs)
          ..add('Application exited during wipe - interrupted, state unknown.'),
        partitions: _buildPartitionOutcomes(job, false),
      ),
    );

    notifyListeners();
  }

  DeviceProfile? attachOrphan() {
    if (_orphanResult?.activeJobState != null) {
      final active = _orphanResult!.activeJobState!;
      DeviceProfile? targetDevice = _devices.cast<DeviceProfile?>().firstWhere(
        (d) => d!.serialNumber == active.deviceSerial || d.id == active.devicePath || d.name == active.deviceName,
        orElse: () => null,
      );
      targetDevice ??= DeviceProfile(
        id: active.devicePath,
        name: active.deviceName,
        serialNumber: active.deviceSerial,
        mediaType: MediaType.unknown,
        busType: 'Unknown',
        capacityBytes: 0,
      );
      _selectedDevice = targetDevice;
      _currentJob = SanitizationJob(
        jobId: active.jobId,
        device: targetDevice,
        dataSensitivity: DataSensitivity.confidential,
        deviceCondition: DeviceCondition.functional,
        disposalPath: DisposalPath.recycling,
        riskScore: 50,
        targetCategory: NistCategory.clear,
        recommendedMethod: SanitizationMethod.singlePassOverwrite,
        standardReference: 'NIST SP 800-88 Rev. 1 (Clear)',
        explanationText: 'Observing in-progress sanitization pipeline',
        status: JobStatus.sanitizing,
        startTime: DateTime.tryParse(active.startedAt) ?? DateTime.now(),
        progress: 0.5,
        currentStageDescription: 'Observing in-progress wipe (attached to PID ${_orphanResult?.pid ?? "active"})...',
      );
      _orphanResult = null;
      notifyListeners();
      return targetDevice;
    }
    return null;
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
  bool get isSimulated => !_isRealMode;

  @visibleForTesting
  set isSimulated(bool value) {
    _isRealMode = !value;
    notifyListeners();
  }
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
    if (isJobRunning) return;
    _isRealMode = value;
    if (_isRealMode) {
      _startAutoPolling();
    } else {
      _stopAutoPolling();
    }
    await refreshDevices();
  }

  bool _isMockingDevices = false;

  Future<void> refreshDevices({bool silent = false}) async {
    if (_isMockingDevices || _isDisposed) return;
    final freshDevices = await _intelligenceService.discoverDevices(realMode: _isRealMode);
    if (_isMockingDevices || _isDisposed) return;

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
      if (isJobRunning && _currentJob != null) {
        final target = _currentJob!.device;
        final stillPresent = _devices.any((d) =>
            d.stableId == target.stableId ||
            (d.id == target.id && d.capacityBytes == target.capacityBytes));
        if (!stillPresent) {
          // Mid-job disappearance = "interrupted"
          final job = _currentJob!;
          job.status = JobStatus.failed;
          job.endTime = DateTime.now();
          job.currentStageDescription = 'Drive Disconnected: Sanitization Interrupted';
          _addLog('ERROR: Drive ${target.name} (${target.id}) was disconnected during operation.');
          _auditLogService.appendEntry(
            AuditLogEntry(
              timestamp: DateTime.now().toIso8601String(),
              jobId: job.jobId,
              deviceSerial: target.serialNumber,
              devicePath: target.id,
              deviceName: target.name,
              scope: job.isPartitionScope ? 'partial' : 'full',
              method: job.effectiveMethod.displayName,
              methodClass: _deriveMethodClass(job.effectiveMethod),
              standardReference: job.standardReference,
              nistCategory: 'INTERRUPTED',
              success: false,
              fingerprintHash: 'DISCONNECTED_INTERRUPTED',
              entropyScore: 0.0,
              sampleCount: 0,
              commandLog: List<String>.from(job.logs)
                ..add('Drive disconnected during operation - interrupted, state unknown.'),
              partitions: _buildPartitionOutcomes(job, false),
            ),
          );
          _jobStateFile.clearActiveJob();
        }
      }
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
      if (!_isDisposed) {
        notifyListeners();
      }
    }
  }

  @override
  void dispose() {
    _isDisposed = true;
    _stopAutoPolling();
    _stallWatchdogTimer?.cancel();
    super.dispose();
  }

  void selectDevice(DeviceProfile device) {
    if (isJobRunning) return;
    _selectedDevice = device;
    _selectedPartition = null;
    _updateJobRecommendation();
    notifyListeners();
  }

  void selectPartition(PartitionInfo? partition) {
    if (isJobRunning) return;
    _selectedPartition = partition;
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
      sensitivity: _dataSensitivity,
    );

    var effectiveRecMethod = recResult.method;
    var standardRef = recResult.standardReference;
    var explanation = recResult.explanation;

    if (_selectedPartition != null) {
      if (effectiveRecMethod != SanitizationMethod.singlePassOverwrite &&
          effectiveRecMethod != SanitizationMethod.multiPassOverwrite) {
        effectiveRecMethod = SanitizationMethod.singlePassOverwrite;
        standardRef = 'NIST SP 800-88 R1 Clear (Partition Scope Overwrite)';
        explanation = 'Partition-scoped wiping only supports overwrite methods. Firmware sanitize and crypto commands affect the whole drive and cannot be scoped to a single partition.';
      }
    }

    final jobId = 'JOB-${DateTime.now().millisecondsSinceEpoch.toString().substring(6)}';

    _currentJob = SanitizationJob(
      jobId: jobId,
      device: device,
      dataSensitivity: _dataSensitivity,
      deviceCondition: _deviceCondition,
      disposalPath: _disposalPath,
      riskScore: riskResult.score,
      targetCategory: riskResult.targetCategory,
      recommendedMethod: effectiveRecMethod,
      standardReference: standardRef,
      explanationText: explanation,
      targetPartition: _selectedPartition,
      shouldSimulateFailure: _simulateFailureMode,
    );

    _lastPolicyResult = _policyLayer.validateOperation(_currentJob!);
  }

  void setOverriddenMethod(SanitizationMethod? method) {
    if (_currentJob != null && !isJobRunning) {
      _currentJob!.overriddenMethod = method;
      _lastPolicyResult = _policyLayer.validateOperation(_currentJob!);
      notifyListeners();
    }
  }

  void setDestroyAcknowledged(bool acknowledged) {
    if (_currentJob != null) {
      _currentJob!.destroyAcknowledged = acknowledged;
      notifyListeners();
    }
  }

  // Orchestrate simulated or real pipeline execution
  @visibleForTesting
  Future<void> runSanitizationPipelineForTesting() async => _runSanitizationPipeline();

  Future<void> _runSanitizationPipeline() async {
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
        job.progress = null; // Honest indeterminate state
        job.currentStageDescription = 'Preparing device: zt_engine handling partition unmounts...';
        _addLog('SYSTEM: Initializing device preparation (zt_engine managing unmount)...');
        notifyListeners();

        // Stage 2: Sanitization execution
        job.status = JobStatus.sanitizing;
        job.progress = null; // Honest indeterminate state until write progress arrives
        job.currentStageDescription = 'Executing real-hardware sanitization...';
        notifyListeners();

        await _jobStateFile.saveActiveJob(ActiveJobState(
          jobId: job.jobId,
          deviceSerial: job.device.serialNumber,
          devicePath: job.isPartitionScope
              ? job.targetPartition!.devicePath
              : (job.device.id.startsWith('real_') ? '/dev/${job.device.id.substring(5)}' : '/dev/sdb'),
          deviceName: job.device.name,
          method: job.effectiveMethod.displayName,
          startedAt: job.startTime?.toIso8601String() ?? DateTime.now().toIso8601String(),
          partitionNumber: job.targetPartition?.partitionNumber,
          partitionStartSector: job.targetPartition?.startSector,
          partitionSizeSectors: job.targetPartition?.sizeSectors,
          scope: job.isPartitionScope ? 'partial' : 'full',
          limitation: job.isPartitionScope
              ? 'Partition wipe: partition table and unselected sectors are not overwritten'
              : null,
        ));

        _lastHeartbeatTime = DateTime.now();
        _isStalled = false;
        _stallWatchdogTimer?.cancel();
        _stallWatchdogTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
          if (job.status == JobStatus.sanitizing && _lastHeartbeatTime != null) {
            final secondsSinceHeartbeat = DateTime.now().difference(_lastHeartbeatTime!).inSeconds;
            if (secondsSinceHeartbeat >= 30 && !_isStalled) {
              _isStalled = true;
              job.currentStageDescription = 'Drive I/O stalled - waiting for hardware response...';
              _addLog('WARNING: No progress or heartbeat received for ${secondsSinceHeartbeat}s; drive I/O may be stalled.');
              notifyListeners();
            } else if (secondsSinceHeartbeat < 30 && _isStalled) {
              _isStalled = false;
              notifyListeners();
            }
          }
        });

        final report = await _realSanitizeService.executeSanitization(
          device: job.device,
          method: job.effectiveMethod,
          confirmationToken: job.device.serialNumber, // verified by dialog retype
          deviceSerial: job.device.serialNumber,
          targetPartition: job.targetPartition,
          dryRun: false,
          onProgress: (event) {
            _lastHeartbeatTime = DateTime.now();
            if (_isStalled) {
              _isStalled = false;
            }
            if (event.isHeartbeat) {
              notifyListeners();
              return;
            }

            _currentSpeedBytesPerSec = event.speedBytesPerSec;
            _currentEtaSeconds = event.etaSeconds;

            // Firmware sanitize methods have percent == null -> indeterminate
            // Software overwrite has real percent computed by native engine
            job.progress = event.percent;

            if (event.bytesTotal > 0 && event.bytesDone > 0) {
              final doneGb = (event.bytesDone / 1e9).toStringAsFixed(1);
              final totalGb = (event.bytesTotal / 1e9).toStringAsFixed(1);
              final speedMb = (event.speedBytesPerSec / 1e6).toStringAsFixed(1);
              final etaStr = event.etaSeconds != null && event.speedBytesPerSec > 1024
                  ? 'ETA: ${event.etaSeconds}s'
                  : 'Estimating ETA...';
              job.currentStageDescription = '${event.message} ($doneGb / $totalGb GB @ $speedMb MB/s, $etaStr)';
            } else {
              job.currentStageDescription = event.message;
            }

            final pctStr = event.percent != null ? ' (${(event.percent! * 100).toInt()}%)' : '';
            _addLog('PROGRESS: [${event.phase}] ${event.message}$pctStr');
            notifyListeners();
          },
          onRawLog: (rawLine) {
            _addLog(rawLine);
            notifyListeners();
          },
        );

        _stallWatchdogTimer?.cancel();
        _stallWatchdogTimer = null;
        _cancelEscalationTimer?.cancel();
        _cancelEscalationTimer = null;
        _isCancelling = false;
        _showForceStop = false;

        if (!report.success) {
          job.status = JobStatus.failed;
          job.endTime = DateTime.now();
          if (report.exitCode == 130) {
            job.currentStageDescription = 'Sanitization Cancelled: Partially Wiped';
            _addLog('CANCEL: Sanitization cancelled by user. Partially wiped.');
          } else {
            job.currentStageDescription = 'Sanitization Failed: ${report.stderr}';
            _addLog('ERROR: Sanitization command failed with code ${report.exitCode}');
            _addLog('ERROR Details: ${report.stderr}');
          }
          await _jobStateFile.clearActiveJob();
          notifyListeners();
          return;
        }

        // ── Disk operation succeeded. Record this fact BEFORE post-processing ──
        // From this point forward, any exception is a post-processing failure
        // (certificate signing, audit log), NOT a disk operation failure.
        final bool diskWipeSucceeded = true;
        job.wipeCompleted = true;

        // Stage 3: Verification LBA sampling
        job.status = JobStatus.verifying;
        job.progress = null; // Indeterminate during LBA sampling
        job.currentStageDescription = 'Verifying sector erasure via LBA sampling...';
        _addLog('VERIFICATION: Running post-sanitize verify LBA sampling...');
        notifyListeners();

        final cliMethod = _realSanitizeService.mapMethodToCliArg(job.effectiveMethod, job.device);
        final isCryptoMethod = job.effectiveMethod == SanitizationMethod.cryptographicErase ||
            report.methodUsed.toLowerCase().contains('crypto') ||
            report.methodUsed.toLowerCase().contains('reverttper');
        final expectZeros = !isCryptoMethod;

        RealVerificationReport? verifyReport;
        try {
          verifyReport = await _realSanitizeService.executeVerification(
            device: job.device,
            method: cliMethod,
            deviceSerial: job.device.serialNumber,
            targetPartition: job.targetPartition,
            sampleCount: 50,
            expectZeros: expectZeros,
          );
        } catch (verifyErr) {
          _addLog('WARNING: Verification sampling failed: $verifyErr');
          _addLog('NOTE: Disk write operation itself completed successfully.');
        }

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
          _completedCertificate = _certificateService.generateCertificate(
            job: job,
            evidence: evidence,
            executionMode: 'real',
            actualMethodExecuted: report.methodUsed,
            verificationSampleCount: verifyReport?.sampleCount,
            verificationEntropyScore: verifyReport?.entropyScore,
          );
          _addLog('CERTIFICATE: Issued ${completedCertificate!.certificateId} signed with ECDSA P-256 key.');
        } catch (certErr) {
          _addLog('WARNING: Certificate generation failed: $certErr');
          _addLog('NOTE: The disk sanitization itself completed successfully.');
          job.currentStageDescription = 'Sanitization succeeded. Certificate generation failed — see logs.';
        }

        if (verifyReport != null) {
          _addLog('VERIFICATION: Entropy score: ${verifyReport.entropyScore}. Fingerprint: ${verifyReport.fingerprintHash}');
        }

        String? certSha;
        if (completedCertificate != null) {
          try {
            final (_, sha) = await _auditLogService.saveCertificate(_completedCertificate!);
            certSha = sha;
          } catch (_) {}
        }

        try {
          final auditEntry = AuditLogEntry(
            timestamp: DateTime.now().toIso8601String(),
            jobId: job.jobId,
            deviceSerial: job.device.serialNumber,
            devicePath: job.isPartitionScope
                ? job.targetPartition!.devicePath
                : (job.device.id.startsWith('real_')
                    ? '/dev/${job.device.id.substring(5)}'
                    : '/dev/null'),
            deviceName: job.device.name,
            scope: job.isPartitionScope ? 'partial' : 'full',
            method: job.recommendedMethod.displayName,
            methodClass: _deriveMethodClass(job.effectiveMethod),
            standardReference: job.standardReference,
            nistCategory: job.effectiveNistCategoryDisplayName,
            success: diskWipeSucceeded && verificationPassed,
            verificationPassed: verificationPassed,
            certificateId: _completedCertificate?.certificateId,
            certificateSha256: certSha,
            fingerprintHash: verifyReport?.fingerprintHash ?? 'UNAVAILABLE',
            entropyScore: verifyReport?.entropyScore ?? 0.0,
            sampleCount: verifyReport?.sampleCount ?? 0,
            commandLog: report.commandLog,
            isSimulated: false,
            partitions: _buildPartitionOutcomes(job, diskWipeSucceeded && verificationPassed),
          );
          await _auditLogService.appendEntry(auditEntry);
        } catch (auditErr) {
          _addLog('WARNING: Audit log write failed: $auditErr');
        }

        await _jobStateFile.clearActiveJob();
        notifyListeners();
      } catch (e) {
        job.status = JobStatus.failed;
        job.endTime = DateTime.now();
        job.currentStageDescription = 'Execution Error: $e';
        _addLog('ERROR: $e');

        try {
          final evidence = _verificationService.verify(job, isSuccess: false);
          final report = _certificateService.generateCertificate(
            job: job,
            evidence: evidence,
            executionMode: 'real',
          );
          _completedCertificate = report;
          final (_, reportSha) = await _auditLogService.saveFailureReport(report);
          await _auditLogService.appendEntry(AuditLogEntry(
            timestamp: DateTime.now().toIso8601String(),
            jobId: job.jobId,
            deviceSerial: job.device.serialNumber,
            devicePath: job.isPartitionScope
                ? job.targetPartition!.devicePath
                : (job.device.id.startsWith('real_') ? '/dev/${job.device.id.substring(5)}' : '/dev/null'),
            deviceName: job.device.name,
            scope: job.isPartitionScope ? 'partial' : 'full',
            method: job.recommendedMethod.displayName,
            methodClass: _deriveMethodClass(job.effectiveMethod),
            standardReference: job.standardReference,
            nistCategory: job.effectiveNistCategoryDisplayName,
            success: false,
            verificationPassed: false,
            certificateId: report.certificateId,
            certificateSha256: reportSha,
            fingerprintHash: 'EXECUTION_FAILED',
            entropyScore: 0.0,
            sampleCount: 0,
            commandLog: List<String>.from(job.logs),
            isSimulated: false,
            partitions: _buildPartitionOutcomes(job, false),
          ));
        } catch (_) {}

        await _jobStateFile.clearActiveJob();
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
    job.currentStageDescription = 'Executing ${job.effectiveMethod.displayName}...';
    _addLog('EXECUTION: Invoking controller command payload [Simulated Engine]...');

    await _jobStateFile.saveActiveJob(ActiveJobState(
      jobId: job.jobId,
      deviceSerial: job.device.serialNumber,
      devicePath: '/dev/sdb',
      deviceName: job.device.name,
      method: job.effectiveMethod.displayName,
      startedAt: job.startTime?.toIso8601String() ?? DateTime.now().toIso8601String(),
    ));

    // Progress updates during sanitization
    for (int p = 45; p <= 80; p += 10) {
      await Future.delayed(const Duration(milliseconds: 400));
      job.progress = p / 100.0;
      _addLog('PROGRESS: ${job.effectiveMethod.displayName} - $p% complete');
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
      _completedCertificate = _certificateService.generateCertificate(
        job: job,
        evidence: evidence,
        executionMode: 'simulated',
      );
      try {
        final (_, reportSha) = await _auditLogService.saveFailureReport(_completedCertificate!);
        await _auditLogService.appendEntry(AuditLogEntry(
          timestamp: DateTime.now().toIso8601String(),
          jobId: job.jobId,
          deviceSerial: job.device.serialNumber,
          devicePath: '/dev/sdb',
          deviceName: job.device.name,
          scope: job.isPartitionScope ? 'partial' : 'full',
          method: job.effectiveMethod.displayName,
          methodClass: _deriveMethodClass(job.effectiveMethod),
          standardReference: job.standardReference,
          nistCategory: job.effectiveNistCategoryDisplayName,
          success: false,
          verificationPassed: false,
          certificateId: _completedCertificate!.certificateId,
          certificateSha256: reportSha,
          fingerprintHash: 'SIMULATED_FAILURE',
          entropyScore: 0.0,
          sampleCount: 0,
          commandLog: List<String>.from(job.logs),
          isSimulated: true,
          partitions: _buildPartitionOutcomes(job, false),
        ));
      } catch (_) {}

      await _jobStateFile.clearActiveJob();
      notifyListeners();
      return;
    }

    // Stage 3: Verification (Simulated Mode)
    job.wipeCompleted = true;
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
    _completedCertificate = _certificateService.generateCertificate(
      job: job,
      evidence: evidence,
      executionMode: 'simulated',
    );
    _addLog('CERTIFICATE: Issued ${completedCertificate!.certificateId} signed with ECDSA P-256 key.');

    try {
      final (_, certSha) = await _auditLogService.saveCertificate(_completedCertificate!);
      await _auditLogService.appendEntry(AuditLogEntry(
        timestamp: DateTime.now().toIso8601String(),
        jobId: job.jobId,
        deviceSerial: job.device.serialNumber,
        devicePath: '/dev/sdb',
        deviceName: job.device.name,
        scope: job.isPartitionScope ? 'partial' : 'full',
        method: job.effectiveMethod.displayName,
        methodClass: _deriveMethodClass(job.effectiveMethod),
        standardReference: job.standardReference,
        nistCategory: job.effectiveNistCategoryDisplayName,
        success: true,
        verificationPassed: true,
        certificateId: _completedCertificate!.certificateId,
        certificateSha256: certSha,
        fingerprintHash: evidence.evidenceHash,
        entropyScore: 0.0,
        sampleCount: 50,
        commandLog: List<String>.from(job.logs),
        isSimulated: true,
        partitions: _buildPartitionOutcomes(job, true),
      ));
    } catch (_) {}

    await _jobStateFile.clearActiveJob();
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

  @visibleForTesting
  void setMockDevices(List<DeviceProfile> devices) {
    _isMockingDevices = true;
    _devices = devices;
    if (_devices.isNotEmpty) {
      _selectedDevice = _devices.first;
    }
    notifyListeners();
  }

  @visibleForTesting
  void setMockOrphanResult(OrphanCheckResult? result) {
    _orphanResult = result;
    notifyListeners();
  }

  @visibleForTesting
  void setMockJob(SanitizationJob? job) {
    _currentJob = job;
    notifyListeners();
  }

  @visibleForTesting
  void setMockCompletedCertificate(SanitizationCertificate? cert) {
    _completedCertificate = cert;
    notifyListeners();
  }
}
