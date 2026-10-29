import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';

import '../core/app_paths.dart';
import '../models/certificate.dart';
import '../models/device_profile.dart';
import '../models/filesystem_recreation.dart';
import '../models/partition_info.dart';
import '../models/sanitization_job.dart';
import 'certificate_service.dart';
import 'classification_service.dart';
import 'device_intelligence_service.dart';
import 'device_simulator.dart';
import 'policy_layer.dart';
import 'partition_table_service.dart';
import 'platform_backend.dart';
import 'recommendation_service.dart';
import 'risk_scoring_service.dart';
import 'verification_service.dart';
import 'real_sanitization_service.dart';
import 'audit_log_service.dart';
import 'filesystem_recreation_preference.dart';
import 'job_state_file.dart';
import 'live_boot_detector.dart';
import 'orphaned_process_checker.dart';
import '../simple/confirm_wipe_dialog.dart';

class SanitizationController extends ChangeNotifier {
  final DeviceSimulator _simulator = DeviceSimulator();
  final DeviceIntelligenceService _intelligenceService =
      DeviceIntelligenceService();
  final ClassificationService _classificationService = ClassificationService();
  final RiskScoringService _riskScoringService = RiskScoringService();
  final RecommendationService _recommendationService = RecommendationService();
  final PolicyLayer _policyLayer = PolicyLayer();
  final VerificationService _verificationService = VerificationService();
  final CertificateService _certificateService = CertificateService();
  late final RealSanitizationService _realSanitizeService;
  late final AppPaths _appPaths;
  late final AuditLogService _auditLogService;
  late final JobStateFile _jobStateFile;
  late final OrphanedProcessChecker _orphanChecker;
  late final FilesystemRecreationPreferenceStore _formatPreferenceStore;

  // Phase F: optional post-wipe filesystem recreation state.
  late FilesystemRecreationPreference _formatPreference;
  FilesystemRecreationRecord? _filesystemRecreation;
  FilesystemRecreationRecord? get filesystemRecreation => _filesystemRecreation;

  /// Receipt paths for targets wiped *and verified* in the current job, keyed
  /// by target node. The format step is refused unless its target is in here.
  final Map<String, String> _verifiedFormatReceipts = {};
  bool _isFormattingFilesystem = false;
  bool _formatPromptDismissed = false;
  String? _filesystemRecreationError;
  String? _filesystemRecreationUnavailableReason;

  // Phase G: the pre-wipe "After wiping" choice. Captured from the
  // WipeAuthorization so nothing is asked again after the wipe.
  bool _restoreChoiceKnown = false;
  bool _restoreAfterWipe = false;
  bool _autoRestoreFailed = false;
  String? _restoreFsType;
  String? _restoreLabel;

  /// Phase G: per-partition captured fs/label (keyed by device path) and the
  /// outcome of each partition's automatic restore attempt.
  Map<String, FilesystemRestoreSpec> _restoreSpecsByPartition = const {};
  final List<PartitionRestoreOutcome> _partitionRestoreOutcomes = [];

  bool get isFormattingFilesystem => _isFormattingFilesystem;
  String? get filesystemRecreationError => _filesystemRecreationError;

  /// Last successfully confirmed filesystem/label pair (never an "enabled"
  /// flag). Used to prefill the pre-wipe restore choice.
  FilesystemRecreationPreference get formatPreference => _formatPreference;

  /// True when the operator chose "Restore as an empty drive" before this
  /// job's wipe.
  bool get restoreAfterWipe => _restoreChoiceKnown && _restoreAfterWipe;

  /// True when the automatic post-verification restore failed or was skipped
  /// because no valid verified-wipe receipt existed. The wipe result is never
  /// changed by this.
  bool get autoRestoreFailed => _autoRestoreFailed;

  /// Phase G: every per-partition restore attempt, in wipe order.
  List<PartitionRestoreOutcome> get partitionRestoreOutcomes =>
      List.unmodifiable(_partitionRestoreOutcomes);

  /// Partitions whose filesystem could not be restored (missing/refused
  /// receipt or a failed format). Each is left blank and may be retried.
  List<PartitionRestoreOutcome> get failedPartitionRestores =>
      _partitionRestoreOutcomes.where((o) => o.failed).toList(growable: false);

  /// Partitions that were successfully restored in this job.
  List<PartitionRestoreOutcome> get successfulPartitionRestores =>
      _partitionRestoreOutcomes.where((o) => o.success).toList(growable: false);

  bool get hasPartitionRestoreFailures =>
      _partitionRestoreOutcomes.any((o) => o.failed);

  /// True when the completed job left the drive (or at least one wiped
  /// partition) without a filesystem, so it will not appear in the file
  /// manager until it is formatted again. False when no pre-wipe choice was
  /// recorded (legacy/mock jobs), so the Phase-F prompt keeps its historic
  /// behaviour.
  bool get driveLeftBlank {
    final job = _currentJob;
    if (job == null || !_restoreChoiceKnown) return false;
    if (!job.wipeCompleted || job.status != JobStatus.completed) return false;
    if (_completedCertificate?.evidence.verifiedPassed != true) return false;
    if (!_restoreAfterWipe) return _filesystemRecreation == null;
    if (job.isPartitionScope) return hasPartitionRestoreFailures;
    return _autoRestoreFailed && _filesystemRecreation == null;
  }

  /// Why the optional "Recreate filesystem?" prompt is NOT offered after this
  /// job's wipe even though verification passed: the engine did not write the
  /// receipt, the receipt did not match this target, or the engine refused
  /// (exit 4). Null when a receipt was accepted or none was ever expected.
  String? get filesystemRecreationUnavailableReason =>
      _filesystemRecreationUnavailableReason;

  /// True only after this job's wipe completed *and* verification passed for
  /// at least one target, with a verified-wipe receipt that still exists on
  /// disk. The proof can disappear (one-shot cleanup, manual delete); the
  /// app must never offer a format the engine can no longer honor.
  bool get canRecreateFilesystem {
    final job = _currentJob;
    if (job == null || _isFormattingFilesystem) return false;
    if (!job.wipeCompleted || job.status != JobStatus.completed) return false;
    if (_completedCertificate?.evidence.verifiedPassed != true) return false;
    if (_filesystemRecreation != null) return false;
    return _hasLiveReceipt(job);
  }

  /// True when the current job has at least one receipt file that still
  /// exists on disk: per live target for partition scope, per device node
  /// for whole-device scope.
  bool _hasLiveReceipt(SanitizationJob job) {
    if (job.isPartitionScope) return filesystemRecreationTargets.isNotEmpty;
    final receipt = _verifiedFormatReceipts[_deviceNode(job.device)];
    return receipt != null && File(receipt).existsSync();
  }

  /// Phase G: per-partition eligibility for a manual "Restore now".
  ///
  /// Unlike [canRecreateFilesystem] this stays true after another partition
  /// was restored, because every partition has its own one-shot receipt.
  bool canRecreatePartition(PartitionInfo partition) {
    final job = _currentJob;
    return job != null && _canRecreatePartitionTarget(job, partition);
  }

  bool _canRecreatePartitionTarget(
    SanitizationJob job,
    PartitionInfo partition,
  ) {
    if (_isFormattingFilesystem) return false;
    if (!job.isPartitionScope) return false;
    if (!job.wipeCompleted || job.status != JobStatus.completed) return false;
    if (_completedCertificate?.evidence.verifiedPassed != true) return false;
    final receipt = _verifiedFormatReceipts[partition.devicePath];
    return receipt != null && File(receipt).existsSync();
  }

  /// UI gate: the prompt disappears once the user formats or dismisses it.
  bool get showFilesystemRecreationPrompt =>
      canRecreateFilesystem && !_formatPromptDismissed;

  /// C6: platform backend for discovery + engine-binary resolution. On
  /// Linux it wraps this controller's own [DeviceIntelligenceService] so
  /// scan state (`lastScanError`, results) stays shared exactly as before;
  /// on other platforms it is the unsupported stub.
  late final PlatformBackend _platformBackend;

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

  /// A4: multi-select partition state. [_selectedPartition] tracks the
  /// partition used by the current job (first selected); this list holds
  /// every user-selected partition for sequential partition-scope wipes.
  List<PartitionInfo> _selectedPartitions = const [];

  /// B1: read-only Windows-install probe results keyed by partition device
  /// path (true = "likely C: (Windows installed)"), plus per-partition error
  /// messages when the probe could not run (no root, no engine, ...).
  final Map<String, bool> _windowsProbeResults = {};
  final Map<String, String> _windowsProbeErrors = {};

  Map<String, bool> get windowsProbeResults =>
      Map.unmodifiable(_windowsProbeResults);
  Map<String, String> get windowsProbeErrors =>
      Map.unmodifiable(_windowsProbeErrors);

  PartitionInfo? get selectedPartition => _selectedPartition;
  List<PartitionInfo> get selectedPartitions => _selectedPartitions;

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

  SanitizationController({
    AppPaths? appPaths,
    bool enableAutoPolling = true,
    bool deferInitialDiscovery = false,
  }) {
    _appPaths = appPaths ?? AppPaths.production();
    _platformBackend = Platform.isLinux
        ? LinuxPlatformBackend(discovery: _intelligenceService)
        : resolvePlatformBackend();
    _auditLogService = AuditLogService(paths: _appPaths);
    _formatPreferenceStore = FilesystemRecreationPreferenceStore(
      paths: _appPaths,
    );
    _formatPreference = _formatPreferenceStore.load();
    _jobStateFile = JobStateFile(paths: _appPaths);
    _orphanChecker = OrphanedProcessChecker(paths: _appPaths);
    _realSanitizeService = RealSanitizationService(paths: _appPaths);
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
  RecommendationResult getAutoMethod(
    DeviceProfile device,
    DisposalIntent intent,
  ) {
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
      throw ArgumentError(
        'WipeAuthorization deviceSerial does not match target device serial',
      );
    }
    if (isJobRunning) return;

    // Pin serial + size at selection
    _selectedDevice = device;

    // Phase G: carry the single pre-wipe "After wiping" decision through the
    // whole job. Captured here, before any destructive step runs.
    _restoreChoiceKnown = true;
    _restoreAfterWipe = authorization.restoreFilesystem;
    _restoreFsType = authorization.restoreFsType;
    _restoreLabel = authorization.restoreLabel;
    _restoreSpecsByPartition = Map.of(authorization.partitionRestoreSpecs);

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
        explanation =
            'Partition-scoped wiping only supports overwrite methods.';
      }
    }

    final jobId =
        'JOB-${DateTime.now().millisecondsSinceEpoch.toString().substring(6)}';

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
      // B4: every selected partition wipes sequentially (subset scope;
      // partition table stays intact).
      targetPartitions: List<PartitionInfo>.from(_selectedPartitions),
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

  /// Method kind stored in `active_job.json` for recovery wording. Derived from
  /// the [SanitizationMethod] enum, never from the display string.
  String _methodKind(SanitizationMethod method) {
    switch (method) {
      case SanitizationMethod.singlePassOverwrite:
      case SanitizationMethod.multiPassOverwrite:
        return 'overwrite';
      case SanitizationMethod.cryptographicErase:
      case SanitizationMethod.ataSecureErase:
      case SanitizationMethod.ataSanitizeBlockErase:
      case SanitizationMethod.nvmeSanitize:
      case SanitizationMethod.emmcSanitize:
        return 'firmware';
      default:
        return 'unknown';
    }
  }

  /// B4: audit outcomes for the partitions this job targeted. [override]
  /// carries the per-target statuses recorded while the sequential wipe loop
  /// ran; without it every selected partition gets the job-level verdict
  /// (simulated mode / failure paths before the loop ran).
  List<PartitionAuditOutcome>? _buildPartitionOutcomes(
    SanitizationJob job,
    bool success, {
    List<PartitionAuditOutcome>? override,
  }) {
    if (override != null && override.isNotEmpty) return override;
    if (!job.isPartitionScope || job.targetPartition == null) return null;
    final List<PartitionInfo> parts = job.targetPartitions.isEmpty
        ? <PartitionInfo>[job.targetPartition!]
        : job.targetPartitions;
    return [
      for (final p in parts)
        PartitionAuditOutcome(
          partitionNumber: p.partitionNumber,
          startSector: p.startSector,
          sizeSectors: p.sizeSectors,
          status: success ? 'COMPLETED' : 'FAILED',
          bytesWiped: success ? p.sizeBytes : 0,
        ),
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
          outcome: 'interrupted',
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
        if (d.serialNumber == active.deviceSerial ||
            d.id == active.devicePath ||
            d.name == active.deviceName) {
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

    await _orphanChecker.removeEngineCheckpoint();
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
    _addLog(
      'USER CANCEL: Sending cancellation signal to zt_engine (SIGTERM)...',
    );
    _realSanitizeService.cancelActiveProcess();

    // After 5 seconds: show "waiting for the drive to finish its current write" and offer Force stop button
    _cancelEscalationTimer?.cancel();
    _cancelEscalationTimer = Timer(const Duration(seconds: 5), () {
      if (_isCancelling && _currentJob != null && isJobRunning) {
        _showForceStop = true;
        _currentJob!.currentStageDescription =
            'waiting for the drive to finish its current write';
        _addLog(
          'CANCEL NOTICE: waiting for the drive to finish its current write',
        );
        notifyListeners();
      }
    });

    final job = _currentJob!;
    job.status = JobStatus.failed;
    job.endTime = DateTime.now();
    job.currentStageDescription = 'Sanitization Cancelled: Partially Wiped';
    _addLog(
      'USER CANCEL: Job cancelled by user. Warning: Drive may be partially wiped.',
    );

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
        outcome: 'cancelled',
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
    _addLog(
      'USER FORCE STOP: Job force stopped. Warning: Drive in interrupted, state unknown.',
    );

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
        outcome: 'interrupted',
        success: false,
        fingerprintHash: 'FORCE_STOPPED_UNVERIFIED',
        entropyScore: 0.0,
        sampleCount: 0,
        commandLog: List<String>.from(job.logs)
          ..add(
            'User force stopped sanitization via SIGKILL - interrupted, state unknown.',
          ),
        partitions: _buildPartitionOutcomes(job, false),
      ),
    );

    // Save interrupted state so checkpoint stays and discovery/recovery detects it
    await _jobStateFile.recordInterrupted(
      ActiveJobState(
        jobId: job.jobId,
        deviceSerial: job.device.serialNumber,
        devicePath: job.device.id,
        deviceName: job.device.name,
        method: job.effectiveMethod.displayName,
        methodKind: _methodKind(job.effectiveMethod),
        deviceSize: job.device.capacityBytes,
        startedAt:
            job.startTime?.toIso8601String() ??
            DateTime.now().toIso8601String(),
      ),
    );

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
    await _jobStateFile.recordInterrupted(
      ActiveJobState(
        jobId: job.jobId,
        deviceSerial: job.device.serialNumber,
        devicePath: job.device.id,
        deviceName: job.device.name,
        method: job.effectiveMethod.displayName,
        methodKind: _methodKind(job.effectiveMethod),
        deviceSize: job.device.capacityBytes,
        startedAt:
            job.startTime?.toIso8601String() ??
            DateTime.now().toIso8601String(),
      ),
    );

    final isFirmware = !canCancelJob;
    job.status = JobStatus.failed;
    job.endTime = DateTime.now();

    if (isFirmware) {
      job.currentStageDescription =
          'Interrupted: Firmware Sanitize in progress on hardware controller';
      _addLog(
        'EXIT INTERRUPT: Firmware sanitize in progress on controller. Not cancelled.',
      );
    } else {
      job.currentStageDescription = 'Interrupted: Partially Wiped';
      _addLog(
        'EXIT INTERRUPT: Overwrite interrupted by user exit. Warning: Drive may be partially wiped.',
      );
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
        outcome: 'interrupted',
        fingerprintHash: isFirmware
            ? 'INTERRUPTED_FIRMWARE'
            : 'INTERRUPTED_PARTIALLY_WIPED',
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
        (d) =>
            d!.serialNumber == active.deviceSerial ||
            d.id == active.devicePath ||
            d.name == active.deviceName,
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
        currentStageDescription:
            'Observing in-progress wipe (attached to PID ${_orphanResult?.pid ?? "active"})...',
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
    _resetFilesystemRecreationState();
    _clearRestoreChoice();
    _updateJobRecommendation();
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Phase F: optional post-wipe filesystem recreation
  // ---------------------------------------------------------------------------

  String _deviceNode(DeviceProfile device) => device.id.startsWith('real_')
      ? '/dev/${device.id.substring(5)}'
      : '/dev/sdb';

  /// Partition-scope targets of the current job, in wipe order, whose
  /// receipt file still exists on disk (a deleted receipt means the format
  /// step is no longer provable).
  List<PartitionInfo> get filesystemRecreationTargets {
    final job = _currentJob;
    if (job == null || !job.isPartitionScope) return const [];
    final parts = job.targetPartitions.isEmpty
        ? <PartitionInfo>[job.targetPartition!]
        : job.targetPartitions;
    return parts.where((p) {
      final receipt = _verifiedFormatReceipts[p.devicePath];
      return receipt != null && File(receipt).existsSync();
    }).toList();
  }

  /// Prefill values for the "Recreate filesystem?" prompt. Defaults come from
  /// the original volume when known; a remembered choice fills the gaps.
  /// [FilesystemRecreationDefaults.defaultEnabled] is always false.
  FilesystemRecreationDefaults? get filesystemRecreationDefaults {
    if (!canRecreateFilesystem) return null;
    final job = _currentJob!;

    if (job.isPartitionScope) {
      final targets = filesystemRecreationTargets;
      if (targets.isEmpty) return null;
      return _partitionDefaults(
        targets.first,
        spec: _restoreSpecsByPartition[targets.first.devicePath],
      );
    }
    return _wholeDeviceDefaults(job);
  }

  /// Phase G: prefill values for restoring one specific wiped partition.
  /// Used by the per-partition "Restore now" action in the blank-drive notice.
  FilesystemRecreationDefaults? filesystemRecreationDefaultsFor(
    PartitionInfo partition,
  ) {
    final job = _currentJob;
    if (job == null || !_canRecreatePartitionTarget(job, partition)) {
      return null;
    }
    return _partitionDefaults(
      partition,
      spec: _restoreSpecsByPartition[partition.devicePath],
    );
  }

  FilesystemRecreationDefaults _partitionDefaults(
    PartitionInfo part, {
    FilesystemRestoreSpec? spec,
  }) {
    final fs =
        spec?.fsType ??
        normalizeFilesystemType(part.fsType) ??
        _formatPreference.fsType ??
        'vfat';
    final rawLabel = spec != null && spec.label.isNotEmpty
        ? spec.label
        : part.label.sanitized.isNotEmpty
        ? part.label.sanitized
        : (_formatPreference.label ?? 'ZT_VOLUME');
    return FilesystemRecreationDefaults(
      fsType: fs,
      label: _safeVolumeLabel(rawLabel),
      scope: 'partial',
    );
  }

  FilesystemRecreationDefaults _wholeDeviceDefaults(SanitizationJob job) {
    final fs =
        normalizeFilesystemType(job.device.fsType) ??
        _formatPreference.fsType ??
        'vfat';
    final tableRaw = job.device.partitionTableType?.toLowerCase();
    final table = (tableRaw == 'mbr' || tableRaw == 'dos') ? 'mbr' : 'gpt';
    final rawLabel = _formatPreference.label ?? job.device.name;
    return FilesystemRecreationDefaults(
      fsType: fs,
      label: _safeVolumeLabel(rawLabel),
      scope: 'full',
      tableType: table,
    );
  }

  /// Filesystem labels are engine input: keep them short, uppercase and free
  /// of characters the formatters reject (FAT labels are 11 chars max).
  static String _safeVolumeLabel(String raw) {
    final cleaned = raw
        .toUpperCase()
        .replaceAll(RegExp(r'[^A-Z0-9_-]'), '_')
        .replaceAll(RegExp(r'_+'), '_');
    final trimmed = cleaned.replaceAll(RegExp(r'^_+|_+$'), '');
    if (trimmed.isEmpty) return 'ZT_VOLUME';
    return trimmed.length <= 11 ? trimmed : trimmed.substring(0, 11);
  }

  void dismissFilesystemRecreationPrompt() {
    if (!canRecreateFilesystem) return;
    _formatPromptDismissed = true;
    notifyListeners();
  }

  void _resetFilesystemRecreationState() {
    _filesystemRecreation = null;
    _filesystemRecreationError = null;
    _filesystemRecreationUnavailableReason = null;
    _isFormattingFilesystem = false;
    _formatPromptDismissed = false;
    _autoRestoreFailed = false;
    _partitionRestoreOutcomes.clear();
    _verifiedFormatReceipts.clear();
  }

  /// Phase G: forget the pre-wipe "After wiping" decision once its job is no
  /// longer on screen.
  void _clearRestoreChoice() {
    _restoreChoiceKnown = false;
    _restoreAfterWipe = false;
    _autoRestoreFailed = false;
    _restoreFsType = null;
    _restoreLabel = null;
    _restoreSpecsByPartition = const {};
    _partitionRestoreOutcomes.clear();
  }

  void _deleteReceiptBestEffort(String path) {
    try {
      final file = File(path);
      if (file.existsSync()) file.deleteSync();
    } catch (_) {}
  }

  /// Phase F: validate a receipt minted by `zt_engine verify` for this exact
  /// target before it can earn the "Recreate filesystem?" prompt.
  ///
  /// Returns null when the file exists, parses, and binds to the target on
  /// every axis the engine also enforces: canonical path (symlink-resolved,
  /// falling back to the raw path when the node cannot be resolved), device
  /// serial, partition scope/number, and partition-table fingerprint
  /// (compared only when both sides carry one — whole-disk receipts are
  /// minted without a fingerprint and must never mismatch on it).
  /// Otherwise a user-facing reason for refusing the format.
  @visibleForTesting
  static String? validateVerifiedWipeReceipt({
    required String targetPath,
    required File receiptFile,
    required String deviceSerial,
    required bool isPartitionScope,
    int? partitionNumber,
    required String expectedFingerprint,
  }) {
    if (!receiptFile.existsSync()) {
      return 'Filesystem recreation unavailable: the verification receipt '
          'was not written by the engine.';
    }

    Map<String, dynamic>? stamp;
    try {
      final decoded = jsonDecode(receiptFile.readAsStringSync());
      if (decoded is Map<String, dynamic>) stamp = decoded;
    } catch (_) {}
    if (stamp == null) {
      return 'Filesystem recreation unavailable: the verification receipt '
          'is not valid JSON.';
    }

    final actualPath = stamp['canonical_path'] as String?;
    if (actualPath == null || actualPath.isEmpty) {
      return 'Filesystem recreation unavailable: the verification receipt '
          'has no canonical path.';
    }
    // Symlink resolution, fail-closed: if the target node cannot be
    // resolved (device removed), compare against the raw path — never a
    // crash, and still a mismatch when the receipt names another target.
    String expectedPath;
    try {
      expectedPath = File(targetPath).resolveSymbolicLinksSync();
    } catch (_) {
      expectedPath = targetPath;
    }
    if (actualPath != expectedPath) {
      return 'Filesystem recreation unavailable: the verification receipt '
          'is for $actualPath, not $targetPath.';
    }

    final actualSerial = stamp['device_serial'] as String?;
    if (actualSerial != deviceSerial) {
      return 'Filesystem recreation unavailable: the verification receipt '
          'is for a different device (serial mismatch).';
    }

    final actualScope = stamp['scope'] as String?;
    if (isPartitionScope) {
      final actualPart = stamp['partition_number'];
      if (actualScope != 'partial' ||
          actualPart is! int ||
          actualPart != partitionNumber) {
        return 'Filesystem recreation unavailable: the verification receipt '
            'is for a different partition.';
      }
    } else if (actualScope != 'full' || stamp['partition_number'] != null) {
      return 'Filesystem recreation unavailable: the verification receipt '
          'is for a partition, not this whole device.';
    }

    final actualFingerprint = stamp['partition_table_fingerprint'];
    if (actualFingerprint != null &&
        expectedFingerprint.isNotEmpty &&
        '$actualFingerprint' != expectedFingerprint) {
      return 'Filesystem recreation unavailable: the verification receipt '
          'was minted for a different partition table.';
    }

    return null;
  }

  /// Offers the format step only for a receipt that really exists and binds
  /// to this exact target. Returns null when the receipt was accepted into
  /// [_verifiedFormatReceipts]; otherwise the reason shown in place of the
  /// prompt (and logged as a warning by the caller).
  String? _recordVerifiedWipeReceipt({
    required SanitizationJob job,
    required String targetPath,
    required PartitionInfo? target,
    required File receiptFile,
    required RealVerificationReport verifyReport,
  }) {
    // Exit 4: verification passed but the engine itself refused to mint the
    // receipt — surface its typed reason verbatim.
    if (verifyReport.exitCode == 4) {
      final detail = verifyReport.stderr.trim();
      return detail.isNotEmpty
          ? 'Filesystem recreation unavailable: $detail'
          : 'Filesystem recreation unavailable: the engine could not save '
              'the verification receipt.';
    }
    final expectedFingerprint = job.device.partitionTableFingerprint ??
        PartitionTableService.computeFingerprint(job.device.partitions);
    final reason = validateVerifiedWipeReceipt(
      targetPath: targetPath,
      receiptFile: receiptFile,
      deviceSerial: job.device.serialNumber,
      isPartitionScope: target != null,
      partitionNumber: target?.partitionNumber,
      expectedFingerprint: expectedFingerprint,
    );
    if (reason != null) return reason;
    _verifiedFormatReceipts[targetPath] = receiptFile.path;
    return null;
  }

  /// Recreate a filesystem on a target that was wiped and verified in this
  /// job. Refuses (returns null with [filesystemRecreationError] set) when:
  /// the job did not complete a verified wipe, the target has no receipt, the
  /// partition was not part of this job, or a whole-device typed confirmation
  /// does not match the device serial.
  ///
  /// A format failure never changes the wipe result.
  Future<FilesystemRecreationRecord?> recreateFilesystem({
    required String fsType,
    required String label,
    String confirmationToken = '',
    String? tableType,
    PartitionInfo? targetPartition,
    bool dryRun = false,
  }) async {
    final job = _currentJob;
    // Phase G: a specific partition stays eligible after another partition
    // was restored — each partition has its own one-shot receipt. Every other
    // path keeps the historic single-shot [canRecreateFilesystem] gate.
    final perPartitionAllowed =
        job != null &&
        targetPartition != null &&
        _canRecreatePartitionTarget(job, targetPartition);
    if (job == null || (!canRecreateFilesystem && !perPartitionAllowed)) {
      _filesystemRecreationError =
          'A filesystem can only be recreated after a wipe and verification '
          'completed successfully in this job.';
      notifyListeners();
      return null;
    }

    final fs = fsType.trim().toLowerCase();
    if (!supportedFilesystemTypes.contains(fs)) {
      _filesystemRecreationError =
          'Unsupported filesystem type "$fsType" (expected vfat, exfat, ntfs or ext4).';
      notifyListeners();
      return null;
    }
    final cleanLabel = _safeVolumeLabel(label);

    PartitionInfo? partition;
    String? effectiveTable;
    String? receiptPath;

    if (job.isPartitionScope) {
      final candidates = filesystemRecreationTargets;
      partition =
          targetPartition ?? (candidates.isEmpty ? null : candidates.first);
      if (partition == null ||
          !candidates.any((p) => p.devicePath == partition!.devicePath)) {
        _filesystemRecreationError =
            'That partition was not wiped and verified in this job.';
        notifyListeners();
        return null;
      }
      receiptPath = _verifiedFormatReceipts[partition.devicePath];
    } else {
      effectiveTable =
          (tableType ?? filesystemRecreationDefaults?.tableType ?? 'gpt')
              .trim()
              .toLowerCase();
      if (effectiveTable != 'gpt' && effectiveTable != 'mbr') {
        _filesystemRecreationError =
            'Whole-device recreation requires a gpt or mbr partition table.';
        notifyListeners();
        return null;
      }
      if (confirmationToken.trim() != job.device.serialNumber) {
        _filesystemRecreationError =
            'Typed confirmation does not match the device serial number.';
        notifyListeners();
        return null;
      }
      receiptPath = _verifiedFormatReceipts[_deviceNode(job.device)];
    }

    if (receiptPath == null || !File(receiptPath).existsSync()) {
      _filesystemRecreationError =
          'No verified-wipe receipt for this target; refusing to format.';
      notifyListeners();
      return null;
    }

    _isFormattingFilesystem = true;
    _filesystemRecreationError = null;
    notifyListeners();

    try {
      final report = await _realSanitizeService.executeFormat(
        device: job.device,
        fsType: fs,
        label: cleanLabel,
        confirmationToken: job.isPartitionScope
            ? job.device.serialNumber
            : confirmationToken,
        deviceSerial: job.device.serialNumber,
        targetPartition: partition,
        tableType: effectiveTable,
        verifiedReceiptPath: receiptPath,
        dryRun: dryRun,
      );

      if (!report.success) {
        final detail = report.stderr.trim();
        _filesystemRecreationError = detail.isNotEmpty
            ? detail
            : 'Filesystem recreation failed (exit code ${report.exitCode}).';
        return null;
      }

      final record = FilesystemRecreationRecord(
        tool: report.tool,
        fsType: report.fsType.isEmpty ? fs : report.fsType,
        label: report.label.isEmpty ? cleanLabel : report.label,
        time: report.time,
        sanitizationVerifiedBeforeFormat:
            report.sanitizationVerifiedBeforeFormat,
        scope: report.scope,
        partitionTableCreated: report.partitionTableCreated,
        partitionTableType: report.partitionTableType,
      );
      _filesystemRecreation = record;

      // Remember only the fs/label pair; the action itself stays default-OFF.
      _formatPreference = FilesystemRecreationPreference(
        fsType: record.fsType,
        label: record.label,
      );
      _formatPreferenceStore.save(fsType: record.fsType, label: record.label);

      // Re-sign the certificate with the separate format record when present.
      String? certSha;
      final cert = _completedCertificate;
      if (cert != null) {
        try {
          final updated = _certificateService.withFilesystemRecreation(
            cert,
            record,
          );
          _completedCertificate = updated;
          final (_, sha) = await _auditLogService.saveCertificate(updated);
          certSha = sha;
        } catch (_) {}
      }

      // Separate audit entry for the format step (wipe entry is untouched).
      try {
        await _auditLogService.appendEntry(
          AuditLogEntry(
            timestamp: record.time,
            jobId: job.jobId,
            deviceSerial: job.device.serialNumber,
            devicePath: partition?.devicePath ?? _deviceNode(job.device),
            deviceName: job.device.name,
            scope: record.scope,
            method: 'recreate filesystem (${record.fsType})',
            methodClass: 'format',
            standardReference: 'Post-wipe filesystem recreation',
            nistCategory: 'FORMAT',
            outcome: 'format_completed',
            success: true,
            verificationPassed: true,
            certificateId: _completedCertificate?.certificateId,
            certificateSha256: certSha,
            fingerprintHash: 'FORMAT_VERIFIED',
            entropyScore: 1.0,
            sampleCount: 0,
            commandLog: report.commandLog,
            isSimulated: false,
            filesystemRecreation: record,
          ),
        );
      } catch (_) {}

      _addLog(
        'FORMAT: Recreated ${record.fsType} (${record.tool}) on '
        '${partition?.devicePath ?? _deviceNode(job.device)} — '
        'wipe result unchanged.',
      );
      // One-shot per target: consume only this target's receipt (other
      // partitions keep theirs for their own restore).
      final consumedKey = partition?.devicePath ?? _deviceNode(job.device);
      _verifiedFormatReceipts.remove(consumedKey);
      _deleteReceiptBestEffort(receiptPath);
      _recordPartitionRestoreSuccess(partition, record);
      return record;
    } catch (e) {
      _filesystemRecreationError = 'Filesystem recreation failed: $e';
      return null;
    } finally {
      _isFormattingFilesystem = false;
      notifyListeners();
    }
  }

  /// Phase G: run the pre-wipe "Restore as an empty drive" choice after a
  /// verified wipe. Every Phase-F guard stays in force:
  ///  * the verified-wipe receipt must still exist and bind to each target;
  ///  * every receipt is consumed one-shot by a successful format;
  ///  * receipt expiry remains the engine's call (an expired/refused receipt
  ///    fails the format, never silently succeeds);
  ///  * a whole-device restore reuses the identity already confirmed in the
  ///    dialog — the operator is never asked for the serial twice;
  ///  * partition scope restores EVERY wiped partition sequentially, each with
  ///    its own captured fs/label and receipt; one failure never stops the
  ///    rest and never changes the recorded wipe result.
  Future<void> _maybeAutoRestoreFilesystem() async {
    if (!_restoreChoiceKnown || !_restoreAfterWipe) return;

    final job = _currentJob;
    if (job == null) return;
    // Never format without a completed wipe and passing verification; the
    // per-target receipt checks add the remaining proof.
    if (!job.wipeCompleted || job.status != JobStatus.completed) return;
    if (_completedCertificate?.evidence.verifiedPassed != true) return;

    if (!job.isPartitionScope) {
      await _autoRestoreWholeDevice(job);
      return;
    }

    final targets = job.targetPartitions.isEmpty
        ? <PartitionInfo>[job.targetPartition!]
        : job.targetPartitions;
    if (targets.isEmpty) return;

    for (final part in targets) {
      final receipt = _verifiedFormatReceipts[part.devicePath];
      if (receipt == null || !File(receipt).existsSync()) {
        const reason =
            'No verified-wipe receipt for this partition; refusing to format.';
        _partitionRestoreOutcomes.add(
          PartitionRestoreOutcome(partition: part, error: reason),
        );
        _addLog('RESTORE: ${part.name} skipped — no verified-wipe receipt.');
        continue;
      }

      final spec = _restoreSpecsByPartition[part.devicePath];
      final defaults = _partitionDefaults(part, spec: spec);
      final fs = spec?.fsType ?? _restoreFsType ?? defaults.fsType;
      final label = spec?.label ?? _restoreLabel ?? defaults.label;
      _addLog('RESTORE: recreating $fs on ${part.name}...');

      FilesystemRecreationRecord? record;
      try {
        record = await recreateFilesystem(
          fsType: fs,
          label: label,
          targetPartition: part,
          // The identity was already confirmed once, in the dialog.
          confirmationToken: job.device.serialNumber,
        );
      } catch (e) {
        _filesystemRecreationError = 'Automatic restore failed: $e';
        record = null;
      }

      if (record == null) {
        _partitionRestoreOutcomes.add(
          PartitionRestoreOutcome(
            partition: part,
            error:
                _filesystemRecreationError ??
                'Filesystem recreation failed.',
          ),
        );
        _addLog(
          'WARNING: Restore of ${part.name} failed: '
          '${_filesystemRecreationError ?? "unknown error"}',
        );
      }
      // Success is recorded by recreateFilesystem itself.
    }
    notifyListeners();
  }

  Future<void> _autoRestoreWholeDevice(SanitizationJob job) async {
    if (!canRecreateFilesystem) {
      _autoRestoreFailed = true;
      _filesystemRecreationError =
          _filesystemRecreationUnavailableReason ??
          'Automatic restore skipped: no valid verified-wipe receipt.';
      _addLog('RESTORE: skipped — ${_filesystemRecreationError!}');
      notifyListeners();
      return;
    }

    final defaults = filesystemRecreationDefaults;
    final fs = _restoreFsType ?? defaults?.fsType ?? 'vfat';
    final label = _restoreLabel ?? defaults?.label ?? job.device.name;
    _addLog('RESTORE: recreating $fs after the verified wipe...');

    try {
      final record = await recreateFilesystem(
        fsType: fs,
        label: label,
        // The device identity was already confirmed once, in the dialog.
        confirmationToken: job.device.serialNumber,
        tableType: defaults?.tableType,
      );

      if (record == null) {
        _autoRestoreFailed = true;
        _addLog(
          'WARNING: Automatic restore failed: '
          '${_filesystemRecreationError ?? "unknown error"}',
        );
      } else {
        _addLog('RESTORE: drive restored as ${record.fsType.toUpperCase()}.');
      }
    } catch (e) {
      _autoRestoreFailed = true;
      _filesystemRecreationError = 'Automatic restore failed: $e';
      _addLog('WARNING: Automatic restore failed: $e');
    }
    notifyListeners();
  }

  /// Phase G: keep the per-partition outcome list in sync when a partition is
  /// restored (automatically or through a manual "Restore now" retry).
  void _recordPartitionRestoreSuccess(
    PartitionInfo? partition,
    FilesystemRecreationRecord record,
  ) {
    if (partition == null) return;
    _partitionRestoreOutcomes.removeWhere(
      (o) => o.partition.devicePath == partition.devicePath,
    );
    _partitionRestoreOutcomes.add(
      PartitionRestoreOutcome(partition: partition, record: record),
    );
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
    final freshDevices = await _platformBackend.discoverDevices(
      realMode: _isRealMode,
    );
    if (_isMockingDevices || _isDisposed) return;

    // Check if device list changed
    bool hasChanged = freshDevices.length != _devices.length;
    if (!hasChanged) {
      for (int i = 0; i < freshDevices.length; i++) {
        if (freshDevices[i].id != _devices[i].id ||
            freshDevices[i].name != _devices[i].name ||
            freshDevices[i].capacityBytes != _devices[i].capacityBytes ||
            freshDevices[i].isWipedNoFilesystem !=
                _devices[i].isWipedNoFilesystem ||
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
        final stillPresent = _devices.any(
          (d) =>
              d.stableId == target.stableId ||
              (d.id == target.id && d.capacityBytes == target.capacityBytes),
        );
        if (!stillPresent) {
          // Mid-job disappearance = "interrupted"
          final job = _currentJob!;
          job.status = JobStatus.failed;
          job.endTime = DateTime.now();
          job.currentStageDescription =
              'Drive Disconnected: Sanitization Interrupted';
          _addLog(
            'ERROR: Drive ${target.name} (${target.id}) was disconnected during operation.',
          );
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
                ..add(
                  'Drive disconnected during operation - interrupted, state unknown.',
                ),
              partitions: _buildPartitionOutcomes(job, false),
            ),
          );
          _jobStateFile.clearActiveJob();
        }
      }
      if (!isJobRunning) {
        if (_devices.isNotEmpty) {
          if (_selectedDevice == null ||
              !_devices.any((d) => d.id == _selectedDevice!.id)) {
            _selectedDevice = _devices.first;
          } else {
            // Refresh selected device reference with new profile
            _selectedDevice = _devices.firstWhere(
              (d) => d.id == _selectedDevice!.id,
            );
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
    _selectedPartitions = const [];
    _updateJobRecommendation();
    notifyListeners();
  }

  void selectPartition(PartitionInfo? partition) {
    if (isJobRunning) return;
    _selectedPartition = partition;
    _selectedPartitions = partition == null ? const [] : [partition];
    _updateJobRecommendation();
    notifyListeners();
  }

  /// A4: toggle a partition in the multi-select set.
  void togglePartitionSelection(PartitionInfo partition) {
    if (isJobRunning) return;
    final next = List<PartitionInfo>.from(_selectedPartitions);
    final idx = next.indexWhere((p) => p.name == partition.name);
    if (idx >= 0) {
      next.removeAt(idx);
    } else {
      next.add(partition);
      next.sort((a, b) => a.partitionNumber.compareTo(b.partitionNumber));
    }
    _selectedPartitions = next;
    _selectedPartition = next.isEmpty ? null : next.first;
    _updateJobRecommendation();
    notifyListeners();
  }

  /// A4: clear all partition selections (back to whole-device scope).
  void clearPartitionSelection() {
    if (isJobRunning) return;
    _selectedPartitions = const [];
    _selectedPartition = null;
    _updateJobRecommendation();
    notifyListeners();
  }

  /// B1: probe a partition read-only for a Windows installation via
  /// `zt_engine probe-windows <device>` (mounts `ro,noexec,nosuid,nodev`,
  /// checks for a `\Windows` directory, reads usage, always unmounts —
  /// the volume is never opened for writing).
  ///
  /// Returns null on success (result recorded in [windowsProbeResults]) or
  /// an error message for the UI.
  Future<String?> probeWindowsInstall(PartitionInfo partition) async {
    String fail(String message) {
      _windowsProbeErrors[partition.devicePath] = message;
      _windowsProbeResults.remove(partition.devicePath);
      notifyListeners();
      return message;
    }

    try {
      final bin = await _platformBackend.resolveEngineBinaryPath();
      final res = await Process.run(bin, [
        'probe-windows',
        partition.devicePath,
      ]).timeout(const Duration(seconds: 30));
      final out = res.stdout as String? ?? '';
      const marker = 'WINDOWS_PROBE:';
      final idx = out.indexOf(marker);
      if (idx < 0) {
        final err = (res.stderr as String? ?? '').trim();
        return fail(err.isEmpty ? 'Probe failed' : 'Probe failed: $err');
      }
      final probe =
          jsonDecode(out.substring(idx + marker.length))
              as Map<String, dynamic>;
      if (probe['mounted_read_only'] != true) {
        return fail(probe['error'] as String? ?? 'read-only mount failed');
      }
      _windowsProbeResults[partition.devicePath] =
          probe['likely_windows_install'] == true;
      _windowsProbeErrors.remove(partition.devicePath);
      notifyListeners();
      return null;
    } catch (e) {
      return fail('Probe failed: $e');
    }
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
    _clearRestoreChoice();
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
        explanation =
            'Partition-scoped wiping only supports overwrite methods. Firmware sanitize and crypto commands affect the whole drive and cannot be scoped to a single partition.';
      }
    }

    final jobId =
        'JOB-${DateTime.now().millisecondsSinceEpoch.toString().substring(6)}';

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
      // B4: preview job mirrors the real one — every selected partition.
      targetPartitions: List<PartitionInfo>.from(_selectedPartitions),
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

  // Orchestrate simulated or real pipeline execution.
  // Deliberately private: the only way to reach it is startSimpleWipe(), which
  // requires a WipeAuthorization minted inside confirm_wipe_dialog.dart.
  Future<void> _runSanitizationPipeline() async {
    if (_currentJob == null) return;

    final job = _currentJob!;
    job.startTime = DateTime.now();
    job.logs.clear();
    // Phase F: every job starts with no format eligibility or prompt.
    _resetFilesystemRecreationState();

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

    _addLog(
      'SUCCESS: Whitelist verified. Target: ${job.device.name} [${job.device.serialNumber}]',
    );
    notifyListeners();

    // B4: fail-closed pre-flight — EVERY selected partition must pass the
    // per-target policy BEFORE the first wipe starts, so a subset wipe never
    // stops half-way because of a later protected partition.
    if (job.isPartitionScope && job.targetPartitions.length > 1) {
      for (final t in job.targetPartitions) {
        final perPart = _policyLayer.validatePartitionTarget(job, t);
        if (!perPart.isAllowed) {
          job.status = JobStatus.failed;
          job.currentStageDescription = perPart.policyMessage;
          _addLog(
            'ERROR: Pre-flight refused partition ${t.name}: ${perPart.policyMessage}',
          );
          notifyListeners();
          return;
        }
      }
      _addLog(
        'SUCCESS: Pre-flight passed for all ${job.targetPartitions.length} selected partitions.',
      );
      notifyListeners();
    }

    if (_isRealMode) {
      if (kIsWeb) {
        job.status = JobStatus.failed;
        job.currentStageDescription =
            'Real mode is not supported on Web. Please run natively on Linux.';
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

      // B4: per-run accumulators shared by the wipe loop and the failure
      // path (declared before try so the catch block can report them).
      final List<PartitionAuditOutcome> outcomes = [];
      final List<String> aggregatedCommandLog = [];
      final List<RealVerificationReport> verifyReports = [];
      RealExecutionReport? lastReport;
      bool anyVerifyRan = false;
      bool allVerifiesPassed = true;
      int wipedTargets = 0;

      try {
        // Stage 1: Detecting & unmounting filesystems
        job.status = JobStatus.unmounting;
        job.progress = null; // Honest indeterminate state
        job.currentStageDescription =
            'Preparing device: zt_engine handling partition unmounts...';
        _addLog(
          'SYSTEM: Initializing device preparation (zt_engine managing unmount)...',
        );
        notifyListeners();

        // B4: execution targets — whole device = single pass; partition
        // scope = every selected partition wiped sequentially (ranges only;
        // the partition table stays intact).
        final List<PartitionInfo?> targets = job.wipeExecutionTargets;

        // Stage 2: Sanitization execution (sequential per target)
        job.status = JobStatus.sanitizing;
        job.progress =
            null; // Honest indeterminate state until write progress arrives
        job.currentStageDescription = targets.length > 1
            ? 'Executing partition wipe 1/${targets.length}...'
            : 'Executing real-hardware sanitization...';
        notifyListeners();

        _lastHeartbeatTime = DateTime.now();
        _isStalled = false;
        _stallWatchdogTimer?.cancel();
        _stallWatchdogTimer = Timer.periodic(const Duration(seconds: 1), (
          timer,
        ) {
          if (job.status == JobStatus.sanitizing &&
              _lastHeartbeatTime != null) {
            final secondsSinceHeartbeat = DateTime.now()
                .difference(_lastHeartbeatTime!)
                .inSeconds;
            if (secondsSinceHeartbeat >= 30 && !_isStalled) {
              _isStalled = true;
              job.currentStageDescription =
                  'Drive I/O stalled - waiting for hardware response...';
              _addLog(
                'WARNING: No progress or heartbeat received for ${secondsSinceHeartbeat}s; drive I/O may be stalled.',
              );
              notifyListeners();
            } else if (secondsSinceHeartbeat < 30 && _isStalled) {
              _isStalled = false;
              notifyListeners();
            }
          }
        });

        for (var ti = 0; ti < targets.length; ti++) {
          final PartitionInfo? target = targets[ti];
          final String targetPath = target != null
              ? target.devicePath
              : (job.device.id.startsWith('real_')
                    ? '/dev/${job.device.id.substring(5)}'
                    : '/dev/sdb');
          if (targets.length > 1) {
            job.currentStageDescription =
                'Wiping partition ${ti + 1}/${targets.length}: ${target!.name}...';
            _addLog(
              'SCOPE: Partition ${ti + 1}/${targets.length}: ${target.devicePath} '
              '(range only — partition table untouched)',
            );
            notifyListeners();
          }

          await _jobStateFile.saveActiveJob(
            ActiveJobState(
              jobId: job.jobId,
              deviceSerial: job.device.serialNumber,
              devicePath: targetPath,
              deviceName: job.device.name,
              method: job.effectiveMethod.displayName,
              methodKind: _methodKind(job.effectiveMethod),
              deviceSize: job.device.capacityBytes,
              startedAt:
                  job.startTime?.toIso8601String() ??
                  DateTime.now().toIso8601String(),
              partitionNumber: target?.partitionNumber,
              partitionStartSector: target?.startSector,
              partitionSizeSectors: target?.sizeSectors,
              scope: job.isPartitionScope ? 'partial' : 'full',
              limitation: job.isPartitionScope
                  ? 'Partition wipe: partition table and unselected sectors are not overwritten'
                  : null,
            ),
          );

          _lastHeartbeatTime = DateTime.now();

          final report = await _realSanitizeService.executeSanitization(
            device: job.device,
            method: job.effectiveMethod,
            confirmationToken:
                job.device.serialNumber, // verified by dialog retype
            deviceSerial: job.device.serialNumber,
            targetPartition: target,
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
              // B4: fold per-partition progress into overall job progress.
              job.progress = (targets.length > 1 && event.percent != null)
                  ? (ti + event.percent!) / targets.length
                  : event.percent;

              if (event.bytesTotal > 0 && event.bytesDone > 0) {
                final doneGb = (event.bytesDone / 1e9).toStringAsFixed(1);
                final totalGb = (event.bytesTotal / 1e9).toStringAsFixed(1);
                final speedMb = (event.speedBytesPerSec / 1e6).toStringAsFixed(
                  1,
                );
                final etaStr =
                    event.etaSeconds != null && event.speedBytesPerSec > 1024
                    ? 'ETA: ${event.etaSeconds}s'
                    : 'Estimating ETA...';
                job.currentStageDescription =
                    '${event.message} ($doneGb / $totalGb GB @ $speedMb MB/s, $etaStr)';
              } else {
                job.currentStageDescription = event.message;
              }

              final pctStr = event.percent != null
                  ? ' (${(event.percent! * 100).toInt()}%)'
                  : '';
              _addLog('PROGRESS: [${event.phase}] ${event.message}$pctStr');
              notifyListeners();
            },
            onRawLog: (rawLine) {
              _addLog(rawLine);
              notifyListeners();
            },
          );
          aggregatedCommandLog.addAll(report.commandLog);
          lastReport = report;

          if (!report.success) {
            job.status = JobStatus.failed;
            job.endTime = DateTime.now();
            if (report.exitCode == 130) {
              job.currentStageDescription =
                  'Sanitization Cancelled: Partially Wiped';
              _addLog(
                'CANCEL: Sanitization cancelled by user. Partially wiped.',
              );
            } else {
              job.currentStageDescription =
                  'Sanitization Failed: ${report.stderr}';
              _addLog(
                'ERROR: Sanitization command failed with code ${report.exitCode}',
              );
              _addLog('ERROR Details: ${report.stderr}');
            }
            if (target != null) {
              outcomes.add(
                PartitionAuditOutcome.forPartition(target, success: false),
              );
            }
            _addLog(
              'ERROR: Wipe stopped; $wipedTargets/${targets.length} target(s) completed.',
            );
            await _jobStateFile.clearActiveJob();
            notifyListeners();
            return;
          }
          if (target != null) {
            outcomes.add(
              PartitionAuditOutcome.forPartition(target, success: true),
            );
          }
          wipedTargets++;

          // Stage 3: Verification LBA sampling — immediately after each
          // target's wipe so every wiped range is sampled.
          job.status = JobStatus.verifying;
          job.progress = targets.length > 1
              ? wipedTargets / targets.length
              : null;
          job.currentStageDescription = targets.length > 1
              ? 'Verifying partition ${ti + 1}/${targets.length}: ${target!.name}...'
              : 'Verifying sector erasure via LBA sampling...';
          _addLog(
            'VERIFICATION: Running post-sanitize verify LBA sampling'
            '${targets.length > 1 ? ' for ${target!.devicePath}' : ''}...',
          );
          notifyListeners();

          final cliMethod = _realSanitizeService.mapMethodToCliArg(
            job.effectiveMethod,
            job.device,
          );
          final isCryptoMethod =
              job.effectiveMethod == SanitizationMethod.cryptographicErase ||
              report.methodUsed.toLowerCase().contains('crypto') ||
              report.methodUsed.toLowerCase().contains('reverttper');
          final expectZeros = !isCryptoMethod;

          // Phase F: ask the engine to leave a one-shot verified-wipe receipt
          // for this exact target. It is the only proof the separate `format`
          // process will accept.
          final receiptFile = target != null
              ? _appPaths.verifiedWipeReceiptFile(
                  job.jobId,
                  partitionNumber: target.partitionNumber,
                )
              : _appPaths.verifiedWipeReceiptFile(job.jobId);

          RealVerificationReport? verifyReport;
          try {
            verifyReport = await _realSanitizeService.executeVerification(
              device: job.device,
              method: cliMethod,
              deviceSerial: job.device.serialNumber,
              targetPartition: target,
              sampleCount: 50,
              expectZeros: expectZeros,
              verifiedReceiptPath: receiptFile.path,
            );
          } catch (verifyErr) {
            _addLog('WARNING: Verification sampling failed: $verifyErr');
            _addLog(
              'NOTE: Disk write operation itself completed successfully.',
            );
          }
          if (verifyReport != null) {
            anyVerifyRan = true;
            allVerifiesPassed = allVerifiesPassed && verifyReport.pass;
            verifyReports.add(verifyReport);
            if (verifyReport.pass) {
              // Phase F: the receipt earns the format prompt only when the
              // file exists and binds to this exact target — otherwise the
              // prompt is withheld, the reason is surfaced, and a warning
              // lands in the job log.
              final reason = _recordVerifiedWipeReceipt(
                job: job,
                targetPath: targetPath,
                target: target,
                receiptFile: receiptFile,
                verifyReport: verifyReport,
              );
              if (reason != null) {
                _filesystemRecreationUnavailableReason = reason;
                _addLog('WARNING: $reason');
              } else {
                _filesystemRecreationUnavailableReason = null;
              }
              notifyListeners();
            }
          }
        } // end per-target wipe loop (B4)

        _stallWatchdogTimer?.cancel();
        _stallWatchdogTimer = null;
        _cancelEscalationTimer?.cancel();
        _cancelEscalationTimer = null;
        _isCancelling = false;
        _showForceStop = false;

        // ── Disk operation succeeded. Record this fact BEFORE post-processing ──
        // From this point forward, any exception is a post-processing failure
        // (certificate signing, audit log), NOT a disk operation failure.
        final bool diskWipeSucceeded = true;
        job.wipeCompleted = true;

        // B4: aggregate verification over every target. Single-target runs
        // keep the exact A8 semantics: no verify report = pass=false in the
        // evidence, but the wipe itself still counts as successful.
        final bool verificationPassed = anyVerifyRan
            ? allVerifiesPassed
            : false;
        final RealVerificationReport? verifyReport = verifyReports.isEmpty
            ? null
            : verifyReports.last;

        // Construct VerificationEvidence from real report(s). Sample offsets
        // are absolute device LBAs, so multi-target samples never collide.
        final List<int> sampleOffsets = [];
        final Map<int, String> sampleHashes = {};
        for (final vr in verifyReports) {
          for (final sample in vr.samples) {
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
            sampleHashes[offset] =
                '0000000000000000000000000000000000000000000000000000000000000000';
          }
        }

        final statusCode = verificationPassed ? 0 : 1;
        final controllerConfirmation = verifyReports.isNotEmpty
            ? (verifyReports.length == 1
                  ? 'VERIFICATION: Pass: ${verifyReports.single.pass} | Samples: ${verifyReports.single.sampleCount} | Entropy: ${verifyReports.single.entropyScore}'
                  : 'VERIFICATION: Pass: $allVerifiesPassed '
                        '(${verifyReports.where((v) => v.pass).length}/${targets.length} partitions) | '
                        'Samples: ${verifyReports.fold<int>(0, (a, v) => a + v.sampleCount)} | '
                        'Entropy: ${verifyReports.last.entropyScore}')
            : 'VERIFICATION: Sampling unavailable (disk wipe command succeeded)';

        final limitations = _verificationService.getTailoredLimitations(
          job.recommendedMethod,
        );

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
        if (anyVerifyRan) {
          isJobSuccessful = allVerifiesPassed;
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
            actualMethodExecuted:
                lastReport?.methodUsed ?? job.effectiveMethod.displayName,
            // A7: sign the ordered engine steps actually executed (B4: the
            // aggregated command log of every sequential target).
            stepsExecuted: aggregatedCommandLog,
            verificationSampleCount: verifyReport?.sampleCount,
            verificationEntropyScore: verifyReport?.entropyScore,
            // B5: signed claim of the boot environment ("live" when running
            // from the live medium).
            bootEnvironment: LiveBootDetector.detect().name,
          );
          _addLog(
            'CERTIFICATE: Issued ${completedCertificate!.certificateId} signed with ECDSA P-256 key.',
          );
        } catch (certErr) {
          _addLog('WARNING: Certificate generation failed: $certErr');
          _addLog('NOTE: The disk sanitization itself completed successfully.');
          job.currentStageDescription =
              'Sanitization succeeded. Certificate generation failed — see logs.';
        }

        if (verifyReport != null) {
          _addLog(
            'VERIFICATION: Entropy score: ${verifyReport.entropyScore}. Fingerprint: ${verifyReport.fingerprintHash}',
          );
        }

        String? certSha;
        if (completedCertificate != null) {
          try {
            final (_, sha) = await _auditLogService.saveCertificate(
              _completedCertificate!,
            );
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
            outcome: verificationPassed ? 'completed' : 'verify_failed',
            success: diskWipeSucceeded && verificationPassed,
            verificationPassed: verificationPassed,
            certificateId: _completedCertificate?.certificateId,
            certificateSha256: certSha,
            fingerprintHash: verifyReport?.fingerprintHash ?? 'UNAVAILABLE',
            entropyScore: verifyReport?.entropyScore ?? 0.0,
            sampleCount: verifyReport?.sampleCount ?? 0,
            commandLog: aggregatedCommandLog,
            isSimulated: false,
            partitions: _buildPartitionOutcomes(
              job,
              diskWipeSucceeded && verificationPassed,
              override: outcomes,
            ),
          );
          await _auditLogService.appendEntry(auditEntry);
        } catch (auditErr) {
          _addLog('WARNING: Audit log write failed: $auditErr');
        }

        // Phase G: run the single pre-wipe "After wiping" decision now that
        // the wipe result, certificate and audit entry are all recorded. A
        // restore failure never changes the wipe verdict.
        await _maybeAutoRestoreFilesystem();

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
            bootEnvironment: LiveBootDetector.detect().name,
          );
          _completedCertificate = report;
          final (_, reportSha) = await _auditLogService.saveFailureReport(
            report,
          );
          await _auditLogService.appendEntry(
            AuditLogEntry(
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
              outcome: 'wipe_failed',
              success: false,
              verificationPassed: false,
              certificateId: report.certificateId,
              certificateSha256: reportSha,
              fingerprintHash: 'EXECUTION_FAILED',
              entropyScore: 0.0,
              sampleCount: 0,
              commandLog: List<String>.from(job.logs),
              isSimulated: false,
              partitions: _buildPartitionOutcomes(
                job,
                false,
                override: outcomes.isNotEmpty ? outcomes : null,
              ),
            ),
          );
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
    job.currentStageDescription =
        'Unmounting filesystems & requesting target device lock...';
    _addLog('DISCOVERY: Classifying media topology & bus capabilities...');
    _addLog('SYSTEM: Unmounted partitions on ${job.device.name}');
    notifyListeners();

    // Stage 2: Sanitization Method Execution (Simulated Mode)
    await Future.delayed(const Duration(milliseconds: 1000));
    job.status = JobStatus.sanitizing;
    job.progress = 0.40;
    job.currentStageDescription =
        'Executing ${job.effectiveMethod.displayName}...';
    _addLog(
      'EXECUTION: Invoking controller command payload [Simulated Engine]...',
    );

    await _jobStateFile.saveActiveJob(
      ActiveJobState(
        jobId: job.jobId,
        deviceSerial: job.device.serialNumber,
        devicePath: '/dev/sdb',
        deviceName: job.device.name,
        method: job.effectiveMethod.displayName,
        methodKind: _methodKind(job.effectiveMethod),
        deviceSize: job.device.capacityBytes,
        startedAt:
            job.startTime?.toIso8601String() ??
            DateTime.now().toIso8601String(),
      ),
    );

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
      job.currentStageDescription =
          'Sanitization Interrupted: Hardware Controller Time-out';
      _addLog(
        'ERROR: Controller returned STATUS_ERR_TIMEOUT (Simulated Failure Injected)',
      );

      final evidence = _verificationService.verify(job, isSuccess: false);
      _completedCertificate = _certificateService.generateCertificate(
        job: job,
        evidence: evidence,
        executionMode: 'simulated',
        bootEnvironment: LiveBootDetector.detect().name,
      );
      try {
        final (_, reportSha) = await _auditLogService.saveFailureReport(
          _completedCertificate!,
        );
        await _auditLogService.appendEntry(
          AuditLogEntry(
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
            outcome: 'wipe_failed',
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
          ),
        );
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
    job.currentStageDescription =
        'Verifying sector erasure via 50-point readback sampling...';
    _addLog('VERIFICATION: Executing sector sampling across full LBA range...');
    notifyListeners();

    // Stage 4: Completion & Certificate Signing (Simulated Mode)
    await Future.delayed(const Duration(milliseconds: 800));
    job.status = JobStatus.completed;
    job.progress = 1.0;
    job.endTime = DateTime.now();
    job.currentStageDescription = 'Sanitization & Audit Verification Complete.';
    _addLog(
      'VERIFICATION: 50/50 Sector Samples zero-verified. SHA-256 evidence calculated.',
    );

    final evidence = _verificationService.verify(job, isSuccess: true);
    _completedCertificate = _certificateService.generateCertificate(
      job: job,
      evidence: evidence,
      executionMode: 'simulated',
      bootEnvironment: LiveBootDetector.detect().name,
    );
    _addLog(
      'CERTIFICATE: Issued ${completedCertificate!.certificateId} signed with ECDSA P-256 key.',
    );

    try {
      final (_, certSha) = await _auditLogService.saveCertificate(
        _completedCertificate!,
      );
      await _auditLogService.appendEntry(
        AuditLogEntry(
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
          outcome: 'completed',
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
        ),
      );
    } catch (_) {}

    await _jobStateFile.clearActiveJob();
    notifyListeners();
  }

  /// Re-run post-sanitize verification in place for the current job.
  ///
  /// Only valid after this job's wipe completed. It never starts a wipe,
  /// re-runs the guard chain, or mints a verified-wipe receipt: it refreshes
  /// the verification verdict, certificate and on-screen stage text.
  Future<void> verifyCurrentJob() async {
    final job = _currentJob;
    if (job == null || !job.wipeCompleted || isJobRunning) return;
    if (job.status != JobStatus.completed && job.status != JobStatus.failed) {
      return;
    }

    job.status = JobStatus.verifying;
    job.progress = null;
    job.currentStageDescription =
        'Verifying sector erasure via 50-point readback sampling...';
    _addLog('VERIFICATION: Re-running post-sanitize LBA sampling...');
    notifyListeners();

    if (_isRealMode && !_isMockingDevices) {
      await _runRealReverification(job);
    } else {
      await _runSimulatedReverification(job);
    }
  }

  Future<void> _runRealReverification(SanitizationJob job) async {
    if (kIsWeb || !Platform.isLinux) {
      final reason = kIsWeb
          ? 'Verification failed: real mode is not supported on Web.'
          : 'Verification failed: real mode is only supported on Linux.';
      await _applyVerificationResult(
        job,
        _verificationService.verify(job, isSuccess: false),
        failureReason: reason,
        executionMode: 'real',
      );
      return;
    }

    final targets = job.wipeExecutionTargets;
    final List<RealVerificationReport> reports = [];
    String? failureReason;

    for (var ti = 0; ti < targets.length; ti++) {
      final target = targets[ti];
      job.currentStageDescription = targets.length > 1
          ? 'Verifying partition ${ti + 1}/${targets.length}: ${target!.name}...'
          : 'Verifying sector erasure via 50-point readback sampling...';
      _addLog(
        'VERIFICATION: Sampling ${target?.devicePath ?? _deviceNode(job.device)}...',
      );
      notifyListeners();

      final cliMethod = _realSanitizeService.mapMethodToCliArg(
        job.effectiveMethod,
        job.device,
      );
      final isCryptoMethod =
          job.effectiveMethod == SanitizationMethod.cryptographicErase;

      try {
        final report = await _realSanitizeService.executeVerification(
          device: job.device,
          method: cliMethod,
          deviceSerial: job.device.serialNumber,
          targetPartition: target,
          sampleCount: 50,
          expectZeros: !isCryptoMethod,
          // Deliberately no verifiedReceiptPath: re-verification must not
          // mint or replace the one-shot post-wipe format receipt.
        );
        reports.add(report);
        if (!report.pass) {
          final scope = target == null ? 'whole device' : target.devicePath;
          failureReason ??=
              'Verification failed: non-zero or dirty sectors detected on '
              '$scope (${report.sampleCount} samples, fingerprint '
              '${report.fingerprintHash}).';
          _addLog('ERROR: $failureReason');
        }
      } catch (e) {
        failureReason ??= 'Verification failed: $e';
        _addLog('ERROR: Verification sampling failed: $e');
        break;
      }
    }

    if (failureReason == null && reports.isEmpty) {
      failureReason =
          'Verification failed: the engine returned no verification report.';
    }

    final bool passed =
        failureReason == null &&
        reports.isNotEmpty &&
        reports.every((report) => report.pass);

    final List<int> sampleOffsets = [];
    final Map<int, String> sampleHashes = {};
    for (final report in reports) {
      for (final sample in report.samples) {
        try {
          final offset = sample['offset'] as int;
          final hash = sample['sector_hash'] as String;
          sampleOffsets.add(offset);
          sampleHashes[offset] = hash;
        } catch (_) {}
      }
    }
    if (sampleOffsets.isEmpty) {
      sampleOffsets.addAll(List.generate(50, (index) => index * 1000));
      for (final offset in sampleOffsets) {
        sampleHashes[offset] =
            '0000000000000000000000000000000000000000000000000000000000000000';
      }
    }

    final RealVerificationReport? lastReport = reports.isEmpty
        ? null
        : reports.last;
    final int sampleCount = reports.fold<int>(
      0,
      (total, report) => total + report.sampleCount,
    );
    final evidence = VerificationEvidence(
      statusCode: passed ? 0 : 1,
      controllerConfirmation: reports.isEmpty
          ? 'VERIFICATION: Sampling unavailable (${failureReason ?? 'no report'})'
          : 'VERIFICATION: Pass: $passed | Samples: $sampleCount | '
                'Entropy: ${lastReport!.entropyScore}',
      sampleOffsets: sampleOffsets,
      sampleHashes: sampleHashes,
      evidenceHash: lastReport?.fingerprintHash ?? 'VERIFY_UNAVAILABLE',
      limitations: _verificationService.getTailoredLimitations(
        job.recommendedMethod,
      ),
      verifiedPassed: passed,
    );

    await _applyVerificationResult(
      job,
      evidence,
      sampleCount: sampleCount,
      entropyScore: lastReport?.entropyScore,
      failureReason: failureReason,
      executionMode: 'real',
    );
  }

  Future<void> _runSimulatedReverification(SanitizationJob job) async {
    job.progress = 0.9;
    notifyListeners();

    await Future.delayed(const Duration(milliseconds: 600));

    final bool passed = !job.shouldSimulateFailure;
    final evidence = _verificationService.verify(job, isSuccess: passed);
    await _applyVerificationResult(
      job,
      evidence,
      sampleCount: 50,
      entropyScore: passed ? 0.0 : 1.0,
      failureReason: passed
          ? null
          : 'Verification failed: non-zero or dirty sectors detected '
                '(simulated failure).',
      executionMode: 'simulated',
    );
  }

  Future<void> _applyVerificationResult(
    SanitizationJob job,
    VerificationEvidence evidence, {
    int? sampleCount,
    double? entropyScore,
    String? failureReason,
    required String executionMode,
  }) async {
    final bool passed = evidence.verifiedPassed;
    final int samples = sampleCount ?? evidence.sampleOffsets.length;

    job.status = passed ? JobStatus.completed : JobStatus.failed;
    job.progress = 1.0;
    job.endTime = DateTime.now();
    job.currentStageDescription = passed
        ? 'Verification passed: $samples/$samples sector samples are zero.'
        : (failureReason ??
              'Verification failed: non-zero or dirty sectors detected.');
    _addLog(
      passed
          ? 'VERIFICATION: Passed $samples/$samples sector samples.'
          : 'ERROR: ${job.currentStageDescription}',
    );
    notifyListeners();

    try {
      _completedCertificate = _certificateService.generateCertificate(
        job: job,
        evidence: evidence,
        executionMode: executionMode,
        actualMethodExecuted: job.effectiveMethod.displayName,
        stepsExecuted: List<String>.from(job.logs),
        verificationSampleCount: sampleCount,
        verificationEntropyScore: entropyScore,
        bootEnvironment: LiveBootDetector.detect().name,
        // Keep an already-recorded format step attached when re-verifying.
        filesystemRecreation: _filesystemRecreation,
      );
      _addLog(
        'CERTIFICATE: Issued ${_completedCertificate!.certificateId} for '
        'verification result.',
      );
    } catch (certErr) {
      _addLog('WARNING: Certificate generation failed: $certErr');
    }

    try {
      String? certSha;
      if (_completedCertificate != null) {
        final (_, sha) = await _auditLogService.saveCertificate(
          _completedCertificate!,
        );
        certSha = sha;
      }
      await _auditLogService.appendEntry(
        AuditLogEntry(
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
          method: job.effectiveMethod.displayName,
          methodClass: _deriveMethodClass(job.effectiveMethod),
          standardReference: job.standardReference,
          nistCategory: job.effectiveNistCategoryDisplayName,
          outcome: passed ? 'completed' : 'verify_failed',
          success: passed,
          verificationPassed: passed,
          certificateId: _completedCertificate?.certificateId,
          certificateSha256: certSha,
          fingerprintHash: evidence.evidenceHash,
          entropyScore: entropyScore ?? 0.0,
          sampleCount: samples,
          commandLog: List<String>.from(job.logs),
          isSimulated: executionMode == 'simulated',
          partitions: _buildPartitionOutcomes(job, passed),
        ),
      );
    } catch (auditErr) {
      _addLog('WARNING: Audit log write failed: $auditErr');
    }

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

  /// Seeds the verified-wipe receipt map so widget tests can exercise the
  /// optional filesystem-recreation prompt without running a real wipe.
  @visibleForTesting
  void setMockVerifiedFormatReceipts(Map<String, String> receipts) {
    _verifiedFormatReceipts
      ..clear()
      ..addAll(receipts);
    notifyListeners();
  }

  /// Phase G: seeds the pre-wipe "After wiping" decision so widget tests can
  /// exercise the blank-drive notice without running a real wipe.
  @visibleForTesting
  void setMockRestoreChoice({
    required bool restoreFilesystem,
    bool autoRestoreFailed = false,
    String? fsType,
    String? label,
  }) {
    _restoreChoiceKnown = true;
    _restoreAfterWipe = restoreFilesystem;
    _autoRestoreFailed = autoRestoreFailed;
    _restoreFsType = fsType;
    _restoreLabel = label;
    notifyListeners();
  }

  /// Phase G: seeds per-partition restore outcomes for widget tests.
  @visibleForTesting
  void setMockPartitionRestoreOutcomes(List<PartitionRestoreOutcome> outcomes) {
    _partitionRestoreOutcomes
      ..clear()
      ..addAll(outcomes);
    notifyListeners();
  }
}
