import 'dart:async';
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

class SanitizationController extends ChangeNotifier {
  final DeviceSimulator _simulator = DeviceSimulator();
  final DeviceIntelligenceService _intelligenceService = DeviceIntelligenceService();
  final ClassificationService _classificationService = ClassificationService();
  final RiskScoringService _riskScoringService = RiskScoringService();
  final RecommendationService _recommendationService = RecommendationService();
  final PolicyLayer _policyLayer = PolicyLayer();
  final VerificationService _verificationService = VerificationService();
  final CertificateService _certificateService = CertificateService();

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

  // Global dev simulator controls
  bool _simulateFailureMode = false;

  SanitizationController() {
    refreshDevices();
    _startAutoPolling();
  }

  // Getters
  List<DeviceProfile> get devices => _devices;
  DeviceProfile? get selectedDevice => _selectedDevice;
  bool get isRealMode => _isRealMode;
  bool get isAutoPollingActive => _autoPollTimer?.isActive ?? false;
  ClassificationService get classificationService => _classificationService;

  DataSensitivity get dataSensitivity => _dataSensitivity;
  DeviceCondition get deviceCondition => _deviceCondition;
  DisposalPath get disposalPath => _disposalPath;

  SanitizationJob? get currentJob => _currentJob;
  SanitizationCertificate? get completedCertificate => _completedCertificate;
  PolicyValidationResult? get lastPolicyResult => _lastPolicyResult;
  bool get simulateFailureMode => _simulateFailureMode;

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
            freshDevices[i].capacityBytes != _devices[i].capacityBytes) {
          hasChanged = true;
          break;
        }
      }
    }

    if (hasChanged || _devices.isEmpty) {
      _devices = freshDevices;
      if (_devices.isNotEmpty) {
        if (_selectedDevice == null || !_devices.any((d) => d.id == _selectedDevice!.id)) {
          _selectedDevice = _devices.first;
        }
      } else {
        _selectedDevice = null;
      }
      _updateJobRecommendation();
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _stopAutoPolling();
    super.dispose();
  }

  void selectDevice(DeviceProfile device) {
    _selectedDevice = device;
    _updateJobRecommendation();
    notifyListeners();
  }

  void setRiskInputs({
    DataSensitivity? sensitivity,
    DeviceCondition? condition,
    DisposalPath? path,
  }) {
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
    _simulator.resetProfiles();
    refreshDevices();
    _currentJob = null;
    _completedCertificate = null;
    _lastPolicyResult = null;
    notifyListeners();
  }

  void _updateJobRecommendation() {
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

  // Orchestrate simulated pipeline execution
  Future<void> runSanitizationPipeline() async {
    if (_currentJob == null) return;

    final job = _currentJob!;
    job.startTime = DateTime.now();
    job.status = JobStatus.detecting;
    job.progress = 0.05;
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

    // Stage 1: Detecting & Locking device
    await Future.delayed(const Duration(milliseconds: 800));
    job.status = JobStatus.unmounting;
    job.progress = 0.20;
    job.currentStageDescription = 'Unmounting filesystems & requesting target device lock...';
    _addLog('DISCOVERY: Classifying media topology & bus capabilities...');
    _addLog('SYSTEM: Unmounted partitions on ${job.device.name}');
    notifyListeners();

    // Stage 2: Sanitization Method Execution
    await Future.delayed(const Duration(milliseconds: 1000));
    job.status = JobStatus.sanitizing;
    job.progress = 0.40;
    job.currentStageDescription = 'Executing ${job.recommendedMethod.displayName}...';
    _addLog('EXECUTION: Invoking controller command payload [Simulated Engine]...');

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
      notifyListeners();
      return;
    }

    // Stage 3: Verification (Algorithm 3)
    await Future.delayed(const Duration(milliseconds: 600));
    job.status = JobStatus.verifying;
    job.progress = 0.90;
    job.currentStageDescription = 'Verifying sector erasure via 50-point readback sampling...';
    _addLog('VERIFICATION: Algorithm 3 executing sector sampling across full LBA range...');
    notifyListeners();

    // Stage 4: Completion & Certificate Signing
    await Future.delayed(const Duration(milliseconds: 800));
    job.status = JobStatus.completed;
    job.progress = 1.0;
    job.endTime = DateTime.now();
    job.currentStageDescription = 'Sanitization & Audit Verification Complete.';
    _addLog('VERIFICATION: 50/50 Sector Samples zero-verified. SHA-256 evidence calculated.');

    final evidence = _verificationService.verify(job, isSuccess: true);
    _completedCertificate = _certificateService.generateCertificate(job: job, evidence: evidence);
    _addLog('CERTIFICATE: Issued ${completedCertificate!.certificateId} signed with ECDSA P-256 key.');

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
