import 'dart:io' show Platform;
import '../models/assistant_context.dart';
import '../models/device_profile.dart';
import '../models/sanitization_error_code.dart';
import '../models/sanitization_job.dart';
import '../models/untrusted_text.dart';
import 'sanitization_controller.dart';

import '../models/sanitization_support_level.dart';

/// Safely constructs an immutable [AssistantContext] snapshot from [SanitizationController].
///
/// ADVISORY-ONLY & ISOLATION:
/// - Only reads state; NEVER calls controller mutators or execution commands.
/// - The controller and services remain completely decoupled from the [AssistantContext] model.
class AssistantContextBuilder {
  /// Builds a snapshot of the current state.
  static AssistantContext fromController(
    SanitizationController controller, {
    DeviceProfile? overrideDevice,
    bool clearDevice = false,
    String? platform,
  }) {
    // 1. Resolve Device
    DeviceProfile? device;
    if (!clearDevice) {
      device = overrideDevice ?? controller.selectedDevice;
    }

    bool isDisconnected = false;
    if (device != null) {
      // Check if device is still present in current devices list
      final isPresent = controller.devices.any((d) => d.stableId == device!.stableId);
      if (!isPresent) {
        isDisconnected = true;
      }
    }

    // 2. Resolve Job State
    final job = controller.currentJob;
    final bool isJobRunning = job != null &&
        (job.status == JobStatus.sanitizing ||
         job.status == JobStatus.verifying ||
         job.status == JobStatus.detecting ||
         job.status == JobStatus.unmounting);
    final bool isCompleted = job?.status == JobStatus.completed;
    final bool isFailed = job?.status == JobStatus.failed;
    final bool jobStarted = isJobRunning || isCompleted || isFailed;
    final bool wipeCompleted = job?.wipeCompleted ?? false;

    // 3. Resolve Error Code
    SanitizationErrorCode? lastErrorCode;
    String? rawErrorMessage;

    if (isFailed) {
      rawErrorMessage = job?.currentStageDescription;
      lastErrorCode = SanitizationErrorCode.fromRawString(rawErrorMessage);
    } else if (controller.lastScanError != null && controller.lastScanError!.isNotEmpty) {
      rawErrorMessage = controller.lastScanError;
      lastErrorCode = SanitizationErrorCode.fromRawString(rawErrorMessage);
    }

    // 4. Resolve Certificate & Verification
    final cert = controller.completedCertificate;
    final bool hasCert = cert != null;

    bool? verificationPassed;
    int? verificationSampleCount = cert?.verificationSampleCount;
    double? verificationEntropyScore = cert?.verificationEntropyScore;
    String? verificationMethod = job?.recommendedMethod.displayName;

    if (job != null && (isCompleted || isFailed)) {
      if (isFailed && !wipeCompleted) {
        // Failed during wipe, verification never ran
        verificationPassed = null;
      } else {
        // If stage description notes verification failure or pass
        final desc = job.currentStageDescription.toLowerCase();
        if (desc.contains('dirty') || desc.contains('non-zero') || desc.contains('verification failed')) {
          verificationPassed = false;
        } else if (isCompleted) {
          verificationPassed = true;
        }
      }
    }

    // 5. Platform
    final String currentPlatform = platform ??
        (Platform.isLinux
            ? 'Linux'
            : Platform.isWindows
                ? 'Windows'
                : Platform.isMacOS
                    ? 'macOS'
                    : Platform.operatingSystem);

    return AssistantContext(
      deviceName: device != null ? UntrustedText(device.name) : null,
      driveType: device?.driveType,
      mediaType: device?.mediaType,
      busType: device?.busType,
      sizeBytes: device?.capacityBytes,
      formattedSize: device?.formattedCapacity,
      supportLevel: device != null ? computeSupportLevel(device) : null,
      mediaTechnology: device?.mediaTechnology ?? MediaTechnology.unknown,
      isRotational: device?.isRotational ?? false,
      isFlash: device?.isFlashMedia ?? false,
      isRemovable: device?.isRemovable ?? false,
      isSecurityFrozen: device?.notes.toLowerCase().contains('frozen') ?? false,
      hasHpaDco: device?.hpaDcoPresent ?? false,
      isDisconnected: isDisconnected,
      methodClass: job?.recommendedMethod,
      jobStatus: job?.status,
      jobStageDescription: job?.currentStageDescription,
      jobStarted: jobStarted,
      wipeCompleted: wipeCompleted,
      verificationPassed: verificationPassed,
      verificationSampleCount: verificationSampleCount,
      verificationEntropyScore: verificationEntropyScore,
      verificationMethod: verificationMethod,
      lastErrorCode: lastErrorCode,
      lastErrorMessage: rawErrorMessage != null ? UntrustedText(rawErrorMessage) : null,
      hasCertificate: hasCert,
      certificateId: cert?.certificateId != null ? UntrustedText(cert!.certificateId) : null,
      isCertificateSimulated: cert?.executionMode == 'simulated',
      isSimulated: !controller.isRealMode,
      platform: currentPlatform,
    );
  }
}
