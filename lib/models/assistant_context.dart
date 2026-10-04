/// Immutable context model for the AI Assistant.
///
/// SAFETY & PRIVACY:
/// 1. This model is a pure, read-only data snapshot. It NEVER imports or calls
///    SanitizationController or any execution engine.
/// 2. It NEVER contains physical device paths (e.g. /dev/sda), physical serial numbers,
///    or WWNs. Coarse facts only.
/// 3. Fields derived from hardware or user input (deviceName, lastErrorMessage, certificateId)
///    are marked as untrusted and must pass through redaction before any external model call.
library;

import 'device_profile.dart';
import 'sanitization_error_code.dart';
import 'sanitization_job.dart';
import 'sanitization_support_level.dart';

class AssistantContext {
  /// Untrusted hardware/user string. Must be sanitized before prompt injection.
  final String? deviceName;

  final DriveType? driveType;
  final MediaType? mediaType;
  final String? busType;
  final int? sizeBytes;
  final String? formattedSize;
  final SanitizationSupportLevel? supportLevel;

  final bool isRotational;
  final bool isFlash;
  final bool isRemovable;
  final bool isSecurityFrozen;
  final bool hasHpaDco;

  /// True if the pinned device was disconnected or disappeared from system enumeration.
  final bool isDisconnected;

  final SanitizationMethod? methodClass;
  final JobStatus? jobStatus;
  final String? jobStageDescription;
  final bool jobStarted;
  final bool wipeCompleted;

  final bool? verificationPassed;
  final int? verificationSampleCount;
  final double? verificationEntropyScore;
  final String? verificationMethod;

  final SanitizationErrorCode? lastErrorCode;

  /// Untrusted error text. Must be sanitized before prompt injection.
  final String? lastErrorMessage;

  final bool hasCertificate;

  /// Untrusted certificate identifier. Must be sanitized before prompt injection.
  final String? certificateId;

  final bool? isCertificateSimulated;
  final bool isSimulated;
  final String platform;

  const AssistantContext({
    this.deviceName,
    this.driveType,
    this.mediaType,
    this.busType,
    this.sizeBytes,
    this.formattedSize,
    this.supportLevel,
    this.isRotational = false,
    this.isFlash = false,
    this.isRemovable = false,
    this.isSecurityFrozen = false,
    this.hasHpaDco = false,
    this.isDisconnected = false,
    this.methodClass,
    this.jobStatus,
    this.jobStageDescription,
    this.jobStarted = false,
    this.wipeCompleted = false,
    this.verificationPassed,
    this.verificationSampleCount,
    this.verificationEntropyScore,
    this.verificationMethod,
    this.lastErrorCode,
    this.lastErrorMessage,
    this.hasCertificate = false,
    this.certificateId,
    this.isCertificateSimulated,
    this.isSimulated = true,
    this.platform = 'Linux',
  });

  /// True if a device is currently selected in this context.
  bool get hasDevice => deviceName != null && deviceName!.isNotEmpty;

  /// Human-readable target summary for message cards (e.g. "Answered for: Samsung SSD 980").
  String get targetSummary {
    if (!hasDevice) return 'None (general knowledge)';
    if (isDisconnected) return '$deviceName (disconnected)';
    return deviceName!;
  }

  /// Generates dynamic, context-aware quick questions capped at ~6.
  /// Prioritizes active errors and failures first.
  List<String> get quickQuestions {
    final questions = <String>[];

    // 1. Errors and Failures (Highest Priority)
    if (verificationPassed == false) {
      questions.add('Why did verification fail?');
    }
    if (lastErrorCode != null && lastErrorCode != SanitizationErrorCode.unknown) {
      questions.add('Explain this error: ${lastErrorCode!.name}');
      questions.add('What should I do after this error?');
    } else if (jobStatus == JobStatus.failed) {
      questions.add('Why did the sanitization fail?');
      questions.add('What should I do after this error?');
    }

    // 2. Active Certificate
    if (hasCertificate) {
      questions.add('Explain this certificate');
      questions.add('What does the cryptographic signature prove?');
    }

    // 3. Device Characteristics
    if (hasDevice) {
      if (isSecurityFrozen) {
        questions.add('What does security frozen mean?');
      }
      if (hasHpaDco) {
        questions.add('What are HPA/DCO hidden sectors?');
      }
      if (isFlash) {
        questions.add('Why is overwrite not recommended for SSDs?');
        questions.add('What is the Flash Translation Layer?');
      } else if (isRotational) {
        questions.add('How does overwrite work for HDDs?');
      }
      questions.add('What sanitization method is recommended?');
      questions.add('Why is this device high risk?');
    }

    // 4. General fallback questions (when no device or to fill up to 6)
    if (questions.length < 6) {
      final general = <String>[
        'Explain CLEAR vs PURGE',
        'Explain NIST SP 800-88 categories',
        'What does cryptographic erase mean?',
        'What is physical destruction?',
        'What is PALES research?',
      ];
      for (final g in general) {
        if (!questions.contains(g)) {
          questions.add(g);
        }
        if (questions.length >= 6) break;
      }
    }

    // Cap at 6 maximum
    return questions.take(6).toList();
  }
}
