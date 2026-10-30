import '../models/certificate.dart';

/// Honest wording for a certificate or failure report.
///
/// A failure report must never claim that a wipe overwrote the target when the
/// engine did not confirm it, and it must never present the synthetic sample
/// offsets / hash used as a UI placeholder as if verification had run.
class FailureReportWording {
  const FailureReportWording._();

  static const String confirmedPartitionHeading =
      'Target Partitions Overwritten:';
  static const String unconfirmedPartitionHeading =
      'Target partitions (not confirmed overwritten)';
  static const String verificationNotRun = 'Verification: not run';

  static const Set<String> _placeholderHashes = {
    '',
    'n/a',
    'na',
    'none',
    'null',
    'unavailable',
    'verify_unavailable',
    'error_verification_failed',
    'execution_failed',
    'simulated_failure',
    'not run',
    'not_run',
    'pending',
    'placeholder',
  };

  static const List<String> _notRunMarkers = [
    'verification: not run',
    'sampling unavailable',
    'no verification report',
  ];

  /// True when [evidence] is a real verification report rather than the
  /// synthetic placeholder used when sampling never ran.
  static bool hasUsableEvidence(VerificationEvidence evidence) {
    final hash = evidence.evidenceHash.trim().toLowerCase();
    if (_placeholderHashes.contains(hash)) return false;
    if (evidence.sampleOffsets.isEmpty || evidence.sampleHashes.isEmpty) {
      return false;
    }

    final hashes = evidence.sampleHashes.values
        .map((value) => value.trim())
        .toList(growable: false);
    final allZero = hashes.every(
      (value) => value.isNotEmpty && RegExp(r'^0+$').hasMatch(value),
    );
    if (allZero) return false;

    final confirmation = evidence.controllerConfirmation.toLowerCase();
    return !_notRunMarkers.any(confirmation.contains);
  }

  /// True when the certificate carries real evidence that a verification pass
  /// ran. Placeholder hashes, empty sample sets and the all-zero synthetic
  /// samples are all treated as "did not run".
  static bool verificationRan(SanitizationCertificate cert) {
    if (cert.verificationSampleCount != null &&
        cert.verificationSampleCount! <= 0) {
      return false;
    }
    if (cert.verificationSummary.toLowerCase().contains(
      'verification: not run',
    )) {
      return false;
    }
    if (!hasUsableEvidence(cert.evidence)) return false;

    // A successful certificate with real sample evidence is verification.
    if (cert.result != 'FAILED') return true;

    // On a failed certificate, only an explicit verification report confirms
    // that the verification stage actually ran. A generic failure placeholder
    // must not be displayed as sample evidence.
    final confirmation = cert.evidence.controllerConfirmation.toLowerCase();
    return confirmation.contains('verification: pass') ||
        confirmation.contains('controller_status_ok') ||
        confirmation.contains('controller_error') ||
        confirmation.contains('samples:') ||
        confirmation.contains('verification passed');
  }

  /// True only when the wipe itself completed (or its verification proves the
  /// wipe stage finished). A failed wipe with no confirmation stays unclaimed.
  static bool overwriteConfirmed(SanitizationCertificate cert) {
    if (cert.result != 'FAILED') return true;
    if (cert.wipeCompleted == true) return true;
    if (verificationRan(cert)) return true;
    final confirmation = cert.evidence.controllerConfirmation.toLowerCase();
    return confirmation.contains('disk wipe command succeeded') ||
        confirmation.contains('wipe completed');
  }

  static String partitionHeading(SanitizationCertificate cert) =>
      overwriteConfirmed(cert)
      ? confirmedPartitionHeading
      : unconfirmedPartitionHeading;

  /// True when the evidence is synthetic/absent rather than a real report.
  static bool hasPlaceholderEvidence(SanitizationCertificate cert) =>
      !verificationRan(cert);
}
