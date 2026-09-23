import '../models/sanitization_job.dart';

class PolicyValidationResult {
  final bool isAllowed;
  final String policyMessage;

  PolicyValidationResult({required this.isAllowed, required this.policyMessage});
}

class PolicyLayer {
  // Strict Whitelist of allowable action tokens
  static const Set<SanitizationMethod> _whitelistedMethods = {
    SanitizationMethod.cryptographicErase,
    SanitizationMethod.ataSecureErase,
    SanitizationMethod.ataSanitizeBlockErase,
    SanitizationMethod.nvmeSanitize,
    SanitizationMethod.emmcSanitize,
    SanitizationMethod.singlePassOverwrite,
    SanitizationMethod.multiPassOverwrite,
  };

  PolicyValidationResult validateOperation(SanitizationJob job) {
    final method = job.effectiveMethod;

    // Safety Rule 2: Root disk check
    if (job.device.isSystemDisk || job.device.mountPoint == '/') {
      return PolicyValidationResult(
        isAllowed: false,
        policyMessage: 'POLICY VIOLATION: Refusing operation target on system boot disk or root mount point.',
      );
    }

    // Safety Rule 3: Whitelist check
    if (!_whitelistedMethods.contains(method)) {
      return PolicyValidationResult(
        isAllowed: false,
        policyMessage: 'POLICY DENIED: Recommended method (${method.displayName}) is non-executable or requires physical destruction.',
      );
    }

    return PolicyValidationResult(
      isAllowed: true,
      policyMessage: 'POLICY PASSED: Method ${method.displayName} matches static execution whitelist.',
    );
  }
}
