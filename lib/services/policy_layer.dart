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

  /// Mount point allowlist: ONLY mounts under these paths are considered unmountable.
  /// Everything else is considered a protected system mount.
  /// (Note: Rust zt_engine is the authoritative enforcement point with kernel major:minor stack analysis).
  static bool isMountUnmountable(String mountPoint) {
    final mp = mountPoint.trim();
    if (mp.isEmpty) return false;

    // Explicitly protect live-media mounts
    if (mp.startsWith('/run/live') ||
        mp.startsWith('/run/archiso') ||
        mp.contains('/live/') ||
        mp.contains('/archiso/') ||
        mp.contains('/casper/')) {
      return false;
    }

    if (mp == '/mnt' || mp.startsWith('/mnt/')) return true;
    if (mp == '/media' || mp.startsWith('/media/')) return true;
    if (mp == '/run/media' || mp.startsWith('/run/media/')) return true;

    return false;
  }

  PolicyValidationResult validateOperation(SanitizationJob job) {
    final method = job.effectiveMethod;

    // Safety Rule 2: Root disk & protected system mount check
    // (Advisory check in Dart; Rust zt_engine execute.rs is the ultimate kernel authority)
    if (job.device.isSystemDisk) {
      return PolicyValidationResult(
        isAllowed: false,
        policyMessage: 'POLICY VIOLATION: Refusing operation target on system boot disk or protected media.',
      );
    }

    final mp = job.device.mountPoint;
    if (mp != null && mp.isNotEmpty && !isMountUnmountable(mp)) {
      return PolicyValidationResult(
        isAllowed: false,
        policyMessage: 'POLICY VIOLATION: Device has protected mount point ($mp). Only mounts under /mnt, /media, or /run/media are unmountable.',
      );
    }

    // Safety Rule 3: Whitelist check
    if (!_whitelistedMethods.contains(method)) {
      return PolicyValidationResult(
        isAllowed: false,
        policyMessage: 'POLICY DENIED: Recommended method (${method.displayName}) is non-executable or requires physical destruction.',
      );
    }

    // Safety Rule 4: Partition mode method allowlist & target protection
    if (job.isPartitionScope) {
      // Decision: partitions on INTERNAL disks are not wipeable. Partition-scoped
      // wiping is for removable media only (strict rule); there is no override.
      if (!job.device.isRemovable) {
        return PolicyValidationResult(
          isAllowed: false,
          policyMessage: 'POLICY VIOLATION: Partition-scoped wiping is only permitted on removable media. Partitions on internal disks are not wipeable.',
        );
      }

      if (method != SanitizationMethod.singlePassOverwrite &&
          method != SanitizationMethod.multiPassOverwrite) {
        return PolicyValidationResult(
          isAllowed: false,
          policyMessage: 'POLICY VIOLATION: Partition mode only allows overwrite methods (Single-Pass Zero or 3-Pass Overwrite). Controller-level firmware erase cannot target a single partition.',
        );
      }

      final part = job.targetPartition;
      if (part != null) {
        if (part.isProtected || part.isActiveSwap) {
          return PolicyValidationResult(
            isAllowed: false,
            policyMessage: 'POLICY VIOLATION: Target partition (${part.name}) is protected (system mount, active swap, or live media).',
          );
        }
        if (part.isMounted && !part.isMountAllowed) {
          return PolicyValidationResult(
            isAllowed: false,
            policyMessage: 'POLICY VIOLATION: Target partition (${part.name}) has protected mount (${part.mountPoint}).',
          );
        }
      }
    }

    return PolicyValidationResult(
      isAllowed: true,
      policyMessage: 'POLICY PASSED: Method ${method.displayName} matches static execution whitelist.',
    );
  }
}
