import '../models/partition_info.dart';
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
      final part = job.targetPartition;
      if (part == null) {
        return PolicyValidationResult(
          isAllowed: false,
          policyMessage: 'POLICY VIOLATION: Partition-scoped wipe requires an explicitly selected target partition.',
        );
      }
      final perTarget = validatePartitionTarget(job, part);
      if (!perTarget.isAllowed) return perTarget;
    }

    return PolicyValidationResult(
      isAllowed: true,
      policyMessage: 'POLICY PASSED: Method ${method.displayName} matches static execution whitelist.',
    );
  }

  /// B4: per-target partition-scope gate. Validates ONE partition of a
  /// partition-scope job. [validateOperation] uses it for the first target;
  /// the controller runs it as a fail-closed pre-flight over EVERY selected
  /// partition before the first wipe starts.
  ///
  /// Messages are identical to the original inline Rule 4 checks so existing
  /// policy tests and operator-facing wording stay stable.
  PolicyValidationResult validatePartitionTarget(SanitizationJob job, PartitionInfo part) {
    final method = job.effectiveMethod;

    // A3: internal-disk partitions are allowed, but ONLY non-system ones.
    // Still refused below: the boot/system disk (isSystemDisk covers disks
    // hosting /, /boot, /boot/efi, /usr, /var, /home and live media),
    // protected mounts, active swap, and busy holders. The Rust engine is
    // the authoritative enforcement point and applies the same family
    // (disk + sibling partitions) rules plus live-mode awareness.
    if (job.device.isSystemDisk) {
      return PolicyValidationResult(
        isAllowed: false,
        policyMessage:
            'POLICY VIOLATION: Refusing partition wipe on the system/live disk (${job.device.name}). '
            'The disk hosting the operating system or live medium is never wipeable, including its non-system partitions.',
      );
    }

    if (method != SanitizationMethod.singlePassOverwrite &&
        method != SanitizationMethod.multiPassOverwrite) {
      return PolicyValidationResult(
        isAllowed: false,
        policyMessage: 'POLICY VIOLATION: Partition mode only allows overwrite methods (Single-Pass Zero or 3-Pass Overwrite). Controller-level firmware erase cannot target a single partition.',
      );
    }

    // A3: partitions holding system paths are never wipeable, even when
    // mounted under an otherwise-unmountable location.
    const systemMounts = {'/', '/boot', '/boot/efi', '/usr', '/var', '/home'};
    final partMp = part.mountPoint;
    if (partMp != null && systemMounts.contains(partMp)) {
      return PolicyValidationResult(
        isAllowed: false,
        policyMessage: 'POLICY VIOLATION: Target partition (${part.name}) holds a system path ($partMp) and is never wipeable.',
      );
    }
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

    return PolicyValidationResult(
      isAllowed: true,
      policyMessage: 'POLICY PASSED: Target partition (${part.name}) passes partition-scope policy.',
    );
  }
}
