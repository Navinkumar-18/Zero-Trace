/// Typed sanitization error codes shared across the engine, controller,
/// error_messages.dart, and the AI assistant.
///
/// SAFETY: Centralized definition ensures no duplicated string maps and
/// consistent, platform-aware user and assistant explanations.
library;

enum SanitizationErrorCode {
  bootDiskProtection,
  confirmationMismatch,
  deviceNotFound,
  securityFrozen,
  permissionDenied,
  deviceBusy,
  timeout,
  interrupted,
  verificationFailed,
  verificationReadError,
  unsupportedOperation,
  unknown;

  /// Classify any raw error string or code into a typed [SanitizationErrorCode].
  static SanitizationErrorCode fromRawString(String? rawError) {
    if (rawError == null || rawError.trim().isEmpty) {
      return SanitizationErrorCode.unknown;
    }

    final lower = rawError.toLowerCase();

    // Check root/boot disk protection
    if (lower.contains('boot') ||
        lower.contains('root') ||
        lower.contains('bootdiskprotection') ||
        lower.contains('protected system drive') ||
        lower.contains('refusing to operate on os root')) {
      return SanitizationErrorCode.bootDiskProtection;
    }

    // Check confirmation token / serial mismatch
    if (lower.contains('confirmation') ||
        lower.contains('mismatch') ||
        lower.contains('token')) {
      return SanitizationErrorCode.confirmationMismatch;
    }

    // Check device missing or unplugged
    if (lower.contains('not found') ||
        lower.contains('disconnected') ||
        lower.contains('removed') ||
        lower.contains('no such device')) {
      return SanitizationErrorCode.deviceNotFound;
    }

    // Check ATA security frozen
    if (lower.contains('frozen') ||
        lower.contains('security freeze') ||
        lower.contains('securityfrozen')) {
      return SanitizationErrorCode.securityFrozen;
    }

    // Check permissions
    if (lower.contains('permission') ||
        lower.contains('eacces') ||
        lower.contains('access denied') ||
        lower.contains('elevated') ||
        lower.contains('polkit') ||
        lower.contains('uac')) {
      return SanitizationErrorCode.permissionDenied;
    }

    // Check mount / busy
    if (lower.contains('mount') ||
        lower.contains('busy') ||
        lower.contains('ebusy') ||
        lower.contains('in use') ||
        lower.contains('holder')) {
      return SanitizationErrorCode.deviceBusy;
    }

    // Check timeout
    if (lower.contains('timeout') ||
        lower.contains('timed out') ||
        lower.contains('status_err_timeout')) {
      return SanitizationErrorCode.timeout;
    }

    // Check user cancellation or interrupted
    if (lower.contains('interrupted') ||
        lower.contains('cancelled') ||
        lower.contains('canceled') ||
        lower.contains('abort')) {
      return SanitizationErrorCode.interrupted;
    }

    // Check verification failure: dirty / non-zero sectors
    if (lower.contains('verification failed') ||
        lower.contains('non-zero') ||
        lower.contains('dirty sector') ||
        lower.contains('verify_failed')) {
      return SanitizationErrorCode.verificationFailed;
    }

    // Check verification I/O read failure
    if (lower.contains('read error') ||
        lower.contains('read failed') ||
        lower.contains('readfailed')) {
      return SanitizationErrorCode.verificationReadError;
    }

    // Check unsupported operation
    if (lower.contains('unsupported') ||
        lower.contains('not supported') ||
        lower.contains('unsupportedoperation')) {
      return SanitizationErrorCode.unsupportedOperation;
    }

    return SanitizationErrorCode.unknown;
  }

  /// Plain-language short message for UI banners and dialogs.
  String toSimpleUserMessage({String platform = 'Linux'}) {
    switch (this) {
      case SanitizationErrorCode.bootDiskProtection:
        return 'This is your system drive. It cannot be wiped.';
      case SanitizationErrorCode.confirmationMismatch:
        return 'Serial confirmation did not match. Re-enter the last 4 characters.';
      case SanitizationErrorCode.deviceNotFound:
        return 'Drive was unplugged. Reconnect and try again.';
      case SanitizationErrorCode.securityFrozen:
        return 'Drive is locked/frozen. Power-cycle the drive and try again.';
      case SanitizationErrorCode.permissionDenied:
        return platform == 'Windows'
            ? 'Administrator permission required. Approve the User Account Control prompt.'
            : 'Administrator permission required. Approve the elevation prompt or verify account permissions.';
      case SanitizationErrorCode.deviceBusy:
        return 'Drive is in use. Close open files/programs and unmount all partitions.';
      case SanitizationErrorCode.timeout:
        return 'The drive stopped responding. Reconnect and retry.';
      case SanitizationErrorCode.interrupted:
        return 'Wipe was interrupted. The drive may contain partial data.';
      case SanitizationErrorCode.verificationFailed:
        return 'Verification failed: non-zero data detected on the drive.';
      case SanitizationErrorCode.verificationReadError:
        return 'Verification failed: unable to read sectors from the drive.';
      case SanitizationErrorCode.unsupportedOperation:
        return 'Selected sanitization method is not supported by this hardware controller.';
      case SanitizationErrorCode.unknown:
        return 'An unexpected error occurred during sanitization.';
    }
  }

  /// Detailed plain-language explanation and next steps for the AI Assistant.
  ErrorExplanation explain({
    String platform = 'Linux',
    bool jobStarted = true,
    bool isSimulated = false,
  }) {
    String summary;
    String rootCause;
    String nextStep;
    bool dataMayRemain;

    switch (this) {
      case SanitizationErrorCode.bootDiskProtection:
        summary = 'System Boot Disk Protection Active';
        rootCause = 'Zero Trace detected that the target drive contains the active operating system root, boot, or swap volume. '
            'Wiping the host operating system drive from within the running system is blocked to prevent catastrophic system destruction.';
        nextStep = 'To sanitize this computer\'s internal drive, boot the machine from an external Zero Trace live USB/media environment.';
        dataMayRemain = false; // Blocked before starting; no write occurred
        break;

      case SanitizationErrorCode.confirmationMismatch:
        summary = 'Confirmation Token Mismatch';
        rootCause = 'The confirmation characters entered did not match the required drive identifier (serial number or path signature). '
            'This safety interlock prevents accidentally targeting the wrong drive.';
        nextStep = 'Verify the physical drive serial number and re-enter the last 4 characters accurately.';
        dataMayRemain = false; // Blocked before starting; no write occurred
        break;

      case SanitizationErrorCode.deviceNotFound:
        summary = 'Storage Device Disconnected';
        rootCause = 'The storage controller lost communication with the drive during the operation. This usually happens if a USB cable is bumped, power fluctuates, or the drive controller reset.';
        nextStep = 'Reconnect the drive firmly to a direct port (avoid unpowered hubs) and inspect the connection before retrying.';
        dataMayRemain = jobStarted;
        break;

      case SanitizationErrorCode.securityFrozen:
        summary = 'Drive Security State is Frozen';
        rootCause = 'The computer BIOS/UEFI locked the drive\'s ATA security registers at boot time to prevent unauthorized firmware attacks. In a frozen state, hardware sanitize and ATA Secure Erase commands are rejected by the drive.';
        nextStep = 'Power-cycle the drive: if external, disconnect and reconnect USB power; if internal, suspend/sleep the computer briefly and wake it, or reboot into BIOS to check security settings.';
        dataMayRemain = false; // Rejected prior to writing
        break;

      case SanitizationErrorCode.permissionDenied:
        summary = 'Insufficient System Privileges';
        rootCause = 'Direct block-device I/O and low-level firmware sanitize commands require elevated administrative authority.';
        nextStep = platform == 'Windows'
            ? 'Approve the User Account Control (UAC) prompt or ensure your user account has administrative privileges.'
            : 'Approve the administrator authorization prompt (Polkit) or ensure your account has direct storage device access privileges.';
        dataMayRemain = false; // Blocked before write
        break;

      case SanitizationErrorCode.deviceBusy:
        summary = 'Device or Partition Currently in Use';
        rootCause = 'The storage device has active file system mounts, open file handles, or active volume holders (such as LVM, LUKS, or RAID). '
            'Wiping a mounted or busy volume can corrupt kernel caches and active filesystems.';
        nextStep = 'Close any programs, file managers, or terminals accessing the drive, unmount all partitions, and try again.';
        dataMayRemain = false;
        break;

      case SanitizationErrorCode.timeout:
        summary = 'Storage Controller Timeout';
        rootCause = 'The drive stopped responding to I/O or firmware commands within the timeout window.';
        nextStep = 'Reconnect the drive and try again. If timeouts repeat across multiple attempts, the drive hardware may be failing or degraded.';
        dataMayRemain = jobStarted;
        break;

      case SanitizationErrorCode.interrupted:
        summary = 'Sanitization Run Interrupted';
        rootCause = 'The wipe process was stopped prematurely, either by user cancellation, system shutdown, or device disconnection.';
        nextStep = 'Re-run the sanitization procedure from start to finish to ensure complete erasure.';
        dataMayRemain = jobStarted;
        break;

      case SanitizationErrorCode.verificationFailed:
        summary = 'Verification Failed: Residual Data Detected';
        rootCause = 'Sample readback of sampled Logical Block Addresses (LBAs) detected non-zero or dirty sectors on the disk after wiping. '
            'This means the sanitization pass did not achieve the required assurance level.';
        nextStep = 'Retry sanitization using an alternate engine-supported method. For drives handling confidential data that fail verification, NIST recommends physical destruction.';
        dataMayRemain = true;
        break;

      case SanitizationErrorCode.verificationReadError:
        summary = 'Verification Read Error';
        rootCause = 'Zero Trace was unable to read sampled sectors back from the drive due to an I/O read failure or bad physical sectors.';
        nextStep = 'Check physical cabling and verify drive health. If bad sectors prevent verification readback, physical destruction may be required.';
        dataMayRemain = true;
        break;

      case SanitizationErrorCode.unsupportedOperation:
        summary = 'Command Not Supported by Drive Firmware';
        rootCause = 'The requested firmware sanitize command (e.g. ATA Sanitize, NVMe Sanitize, or Cryptographic Erase) is not supported by this specific drive controller.';
        nextStep = 'Select an alternate method supported by the device, such as software overwrite (Clear level) or physical destruction.';
        dataMayRemain = false;
        break;

      case SanitizationErrorCode.unknown:
        summary = 'Unexpected Operation Error';
        rootCause = 'An unspecified error occurred while interacting with the storage subsystem.';
        nextStep = 'Verify the device connection, check system diagnostic logs, and ensure no other disk utilities are interacting with the drive.';
        dataMayRemain = jobStarted;
        break;
    }

    return ErrorExplanation(
      code: this,
      summary: summary,
      rootCause: rootCause,
      nextStep: nextStep,
      dataMayRemain: dataMayRemain,
      isSimulated: isSimulated,
    );
  }
}

/// Structured explanation model returned by [SanitizationErrorCode.explain].
class ErrorExplanation {
  final SanitizationErrorCode code;
  final String summary;
  final String rootCause;
  final String nextStep;
  final bool dataMayRemain;
  final bool isSimulated;

  const ErrorExplanation({
    required this.code,
    required this.summary,
    required this.rootCause,
    required this.nextStep,
    required this.dataMayRemain,
    required this.isSimulated,
  });

  /// Formatted explanation string suitable for the AI Assistant.
  String toFormattedText() {
    final buffer = StringBuffer();

    if (isSimulated) {
      buffer.writeln('⚠️ [SIMULATION MODE] No data was actually written or erased; this error occurred during simulation testing.\n');
    }

    buffer.writeln('**$summary**\n');
    buffer.writeln('• **What happened:** $rootCause\n');
    buffer.writeln('• **Recommended Next Step:** $nextStep\n');

    if (dataMayRemain) {
      buffer.writeln('⚠️ **Data Remanence Warning:** Because the operation was interrupted or failed after starting, data may remain or be partially wiped on the device. Do not treat the drive as sanitized.');
    } else {
      buffer.writeln('ℹ️ **Safety Note:** The operation was halted before destructive writes began. Existing drive contents remain unchanged.');
    }

    return buffer.toString().trim();
  }
}
