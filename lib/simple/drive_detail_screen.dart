import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../models/device_profile.dart';
import '../models/sanitization_job.dart';
import '../models/sanitization_support_level.dart';
import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';
import 'certificate_dialog.dart';
import 'confirm_wipe_dialog.dart';
import 'error_messages.dart';

class DriveDetailScreen extends StatelessWidget {
  final String deviceId;

  const DriveDetailScreen({super.key, required this.deviceId});

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final isSimulated = !controller.isRealMode;

    // Find device by stableId
    final device = controller.devices.cast<DeviceProfile?>().firstWhere(
          (d) => d!.stableId == deviceId,
          orElse: () => null,
        );

    if (device == null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.usb_off, size: 48, color: AppTheme.textMuted),
              const SizedBox(height: 12),
              const Text('Drive not found',
                  style: TextStyle(color: AppTheme.textMuted, fontSize: 16)),
              const SizedBox(height: 4),
              const Text('It may have been unplugged.',
                  style: TextStyle(color: AppTheme.textMuted, fontSize: 13)),
              const SizedBox(height: 16),
              ElevatedButton.icon(
                onPressed: () => context.go('/'),
                icon: const Icon(Icons.arrow_back),
                label: const Text('All Drives'),
              ),
            ],
          ),
        ),
      );
    }

    // Item 4: Refuse direct navigation to protected system drive
    if (device.isSystemDisk) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.shield, size: 56, color: AppTheme.accentRose),
              const SizedBox(height: 16),
              const Text(
                'Protected System Drive',
                style: TextStyle(
                  color: AppTheme.accentRose,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                '${device.name} (${device.id}) is a protected system drive containing active operating system partitions. Direct wiping is refused.',
                textAlign: TextAlign.center,
                style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13),
              ),
              const SizedBox(height: 20),
              ElevatedButton.icon(
                onPressed: () => context.go('/'),
                icon: const Icon(Icons.arrow_back),
                label: const Text('Back to Drives'),
              ),
            ],
          ),
        ),
      );
    }

    // Refuse direct navigation to unsupported drive types
    if (device.simpleDisabledReason != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.block, size: 56, color: AppTheme.textMuted),
              const SizedBox(height: 16),
              const Text(
                'Unsupported Drive',
                style: TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                '${device.name}: ${device.simpleDisabledReason}',
                textAlign: TextAlign.center,
                style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13),
              ),
              const SizedBox(height: 20),
              ElevatedButton.icon(
                onPressed: () => context.go('/'),
                icon: const Icon(Icons.arrow_back),
                label: const Text('Back to Drives'),
              ),
            ],
          ),
        ),
      );
    }

    final job = controller.currentJob;
    final isJobForThisDevice =
        job != null && job.device.stableId == device.stableId;
    final isRunning = controller.isJobRunning && isJobForThisDevice;
    final isVerifying = isJobForThisDevice && job.status == JobStatus.verifying;
    final isFinished = isJobForThisDevice &&
        (job.status == JobStatus.completed || job.status == JobStatus.failed);
    final isCompleted =
        isJobForThisDevice && job.status == JobStatus.completed;
    final isFailed = isJobForThisDevice && job.status == JobStatus.failed;
    final wipeCompleted = job?.wipeCompleted ?? false;
    final isWipeFailed = isFailed && !wipeCompleted;

    final supportLevel = computeSupportLevel(device);
    final isFlash = device.mediaTechnology == MediaTechnology.flash;
    final isUnknown = device.mediaTechnology == MediaTechnology.unknown;
    final cert = controller.completedCertificate;
    final hasCert = cert != null && isFinished;
    final verifyPassed = cert?.evidence.verifiedPassed ?? false;

    // Determine badge text
    String? badgeText;
    Color? badgeColor;
    if (isCompleted && hasCert) {
      badgeText = SimpleErrorMessages.wipeBadgeText(
        sanitizationCategory: cert.sanitizationCategory,
        isFlashMedia: isFlash,
        verificationPassed: verifyPassed,
      );
      badgeColor =
          verifyPassed ? AppTheme.simpleSuccess : AppTheme.simpleDestructive;
    } else if (isFailed) {
      badgeText = isWipeFailed ? 'Wipe failed' : 'Verification failed';
      badgeColor = AppTheme.simpleDestructive;
    }

    return PopScope(
      canPop: !isRunning,
      onPopInvokedWithResult: (didPop, result) {
        if (!didPop && isRunning) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Cannot leave while a wipe is in progress!'),
              backgroundColor: AppTheme.accentRose,
            ),
          );
        }
      },
      child: Column(
        children: [
          // SIMULATION banner on Screen 2
          if (isSimulated)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                color: AppTheme.accentGold.withValues(alpha: 0.15),
                border: Border(
                  bottom: BorderSide(
                    color: AppTheme.accentGold.withValues(alpha: 0.5),
                    width: 1.5,
                  ),
                ),
              ),
              child: const Row(
                children: [
                  Icon(Icons.science, color: AppTheme.accentGold, size: 18),
                  SizedBox(width: 8),
                  Text(
                    'SIMULATION MODE — No real drives will be modified',
                    style: TextStyle(
                      color: AppTheme.accentGold,
                      fontWeight: FontWeight.bold,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),

          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Back link
                  TextButton.icon(
                    onPressed: isRunning ? null : () => context.go('/'),
                    icon: const Icon(Icons.arrow_back, size: 16),
                    label: const Text('All drives', style: TextStyle(fontSize: 13)),
                  ),
                  const SizedBox(height: 8),

                  // Device info card
                  Container(
                    padding: const EdgeInsets.all(18),
                    decoration: BoxDecoration(
                      color: AppTheme.surfaceCard,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: AppTheme.surfaceBorder),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.all(10),
                              decoration: BoxDecoration(
                                color: AppTheme.simplePrimary.withValues(alpha: 0.1),
                                borderRadius: BorderRadius.circular(10),
                              ),
                              child: Icon(
                                _driveIcon(device.driveType),
                                color: AppTheme.simplePrimary,
                                size: 28,
                              ),
                            ),
                            const SizedBox(width: 14),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(device.name,
                                      style: const TextStyle(
                                          fontWeight: FontWeight.bold, fontSize: 16)),
                                  const SizedBox(height: 2),
                                  Text(
                                    '${device.formattedCapacity} • ${device.busType} • S/N: ${device.serialNumber}',
                                    style: const TextStyle(
                                        color: AppTheme.textSecondary, fontSize: 12),
                                  ),
                                ],
                              ),
                            ),
                            // DriveType + support chips
                            Column(
                              crossAxisAlignment: CrossAxisAlignment.end,
                              children: [
                                Container(
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 8, vertical: 3),
                                  decoration: BoxDecoration(
                                    color:
                                        AppTheme.simplePrimary.withValues(alpha: 0.1),
                                    borderRadius: BorderRadius.circular(6),
                                  ),
                                  child: Text(device.driveType.label,
                                      style: const TextStyle(
                                          color: AppTheme.simplePrimary,
                                          fontSize: 10,
                                          fontWeight: FontWeight.bold)),
                                ),
                                const SizedBox(height: 4),
                                Container(
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 8, vertical: 3),
                                  decoration: BoxDecoration(
                                    color: supportLevel.badgeColor
                                        .withValues(alpha: 0.1),
                                    borderRadius: BorderRadius.circular(6),
                                  ),
                                  child: Text(supportLevel.badgeLabel,
                                      style: TextStyle(
                                          color: supportLevel.badgeColor,
                                          fontSize: 10,
                                          fontWeight: FontWeight.bold)),
                                ),
                              ],
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),

                        // Method + path
                        _metaRow('Path:', device.id.startsWith('real_')
                            ? '/dev/${device.id.substring(5)}'
                            : '/dev/sdb (Simulated)'),
                        const SizedBox(height: 4),
                        _metaRow('Method:', 'Decided at confirmation'),

                        // Clear-only caveat (Flash vs Unknown)
                        if (supportLevel == SanitizationSupportLevel.clearOnly) ...[
                          if (isFlash) ...[
                            const SizedBox(height: 8),
                            Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: AppTheme.accentGold.withValues(alpha: 0.08),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: const Row(
                                children: [
                                  Icon(Icons.info_outline,
                                      color: AppTheme.accentGold, size: 14),
                                  SizedBox(width: 6),
                                  Expanded(
                                    child: Text(
                                      'Flash media: Clear level only. Overwrite cannot reach remapped blocks.',
                                      style: TextStyle(
                                          color: AppTheme.accentGold, fontSize: 11),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ] else if (isUnknown) ...[
                            const SizedBox(height: 8),
                            Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: AppTheme.accentGold.withValues(alpha: 0.08),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: const Row(
                                children: [
                                  Icon(Icons.info_outline,
                                      color: AppTheme.accentGold, size: 14),
                                  SizedBox(width: 6),
                                  Expanded(
                                    child: Text(
                                      'Clear level only. Logical overwrite cannot guarantee firmware-level purge.',
                                      style: TextStyle(
                                          color: AppTheme.accentGold, fontSize: 11),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ],

                        // Badge (post-wipe)
                        if (badgeText != null) ...[
                          const SizedBox(height: 12),
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 14, vertical: 8),
                            decoration: BoxDecoration(
                              color: badgeColor!.withValues(alpha: 0.12),
                              borderRadius: BorderRadius.circular(20),
                              border: Border.all(color: badgeColor, width: 1.5),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  verifyPassed && isCompleted
                                      ? Icons.verified
                                      : Icons.gpp_bad,
                                  color: badgeColor,
                                  size: 18,
                                ),
                                const SizedBox(width: 6),
                                Text(badgeText,
                                    style: TextStyle(
                                        color: badgeColor,
                                        fontWeight: FontWeight.bold,
                                        fontSize: 13)),
                              ],
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                  const SizedBox(height: 20),

                  // Progress area (inline, not separate screen)
                  if (isRunning && isJobForThisDevice) ...[
                    _buildProgressSection(context, controller, job, isSimulated),
                    const SizedBox(height: 20),
                  ],

                  // Error message
                  if (isFailed && isJobForThisDevice) ...[
                    Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: AppTheme.accentRose.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                            color: AppTheme.accentRose.withValues(alpha: 0.3)),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.error_outline,
                              color: AppTheme.accentRose, size: 20),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              SimpleErrorMessages.fromError(
                                  job.currentStageDescription),
                              style: const TextStyle(
                                  color: AppTheme.accentRose, fontSize: 13),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 20),
                  ],

                  // 3 action buttons
                  _buildActionButtons(
                    context: context,
                    controller: controller,
                    device: device,
                    isRunning: isRunning,
                    isVerifying: isVerifying,
                    isFinished: isFinished,
                    isCompleted: isCompleted,
                    isFailed: isFailed,
                    wipeCompleted: wipeCompleted,
                    hasCert: hasCert,
                    verifyPassed: verifyPassed,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildProgressSection(
    BuildContext context,
    SanitizationController controller,
    SanitizationJob job,
    bool isSimulated,
  ) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppTheme.surfaceCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Column(
        children: [
          // SIMULATION chip inside progress container
          if (isSimulated) ...[
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: AppTheme.accentGold.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.4)),
              ),
              child: const Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.science, color: AppTheme.accentGold, size: 14),
                  SizedBox(width: 6),
                  Text(
                    'SIMULATION MODE',
                    style: TextStyle(
                      color: AppTheme.accentGold,
                      fontSize: 11,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
          ],

          // Circular progress
          SizedBox(
            width: 120,
            height: 120,
            child: Stack(
              alignment: Alignment.center,
              children: [
                CircularProgressIndicator(
                  value: job.progress,
                  strokeWidth: 10,
                  backgroundColor: AppTheme.surfaceBorder,
                  valueColor: const AlwaysStoppedAnimation<Color>(
                      AppTheme.simplePrimary),
                ),
                Text(
                  job.progress != null
                      ? '${(job.progress! * 100).toInt()}%'
                      : '...',
                  style: const TextStyle(
                    fontSize: 28,
                    fontWeight: FontWeight.bold,
                    color: AppTheme.textPrimary,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          Text(
            job.currentStageDescription,
            textAlign: TextAlign.center,
            style: const TextStyle(
              fontSize: 13,
              fontWeight: FontWeight.w600,
              color: AppTheme.simplePrimary,
            ),
          ),
          const SizedBox(height: 4),
          const Text(
            'Do not unplug the drive',
            style: TextStyle(color: AppTheme.accentGold, fontSize: 11),
          ),
          const SizedBox(height: 14),

          // Cancel Wipe / Waiting Notice / Force Stop button
          if (controller.showForceStop) ...[
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: AppTheme.accentGold.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.4)),
              ),
              child: const Text(
                'waiting for the drive to finish its current write',
                style: TextStyle(color: AppTheme.accentGold, fontSize: 12, fontWeight: FontWeight.w500),
                textAlign: TextAlign.center,
              ),
            ),
            const SizedBox(height: 10),
            ElevatedButton.icon(
              icon: const Icon(Icons.dangerous_outlined, size: 16),
              label: const Text('Force stop', style: TextStyle(fontSize: 12)),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.accentRose,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              ),
              onPressed: () => _handleForceStop(context, controller),
            ),
          ] else if (controller.isCancelling) ...[
            const Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(strokeWidth: 2, color: AppTheme.accentRose),
                ),
                SizedBox(width: 8),
                Text(
                  'Cancelling... waiting for write to sync',
                  style: TextStyle(color: AppTheme.accentRose, fontSize: 12),
                ),
              ],
            ),
          ] else if (controller.canCancelJob)
            OutlinedButton.icon(
              icon: const Icon(Icons.cancel_outlined, size: 16),
              label: const Text('Cancel Wipe', style: TextStyle(fontSize: 12)),
              style: OutlinedButton.styleFrom(
                foregroundColor: AppTheme.accentRose,
                side: BorderSide(color: AppTheme.accentRose.withValues(alpha: 0.5)),
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              ),
              onPressed: () => _handleCancel(context, controller),
            )
          else
            const Text(
              'Hardware firmware wipe in progress — cannot be cancelled safely',
              style: TextStyle(color: AppTheme.textMuted, fontSize: 11),
            ),
        ],
      ),
    );
  }

  Future<void> _handleForceStop(BuildContext context, SanitizationController controller) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.surfaceDark,
        title: const Row(
          children: [
            Icon(Icons.dangerous_rounded, color: AppTheme.accentRose),
            SizedBox(width: 8),
            Text('Force Stop Process?'),
          ],
        ),
        content: const Text(
          'Warning: Force stopping terminates the zt_engine process immediately (SIGKILL).\n\n'
          'Drive write buffers will not be flushed and sectors may be left in an inconsistent state.\n\n'
          'Are you sure you want to force terminate?',
          style: TextStyle(color: AppTheme.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Wait for Drive'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.accentRose),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Force Stop Now'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await controller.forceStopCurrentJob();
    }
  }

  Future<void> _handleCancel(BuildContext context, SanitizationController controller) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.surfaceDark,
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: AppTheme.accentGold),
            SizedBox(width: 8),
            Text('Cancel Sanitization?'),
          ],
        ),
        content: const Text(
          'Warning: Cancelling an active overwrite will leave the drive partially wiped. '
          'Existing filesystems and partition tables may already be destroyed.\n\n'
          'Are you sure you want to stop?',
          style: TextStyle(color: AppTheme.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Continue Wipe'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.accentRose),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Stop & Mark Partially Wiped'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await controller.cancelCurrentJob();
    }
  }

  Widget _buildActionButtons({
    required BuildContext context,
    required SanitizationController controller,
    required DeviceProfile device,
    required bool isRunning,
    required bool isVerifying,
    required bool isFinished,
    required bool isCompleted,
    required bool isFailed,
    required bool wipeCompleted,
    required bool hasCert,
    required bool verifyPassed,
  }) {
    // State machine for button enable/disable
    final canWipe = !isRunning && (!isFinished || isFailed);
    // Verify is enabled ONLY when the wipe itself completed
    final canVerify = !isRunning && (isCompleted || (isFailed && wipeCompleted));
    final canCert = hasCert;

    return Column(
      children: [
        // Wipe button
        SizedBox(
          width: double.infinity,
          child: ElevatedButton.icon(
            icon: Icon(
              isFailed ? Icons.refresh : Icons.delete_forever,
              size: 22,
            ),
            label: Text(
              isRunning
                  ? (isVerifying ? 'Verifying...' : 'Wiping...')
                  : (isFailed ? 'Retry Wipe' : 'Secure Wipe'),
              style: const TextStyle(
                  fontWeight: FontWeight.bold, fontSize: 15),
            ),
            style: ElevatedButton.styleFrom(
              backgroundColor: canWipe
                  ? AppTheme.simpleDestructive
                  : AppTheme.surfaceBorder,
              foregroundColor:
                  canWipe ? Colors.white : AppTheme.textMuted,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12)),
            ),
            onPressed: canWipe
                ? () => _handleWipe(context, controller, device)
                : null,
          ),
        ),
        const SizedBox(height: 10),

        Row(
          children: [
            // Verify button
            Expanded(
              child: OutlinedButton.icon(
                icon: const Icon(Icons.verified_user_outlined, size: 18),
                label: const Text('Verify'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: canVerify
                      ? AppTheme.simplePrimary
                      : AppTheme.textMuted,
                  side: BorderSide(
                    color: canVerify
                        ? AppTheme.simplePrimary
                        : AppTheme.surfaceBorder,
                  ),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12)),
                ),
                onPressed: canVerify
                    ? () => context.go('/advanced/verification')
                    : null,
              ),
            ),
            const SizedBox(width: 10),

            // Certificate / Failure report button
            Expanded(
              child: OutlinedButton.icon(
                icon: Icon(
                  canCert
                      ? (verifyPassed
                          ? Icons.description
                          : Icons.report_problem)
                      : Icons.description_outlined,
                  size: 18,
                ),
                label: Text(
                  canCert && !verifyPassed
                      ? 'Failure Report'
                      : 'Certificate',
                ),
                style: OutlinedButton.styleFrom(
                  foregroundColor: canCert
                      ? (verifyPassed
                          ? AppTheme.simpleSuccess
                          : AppTheme.accentGold)
                      : AppTheme.textMuted,
                  side: BorderSide(
                    color: canCert
                        ? (verifyPassed
                            ? AppTheme.simpleSuccess
                            : AppTheme.accentGold)
                        : AppTheme.surfaceBorder,
                  ),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12)),
                ),
                onPressed: canCert
                    ? () => SimpleCertificateDialog.show(context)
                    : null,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Future<void> _handleWipe(
    BuildContext context,
    SanitizationController controller,
    DeviceProfile device,
  ) async {
    // Re-check device still present
    final stillPresent = controller.devices.any((d) => d.stableId == device.stableId);
    if (!stillPresent) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Drive was unplugged. Reconnect and try again.'),
            backgroundColor: AppTheme.accentRose,
          ),
        );
      }
      return;
    }

    // Re-check serial + size match (pinned at selection)
    final currentDevice = controller.devices.firstWhere(
      (d) => d.stableId == device.stableId,
    );
    if (currentDevice.serialNumber != device.serialNumber ||
        currentDevice.capacityBytes != device.capacityBytes) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text(
                'Drive identity changed. A different device may have been connected.'),
            backgroundColor: AppTheme.accentRose,
          ),
        );
      }
      return;
    }

    if (!context.mounted) return;
    final result = await SimpleConfirmDialog.show(context, device);
    if (result == null) return;

    if (!context.mounted) return;
    await controller.startSimpleWipe(
      device,
      result.intent,
      overrideMethod: result.overrideMethod,
    );
  }

  Widget _metaRow(String label, String value) {
    return Row(
      children: [
        SizedBox(
          width: 80,
          child: Text(label,
              style: const TextStyle(
                  fontSize: 12,
                  color: AppTheme.textMuted,
                  fontWeight: FontWeight.w600)),
        ),
        Expanded(
          child: Text(value,
              style: const TextStyle(
                  fontSize: 12, color: AppTheme.textSecondary)),
        ),
      ],
    );
  }

  IconData _driveIcon(DriveType type) {
    switch (type) {
      case DriveType.usb:
        return Icons.usb;
      case DriveType.sd:
        return Icons.sd_card;
      case DriveType.hdd:
        return Icons.storage;
      case DriveType.ssd:
        return Icons.memory;
      case DriveType.nvme:
        return Icons.developer_board;
      case DriveType.unknown:
        return Icons.help_outline;
    }
  }
}
