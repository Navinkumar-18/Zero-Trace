import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../models/device_profile.dart';
import '../models/partition_info.dart';
import '../models/sanitization_job.dart';
import '../models/sanitization_support_level.dart';
import '../models/storage_capability.dart';
import '../services/sanitization_controller.dart';
import '../services/platform_backend.dart';
import '../widgets/theme.dart';
import 'certificate_dialog.dart';
import 'confirm_wipe_dialog.dart';
import 'error_messages.dart';
import 'filesystem_recreation_dialog.dart';

class DriveDetailScreen extends StatelessWidget {
  final String deviceId;

  const DriveDetailScreen({super.key, required this.deviceId});

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final isSimulated = !controller.isRealMode;

    // Find device by stableId or id
    final device = controller.devices.cast<DeviceProfile?>().firstWhere(
      (d) => d!.stableId == deviceId || d.id == deviceId,
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
              const Text(
                'Drive not found',
                style: TextStyle(color: AppTheme.textMuted, fontSize: 16),
              ),
              const SizedBox(height: 4),
              const Text(
                'It may have been unplugged.',
                style: TextStyle(color: AppTheme.textMuted, fontSize: 13),
              ),
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
                style: const TextStyle(
                  color: AppTheme.textSecondary,
                  fontSize: 13,
                ),
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
                style: const TextStyle(
                  color: AppTheme.textSecondary,
                  fontSize: 13,
                ),
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
    final isFinished =
        isJobForThisDevice &&
        (job.status == JobStatus.completed || job.status == JobStatus.failed);
    final isCompleted = isJobForThisDevice && job.status == JobStatus.completed;
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
      badgeColor = verifyPassed
          ? AppTheme.simpleSuccess
          : AppTheme.simpleDestructive;
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
                    label: const Text(
                      'All drives',
                      style: TextStyle(fontSize: 13),
                    ),
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
                                color: AppTheme.simplePrimary.withValues(
                                  alpha: 0.1,
                                ),
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
                                  Text(
                                    device.name,
                                    style: const TextStyle(
                                      fontWeight: FontWeight.bold,
                                      fontSize: 16,
                                    ),
                                  ),
                                  const SizedBox(height: 2),
                                  Text(
                                    '${device.formattedCapacity} • ${device.busType} • S/N: ${device.serialNumber}',
                                    style: const TextStyle(
                                      color: AppTheme.textSecondary,
                                      fontSize: 12,
                                    ),
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
                                    horizontal: 8,
                                    vertical: 3,
                                  ),
                                  decoration: BoxDecoration(
                                    color: AppTheme.simplePrimary.withValues(
                                      alpha: 0.1,
                                    ),
                                    borderRadius: BorderRadius.circular(6),
                                  ),
                                  child: Text(
                                    device.driveType.label,
                                    style: const TextStyle(
                                      color: AppTheme.simplePrimary,
                                      fontSize: 10,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ),
                                const SizedBox(height: 4),
                                Container(
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 8,
                                    vertical: 3,
                                  ),
                                  decoration: BoxDecoration(
                                    color: supportLevel.badgeColor.withValues(
                                      alpha: 0.1,
                                    ),
                                    borderRadius: BorderRadius.circular(6),
                                  ),
                                  child: Text(
                                    supportLevel.badgeLabel,
                                    style: TextStyle(
                                      color: supportLevel.badgeColor,
                                      fontSize: 10,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),

                        // Method + path
                        _metaRow(
                          'Path:',
                          device.id.startsWith('real_')
                              ? '/dev/${device.id.substring(5)}'
                              : '/dev/sdb (Simulated)',
                        ),
                        const SizedBox(height: 4),
                        _metaRow('Method:', 'Decided at confirmation'),

                        // Clear-only caveat (Flash vs Unknown)
                        if (supportLevel ==
                            SanitizationSupportLevel.clearOnly) ...[
                          if (isFlash) ...[
                            const SizedBox(height: 8),
                            Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: AppTheme.accentGold.withValues(
                                  alpha: 0.08,
                                ),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: const Row(
                                children: [
                                  Icon(
                                    Icons.info_outline,
                                    color: AppTheme.accentGold,
                                    size: 14,
                                  ),
                                  SizedBox(width: 6),
                                  Expanded(
                                    child: Text(
                                      'Flash media: Clear level only. Overwrite cannot reach remapped blocks.',
                                      style: TextStyle(
                                        color: AppTheme.accentGold,
                                        fontSize: 11,
                                      ),
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
                                color: AppTheme.accentGold.withValues(
                                  alpha: 0.08,
                                ),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: const Row(
                                children: [
                                  Icon(
                                    Icons.info_outline,
                                    color: AppTheme.accentGold,
                                    size: 14,
                                  ),
                                  SizedBox(width: 6),
                                  Expanded(
                                    child: Text(
                                      'Clear level only. Logical overwrite cannot guarantee firmware-level purge.',
                                      style: TextStyle(
                                        color: AppTheme.accentGold,
                                        fontSize: 11,
                                      ),
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
                              horizontal: 14,
                              vertical: 8,
                            ),
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
                                Text(
                                  badgeText,
                                  style: TextStyle(
                                    color: badgeColor,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 13,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                  const SizedBox(height: 20),

                  // A4: partition chooser (only when the drive has partitions
                  // and no job is running for it)
                  if (device.hasPartitions &&
                      !(isRunning && isJobForThisDevice)) ...[
                    _PartitionChooserSection(
                      device: device,
                      isSimulated: isSimulated,
                    ),
                    const SizedBox(height: 20),
                  ],

                  // Progress area (inline, not separate screen)
                  if (isRunning && isJobForThisDevice) ...[
                    _buildProgressSection(
                      context,
                      controller,
                      job,
                      isSimulated,
                    ),
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
                          color: AppTheme.accentRose.withValues(alpha: 0.3),
                        ),
                      ),
                      child: Row(
                        children: [
                          const Icon(
                            Icons.error_outline,
                            color: AppTheme.accentRose,
                            size: 20,
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              SimpleErrorMessages.fromError(
                                job.currentStageDescription,
                              ),
                              style: const TextStyle(
                                color: AppTheme.accentRose,
                                fontSize: 13,
                              ),
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
                  const SizedBox(height: 20),

                  // Phase F: optional post-wipe filesystem recreation. Shown
                  // only after this job's wipe AND verification succeeded.
                  if (isJobForThisDevice &&
                      controller.filesystemRecreation != null) ...[
                    _buildFilesystemRecreationRecord(controller),
                    const SizedBox(height: 20),
                  ] else if (isJobForThisDevice &&
                      controller.showFilesystemRecreationPrompt) ...[
                    _buildFilesystemRecreationPrompt(context, controller),
                    const SizedBox(height: 20),
                  ],
                  const SizedBox(height: 4),

                  // Read-only Drive Details & Hardware Capability Matrix
                  _buildDriveDetailsSection(device),
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
                border: Border.all(
                  color: AppTheme.accentGold.withValues(alpha: 0.4),
                ),
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
                    AppTheme.simplePrimary,
                  ),
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
                border: Border.all(
                  color: AppTheme.accentGold.withValues(alpha: 0.4),
                ),
              ),
              child: const Text(
                'waiting for the drive to finish its current write',
                style: TextStyle(
                  color: AppTheme.accentGold,
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
                textAlign: TextAlign.center,
              ),
            ),
            const SizedBox(height: 10),
            ElevatedButton.icon(
              icon: const Icon(Icons.dangerous_outlined, size: 16),
              label: const Text('Force stop', style: TextStyle(fontSize: 12)),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.accentRose,
                padding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 8,
                ),
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
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: AppTheme.accentRose,
                  ),
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
                side: BorderSide(
                  color: AppTheme.accentRose.withValues(alpha: 0.5),
                ),
                padding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 8,
                ),
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

  Future<void> _handleForceStop(
    BuildContext context,
    SanitizationController controller,
  ) async {
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
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.accentRose,
            ),
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

  Future<void> _handleCancel(
    BuildContext context,
    SanitizationController controller,
  ) async {
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
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.accentRose,
            ),
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

  /// Phase F: persistent prompt card. The format action itself is OFF by
  /// default inside the dialog; this card never enables it implicitly.
  Widget _buildFilesystemRecreationPrompt(
    BuildContext context,
    SanitizationController controller,
  ) {
    final defaults = controller.filesystemRecreationDefaults;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.surfaceCard,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(
                Icons.storage_rounded,
                color: AppTheme.simplePrimary,
                size: 20,
              ),
              SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Recreate filesystem?',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 15,
                    color: AppTheme.textPrimary,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'Optional. The wipe result is already verified and is not affected '
            'by formatting — this only makes the drive usable again.',
            style: TextStyle(color: AppTheme.textSecondary, fontSize: 12),
          ),
          if (defaults != null) ...[
            const SizedBox(height: 6),
            Text(
              'Defaults from the original volume: '
              '${defaults.fsType.toUpperCase()} • label ${defaults.label}',
              style: const TextStyle(color: AppTheme.textMuted, fontSize: 11),
            ),
          ],
          if (controller.filesystemRecreationError != null) ...[
            const SizedBox(height: 8),
            Text(
              'Format failed: ${controller.filesystemRecreationError}',
              key: const Key('filesystem-recreate-card-error'),
              style: const TextStyle(color: AppTheme.accentRose, fontSize: 12),
            ),
          ],
          const SizedBox(height: 10),
          Row(
            children: [
              ElevatedButton.icon(
                key: const Key('filesystem-recreate-open'),
                onPressed: () =>
                    FilesystemRecreationDialog.show(context, controller),
                icon: const Icon(Icons.build_circle_outlined, size: 16),
                label: const Text(
                  'Choose filesystem...',
                  style: TextStyle(fontSize: 12),
                ),
              ),
              const SizedBox(width: 8),
              TextButton(
                onPressed: controller.dismissFilesystemRecreationPrompt,
                child: const Text('Not now', style: TextStyle(fontSize: 12)),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildFilesystemRecreationRecord(SanitizationController controller) {
    final record = controller.filesystemRecreation!;
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppTheme.simpleSuccess.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: AppTheme.simpleSuccess.withValues(alpha: 0.35),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(
                Icons.check_circle_outline,
                color: AppTheme.simpleSuccess,
                size: 18,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Filesystem recreated: ${record.fsType.toUpperCase()} '
                  '(${record.tool})',
                  style: const TextStyle(
                    color: AppTheme.simpleSuccess,
                    fontWeight: FontWeight.bold,
                    fontSize: 13,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            'Label: ${record.label.isEmpty ? '(none)' : record.label}'
            '${record.partitionTableCreated ? ' • new ${record.partitionTableType?.toUpperCase() ?? 'partition table'}' : ''}',
            style: const TextStyle(color: AppTheme.textSecondary, fontSize: 12),
          ),
          const SizedBox(height: 2),
          Text(
            'Format time: ${record.time} • sanitization verified before format: '
            '${record.sanitizationVerifiedBeforeFormat ? 'yes' : 'no'}',
            style: const TextStyle(color: AppTheme.textMuted, fontSize: 11),
          ),
        ],
      ),
    );
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
    // C6: platform capability gate — unsupported platforms disable the
    // engine-dependent actions and show the reason inline (the action is
    // never hidden silently).
    final platform = currentPlatformBackend();
    final platformSupported = platform.isSupported;

    // State machine for button enable/disable
    final canWipe =
        platformSupported && !isRunning && (!isFinished || isFailed);
    // Verify is enabled ONLY when the wipe itself completed
    final canVerify =
        platformSupported &&
        !isRunning &&
        (isCompleted || (isFailed && wipeCompleted));
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
              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15),
            ),
            style: ElevatedButton.styleFrom(
              backgroundColor: canWipe
                  ? AppTheme.simpleDestructive
                  : AppTheme.surfaceBorder,
              foregroundColor: canWipe ? Colors.white : AppTheme.textMuted,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            onPressed: canWipe
                ? () => _handleWipe(context, controller, device)
                : null,
          ),
        ),
        if (!platformSupported) ...[
          const SizedBox(height: 8),
          Text(
            platform.unsupportedReason,
            textAlign: TextAlign.center,
            style: const TextStyle(color: AppTheme.textMuted, fontSize: 12),
          ),
        ],
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
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                onPressed: canVerify
                    ? () => _handleVerify(context, controller)
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
                  canCert && !verifyPassed ? 'Failure Report' : 'Certificate',
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
                    borderRadius: BorderRadius.circular(12),
                  ),
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

  Future<void> _handleVerify(
    BuildContext context,
    SanitizationController controller,
  ) async {
    try {
      await controller.verifyCurrentJob();
    } catch (e) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Verification failed: $e'),
          backgroundColor: AppTheme.accentRose,
        ),
      );
    }
  }

  Future<void> _handleWipe(
    BuildContext context,
    SanitizationController controller,
    DeviceProfile device,
  ) async {
    // Re-check device still present
    final stillPresent = controller.devices.any(
      (d) => d.stableId == device.stableId,
    );
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
              'Drive identity changed. A different device may have been connected.',
            ),
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
      authorization: result.authorization,
      overrideMethod: result.overrideMethod,
    );
  }

  Widget _buildDriveDetailsSection(DeviceProfile device) {
    final caps = DeviceCapabilities.fromDevice(device);
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppTheme.surfaceCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.memory, color: AppTheme.simplePrimary, size: 20),
              SizedBox(width: 8),
              Text(
                'Drive Details & Hardware Capabilities',
                style: TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.bold,
                  color: AppTheme.textPrimary,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          const Divider(color: AppTheme.surfaceBorder, height: 1),
          const SizedBox(height: 12),
          _metaRow(
            'Bus Interface:',
            device.busType.isNotEmpty ? device.busType : 'Unknown',
          ),
          const SizedBox(height: 6),
          _metaRow(
            'Rotational:',
            device.isRotational ? 'Yes (HDD)' : 'No (Solid State / Flash)',
          ),
          const SizedBox(height: 6),
          if (device.rotationalRpm != null && device.rotationalRpm! > 0) ...[
            _metaRow('RPM:', '${device.rotationalRpm}'),
            const SizedBox(height: 6),
          ],
          _metaRow(
            'HPA / DCO:',
            device.hpaDcoPresent ? 'Detected (Hidden Areas)' : 'None',
          ),
          const SizedBox(height: 14),
          const Text(
            'HARDWARE SANITIZATION MATRIX',
            style: TextStyle(
              fontSize: 10,
              fontWeight: FontWeight.bold,
              letterSpacing: 0.8,
              color: AppTheme.textMuted,
            ),
          ),
          const SizedBox(height: 8),
          ...caps.capabilities.map((cap) {
            Color statusColor = AppTheme.textMuted;
            switch (cap.status) {
              case CapabilityStatus.available:
                statusColor = AppTheme.simpleSuccess;
                break;
              // P1: "not supported on this device" is informational, not a
              // failure — red is reserved for real errors. The reason text
              // (cap.description) stays visible below every row.
              case CapabilityStatus.notAvailable:
                statusColor = AppTheme.textMuted;
                break;
              case CapabilityStatus.unknown:
                statusColor = AppTheme.accentOrange;
                break;
              case CapabilityStatus.notApplicable:
                statusColor = AppTheme.textMuted;
                break;
            }
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Row(
                children: [
                  Text(
                    cap.status.icon,
                    style: TextStyle(color: statusColor, fontSize: 14),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          cap.name,
                          style: const TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                            color: AppTheme.textPrimary,
                          ),
                        ),
                        Text(
                          cap.description,
                          style: const TextStyle(
                            fontSize: 10,
                            color: AppTheme.textMuted,
                          ),
                        ),
                      ],
                    ),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: statusColor.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Text(
                      cap.status.displayName,
                      style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                        color: statusColor,
                      ),
                    ),
                  ),
                ],
              ),
            );
          }),
        ],
      ),
    );
  }

  Widget _metaRow(String label, String value) {
    return Row(
      children: [
        SizedBox(
          width: 80,
          child: Text(
            label,
            style: const TextStyle(
              fontSize: 12,
              color: AppTheme.textMuted,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: const TextStyle(fontSize: 12, color: AppTheme.textSecondary),
          ),
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

/// A4: partition chooser.
///
/// Shows every partition of the drive as a selectable row (label, size,
/// filesystem, mountpoint) in a C:/D: style list. Multi-select is allowed;
/// "select all" switches to the whole-device path. System/unsafe partitions
/// are shown disabled with the reason. Selecting every partition of a
/// removable device offers "Wipe entire device" instead.
class _PartitionChooserSection extends StatelessWidget {
  final DeviceProfile device;
  final bool isSimulated;

  const _PartitionChooserSection({
    required this.device,
    required this.isSimulated,
  });

  /// Reason a partition cannot be selected, or null when selectable.
  String? _unsafeReason(PartitionInfo p) {
    if (p.isActiveSwap) return 'Active swap partition';
    if (p.isSystemPartition) return 'Holds system path (${p.mountPoint})';
    if (p.isProtected) {
      return p.isMounted
          ? 'Protected mount (${p.mountPoint})'
          : 'Protected partition (live media or system)';
    }
    if (p.isMounted && !p.isMountAllowed) {
      return 'Mounted at ${p.mountPoint} — unmount first';
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final selected = controller.selectedPartitions;
    final selectedNames = selected.map((p) => p.name).toSet();

    final selectable = device.partitions
        .where((p) => _unsafeReason(p) == null)
        .toList();
    final allSelected =
        selectable.isNotEmpty &&
        selectable.every((p) => selectedNames.contains(p.name));
    final allPartitionsSelected =
        selectable.length == device.partitions.length && allSelected;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppTheme.simplePrimary.withValues(alpha: 0.05),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: AppTheme.simplePrimary.withValues(alpha: 0.2),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(
                Icons.view_list,
                color: AppTheme.simplePrimary,
                size: 18,
              ),
              const SizedBox(width: 8),
              const Expanded(
                child: Text(
                  'Wipe specific partitions',
                  style: TextStyle(
                    color: AppTheme.simplePrimary,
                    fontWeight: FontWeight.bold,
                    fontSize: 14,
                  ),
                ),
              ),
              Text(
                isSimulated ? 'Simulated' : 'Real mode',
                style: const TextStyle(color: AppTheme.textMuted, fontSize: 10),
              ),
            ],
          ),
          const SizedBox(height: 4),
          const Text(
            'Leave everything unselected to wipe the entire drive.',
            style: TextStyle(color: AppTheme.textMuted, fontSize: 11),
          ),
          const SizedBox(height: 10),

          // "Select all" row → whole-device path
          InkWell(
            onTap: selectable.isEmpty
                ? null
                : () {
                    if (allSelected) {
                      controller.clearPartitionSelection();
                    } else {
                      for (final p in selectable) {
                        if (!selectedNames.contains(p.name)) {
                          controller.togglePartitionSelection(p);
                        }
                      }
                    }
                  },
            borderRadius: BorderRadius.circular(8),
            child: Container(
              padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 4),
              child: Row(
                children: [
                  Icon(
                    allSelected
                        ? Icons.check_box
                        : Icons.check_box_outline_blank,
                    color: allSelected
                        ? AppTheme.simplePrimary
                        : AppTheme.textMuted,
                    size: 20,
                  ),
                  const SizedBox(width: 10),
                  const Expanded(
                    child: Text(
                      'Select all partitions',
                      style: TextStyle(
                        fontWeight: FontWeight.w600,
                        fontSize: 13,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),

          const Divider(height: 12),

          // Partition rows
          for (final p in device.partitions) ...[
            _buildPartitionRow(context, controller, p, selectedNames),
            const SizedBox(height: 2),
          ],

          // B4: subset vs entire-disk scope. Selecting every partition wipes
          // only those ranges (partition table stays intact); switching to
          // "entire disk" destroys every partition AND the table. Offered for
          // removable AND internal non-system disks (a Windows laptop drive
          // included) — the A5 typed confirmation still gates execution.
          if (allPartitionsSelected &&
              (device.isRemovable || !device.isSystemDisk)) ...[
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: AppTheme.accentGold.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  const Icon(
                    Icons.warning_amber_rounded,
                    color: AppTheme.accentGold,
                    size: 16,
                  ),
                  const SizedBox(width: 8),
                  const Expanded(
                    child: Text(
                      'All partitions selected: this wipes only the selected '
                      'ranges — the partition table stays intact. Choose '
                      '"Wipe entire disk" to destroy every partition and the '
                      'table as well.',
                      style: TextStyle(
                        color: AppTheme.accentGold,
                        fontSize: 11,
                      ),
                    ),
                  ),
                  TextButton(
                    onPressed: () => controller.clearPartitionSelection(),
                    style: TextButton.styleFrom(
                      padding: const EdgeInsets.symmetric(horizontal: 8),
                      minimumSize: const Size(0, 32),
                    ),
                    child: const Text(
                      'Wipe entire disk',
                      style: TextStyle(fontSize: 11),
                    ),
                  ),
                ],
              ),
            ),
          ],

          // Selection summary
          if (selected.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(
              '${selected.length} partition(s) selected for wipe: '
              '${selected.map((p) => p.name).join(', ')}',
              style: const TextStyle(
                color: AppTheme.textSecondary,
                fontSize: 11,
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildPartitionRow(
    BuildContext context,
    SanitizationController controller,
    PartitionInfo p,
    Set<String> selectedNames,
  ) {
    final reason = _unsafeReason(p);
    final disabled = reason != null;
    final isSelected = !disabled && selectedNames.contains(p.name);

    // B1/P1: filesystem-based name ("exFAT volume", "NTFS volume", "Recovery",
    // "EFI System", …) — never assumes an OS from the filesystem and never
    // invents drive letters. "Windows volume" only appears for NTFS once the
    // read-only probe actually found a Windows installation; label/size/fs
    // stay visible in the detail line.
    final likelyWindows = controller.windowsProbeResults[p.devicePath];
    final probeError = controller.windowsProbeErrors[p.devicePath];
    final displayName = p.displayName(
      windowsInstallDetected: likelyWindows == true,
    );
    final title = likelyWindows == true
        ? '$displayName — likely C: (Windows installed)'
        : displayName;
    // B1 optional: offer the read-only Windows-install probe for Windows-ish,
    // not-disabled partitions in real mode only.
    final bool offerProbe =
        !isSimulated &&
        !disabled &&
        (p.role == 'windows_data' ||
            const {
              'ntfs',
              'exfat',
              'fat32',
              'fat16',
              'fat12',
              'bitlocker',
            }.contains(p.fsType?.toLowerCase()));

    return InkWell(
      onTap: disabled ? null : () => controller.togglePartitionSelection(p),
      borderRadius: BorderRadius.circular(8),
      child: Opacity(
        opacity: disabled ? 0.55 : 1.0,
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 4),
          decoration: BoxDecoration(
            color: isSelected
                ? AppTheme.simplePrimary.withValues(alpha: 0.08)
                : null,
            borderRadius: BorderRadius.circular(8),
          ),
          child: Row(
            children: [
              Icon(
                disabled
                    ? Icons.lock_outline
                    : (isSelected
                          ? Icons.check_box
                          : Icons.check_box_outline_blank),
                size: 18,
                color: disabled
                    ? AppTheme.textMuted
                    : (isSelected
                          ? AppTheme.simplePrimary
                          : AppTheme.textMuted),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: TextStyle(
                        fontWeight: isSelected
                            ? FontWeight.bold
                            : FontWeight.w500,
                        fontSize: 13,
                        decoration: disabled
                            ? TextDecoration.lineThrough
                            : null,
                      ),
                    ),
                    Text(
                      disabled
                          ? reason
                          : (probeError != null
                                ? '${p.detailLine} • $probeError'
                                : p.detailLine),
                      style: const TextStyle(
                        color: AppTheme.textMuted,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
              Text(
                p.name,
                style: const TextStyle(color: AppTheme.textMuted, fontSize: 11),
              ),
              if (offerProbe)
                IconButton(
                  tooltip: 'Probe for Windows (read-only)',
                  visualDensity: VisualDensity.compact,
                  iconSize: 18,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(
                    minWidth: 32,
                    minHeight: 32,
                  ),
                  icon: const Icon(
                    Icons.travel_explore,
                    size: 18,
                    color: AppTheme.textMuted,
                  ),
                  onPressed: () async {
                    final err = await controller.probeWindowsInstall(p);
                    if (!context.mounted) return;
                    final messenger = ScaffoldMessenger.maybeOf(context);
                    messenger?.showSnackBar(
                      SnackBar(
                        content: Text(
                          err ??
                              (controller.windowsProbeResults[p.devicePath] ==
                                      true
                                  ? '${p.devicePath}: likely C: (Windows installed)'
                                  : '${p.devicePath}: no Windows installation found'),
                        ),
                        duration: const Duration(seconds: 4),
                      ),
                    );
                  },
                ),
            ],
          ),
        ),
      ),
    );
  }
}
