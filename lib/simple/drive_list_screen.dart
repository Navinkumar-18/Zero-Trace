import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../models/device_profile.dart';
import '../models/sanitization_support_level.dart';
import '../services/orphaned_process_checker.dart';
import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';

class DriveListScreen extends StatefulWidget {
  const DriveListScreen({super.key});

  @override
  State<DriveListScreen> createState() => _DriveListScreenState();
}

class _DriveListScreenState extends State<DriveListScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) {
        context.read<SanitizationController>().resetShowInternalDrives();
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final allDevices = controller.devices;
    final showInternal = controller.showInternalDrives;
    final isSimulated = !controller.isRealMode;
    final orphanResult = controller.orphanResult;

    // Filter: removable first, then internal if toggled on
    final List<DeviceProfile> visibleDevices = allDevices.where((d) {
      if (d.isRemovable) return true;
      return showInternal;
    }).toList();

    // Sort: removable first, system drives last
    visibleDevices.sort((a, b) {
      if (a.isSystemDisk != b.isSystemDisk) {
        return a.isSystemDisk ? 1 : -1;
      }
      if (a.isRemovable != b.isRemovable) {
        return a.isRemovable ? -1 : 1;
      }
      return a.name.compareTo(b.name);
    });

    return Column(
      children: [
        // Persistent SIMULATION banner
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
                // Info banner
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppTheme.simplePrimary.withValues(alpha: 0.08),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                        color: AppTheme.simplePrimary.withValues(alpha: 0.2)),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.info_outline,
                          color: AppTheme.simplePrimary, size: 20),
                      SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          'Select a drive to securely wipe all data',
                          style: TextStyle(
                            color: AppTheme.simplePrimary,
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),

                // Orphan detection card (active wipe in progress OR interrupted wipe)
                if (orphanResult != null) ...[
                  if (orphanResult.status == OrphanCheckStatus.processActive) ...[
                    Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: AppTheme.accentEmerald.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                            color: AppTheme.accentEmerald.withValues(alpha: 0.5)),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.sync,
                              color: AppTheme.accentEmerald, size: 24),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'A wipe is already in progress',
                                  style: TextStyle(
                                    color: AppTheme.accentEmerald,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 14,
                                  ),
                                ),
                                const SizedBox(height: 2),
                                Text(
                                  'PID: ${orphanResult.pid ?? "active"} • Target: ${orphanResult.activeJobState?.deviceName ?? orphanResult.activeJobState?.devicePath ?? "unknown"} • Method: ${orphanResult.activeJobState?.method ?? "unknown"}',
                                  style: const TextStyle(
                                    color: AppTheme.textSecondary,
                                    fontSize: 12,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          ElevatedButton.icon(
                            style: ElevatedButton.styleFrom(
                              backgroundColor: AppTheme.accentEmerald,
                              foregroundColor: Colors.white,
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 14, vertical: 8),
                            ),
                            icon: const Icon(Icons.visibility, size: 16),
                            label: const Text('Attach',
                                style: TextStyle(
                                    fontSize: 12,
                                    fontWeight: FontWeight.bold)),
                            onPressed: () {
                              final attached = controller.attachOrphan();
                              if (attached != null) {
                                context.go('/drive/${attached.stableId}');
                              }
                            },
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                  ] else ...[
                    Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: AppTheme.accentRose.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                            color: AppTheme.accentRose.withValues(alpha: 0.4)),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.warning_amber_rounded,
                              color: AppTheme.accentRose, size: 22),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'Interrupted wipe detected',
                                  style: TextStyle(
                                    color: AppTheme.accentRose,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 13,
                                  ),
                                ),
                                const SizedBox(height: 2),
                                Text(
                                  'Device ${orphanResult.activeJobState?.deviceName ?? "unknown"} '
                                  'was not cleanly verified. Check before reuse.',
                                  style: const TextStyle(
                                    color: AppTheme.textSecondary,
                                    fontSize: 12,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          TextButton(
                            onPressed: () => controller.acknowledgeOrphan(),
                            child: const Text('Dismiss',
                                style: TextStyle(fontSize: 11)),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                  ],
                ],

                // Available Drives heading + refresh + toggle
                Row(
                  children: [
                    const Text(
                      'Available Drives',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                        color: AppTheme.textPrimary,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 8, vertical: 2),
                      decoration: BoxDecoration(
                        color: AppTheme.simplePrimary.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Text(
                        '${visibleDevices.length}',
                        style: const TextStyle(
                          color: AppTheme.simplePrimary,
                          fontWeight: FontWeight.bold,
                          fontSize: 12,
                        ),
                      ),
                    ),
                    const Spacer(),
                    TextButton.icon(
                      onPressed: () => controller.refreshDevices(),
                      icon: const Icon(Icons.refresh, size: 16),
                      label: const Text('Refresh', style: TextStyle(fontSize: 12)),
                    ),
                  ],
                ),
                const SizedBox(height: 12),

                // Drive cards
                if (visibleDevices.isEmpty)
                  Container(
                    padding: const EdgeInsets.all(32),
                    width: double.infinity,
                    decoration: BoxDecoration(
                      color: AppTheme.surfaceCard,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Column(
                      children: [
                        Icon(Icons.usb_off,
                            size: 48,
                            color: AppTheme.textMuted.withValues(alpha: 0.5)),
                        const SizedBox(height: 12),
                        const Text(
                          'No removable drives detected',
                          style: TextStyle(
                            color: AppTheme.textMuted,
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 4),
                        const Text(
                          'Connect a USB drive or SD card, then tap Refresh',
                          style:
                              TextStyle(color: AppTheme.textMuted, fontSize: 12),
                        ),
                      ],
                    ),
                  )
                else
                  ...visibleDevices.map((device) =>
                      _DriveCard(device: device)),

                const SizedBox(height: 16),

                // Show internal drives toggle
                InkWell(
                  onTap: () =>
                      controller.setShowInternalDrives(!showInternal),
                  borderRadius: BorderRadius.circular(8),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    child: Row(
                      children: [
                        Icon(
                          showInternal
                              ? Icons.visibility
                              : Icons.visibility_off,
                          size: 18,
                          color: AppTheme.textMuted,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          showInternal
                              ? 'Hide internal drives'
                              : 'Show internal drives',
                          style: const TextStyle(
                            color: AppTheme.textMuted,
                            fontSize: 13,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _DriveCard extends StatelessWidget {
  final DeviceProfile device;

  const _DriveCard({required this.device});

  @override
  Widget build(BuildContext context) {
    final disabled = device.simpleDisabledReason;
    final supportLevel = computeSupportLevel(device);
    final driveType = device.driveType;

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Material(
        color: disabled != null
            ? AppTheme.surfaceCard.withValues(alpha: 0.5)
            : AppTheme.surfaceCard,
        borderRadius: BorderRadius.circular(14),
        child: InkWell(
          borderRadius: BorderRadius.circular(14),
          onTap: disabled != null
              ? null
              : () => context.go('/drive/${device.stableId}'),
          child: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(14),
              border: Border.all(
                color: device.isSystemDisk
                    ? AppTheme.accentRose.withValues(alpha: 0.3)
                    : AppTheme.surfaceBorder,
              ),
            ),
            child: Row(
              children: [
                // Drive icon
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: disabled != null
                        ? AppTheme.textMuted.withValues(alpha: 0.1)
                        : AppTheme.simplePrimary.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Icon(
                    _driveIcon(driveType),
                    color: disabled != null
                        ? AppTheme.textMuted
                        : AppTheme.simplePrimary,
                    size: 24,
                  ),
                ),
                const SizedBox(width: 14),

                // Info
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        device.name,
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 14,
                          color: disabled != null
                              ? AppTheme.textMuted
                              : AppTheme.textPrimary,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 2),
                      Text(
                        '${device.formattedCapacity} • ${device.busType}',
                        style: const TextStyle(
                          color: AppTheme.textSecondary,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),

                // Badges
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // DriveType chip
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: AppTheme.simplePrimary.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        driveType.label,
                        style: const TextStyle(
                          color: AppTheme.simplePrimary,
                          fontSize: 10,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                    const SizedBox(width: 6),

                    // System/disabled badge OR support level badge
                    if (disabled != null)
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: AppTheme.accentRose.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(
                              color:
                                  AppTheme.accentRose.withValues(alpha: 0.3)),
                        ),
                        child: Text(
                          disabled,
                          style: const TextStyle(
                            color: AppTheme.accentRose,
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      )
                    else
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: supportLevel.badgeColor.withValues(alpha: 0.1),
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

                if (disabled == null) ...[
                  const SizedBox(width: 8),
                  const Icon(Icons.chevron_right,
                      color: AppTheme.textMuted, size: 20),
                ],
              ],
            ),
          ),
        ),
      ),
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
