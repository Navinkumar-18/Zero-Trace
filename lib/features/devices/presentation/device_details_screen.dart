import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../../../models/device_profile.dart';
import '../../../models/sanitization_support_level.dart';
import '../../../models/storage_capability.dart';
import '../../../services/sanitization_controller.dart';
import '../../../widgets/theme.dart';

class DeviceDetailsScreen extends StatelessWidget {
  final String deviceId;
  const DeviceDetailsScreen({super.key, required this.deviceId});

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final device = controller.devices.where((d) => d.id == deviceId).firstOrNull;

    if (device == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Device Details')),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.error_outline, size: 48, color: AppTheme.textMuted),
              const SizedBox(height: 12),
              Text(
                'Device not found: $deviceId',
                style: GoogleFonts.inter(color: AppTheme.textSecondary),
              ),
              const SizedBox(height: 16),
              OutlinedButton(
                onPressed: () => context.go('/advanced/devices'),
                child: const Text('Back to Devices'),
              ),
            ],
          ),
        ),
      );
    }

    final capabilities = DeviceCapabilities.fromDeviceFlags(
      deviceId: device.id,
      mediaType: device.mediaType.name,
      supportsAtaSecureErase: device.supportsAtaSecureErase,
      supportsAtaSanitize: device.supportsAtaSanitize,
      supportsNvmeSanitize: device.supportsNvmeSanitize,
      supportsEmmcSanitize: device.supportsEmmcSanitize,
      supportsTrim: device.supportsTrim,
      isHardwareEncrypted: device.isHardwareEncrypted,
      hpaDcoPresent: device.hpaDcoPresent,
    );

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Back navigation
              Row(
                children: [
                  IconButton(
                    icon: const Icon(Icons.arrow_back, color: AppTheme.textSecondary),
                    onPressed: () => context.go('/advanced/devices'),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Device Details',
                    style: GoogleFonts.outfit(
                      color: AppTheme.textPrimary,
                      fontSize: 24,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 20),

              // Device identity card
              _buildDeviceIdentityCard(device),
              const SizedBox(height: 20),

              // Two-column layout on wide screens
              LayoutBuilder(
                builder: (context, constraints) {
                  if (constraints.maxWidth > 800) {
                    return Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(child: _buildCapabilitiesTable(capabilities)),
                        const SizedBox(width: 20),
                        Expanded(child: _buildRiskAndActions(context, controller, device)),
                      ],
                    );
                  }
                  return Column(
                    children: [
                      _buildCapabilitiesTable(capabilities),
                      const SizedBox(height: 20),
                      _buildRiskAndActions(context, controller, device),
                    ],
                  );
                },
              ),

              const SizedBox(height: 20),
              _buildTechnicalNotes(device),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDeviceIdentityCard(DeviceProfile device) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: device.isSystemDisk ? AppTheme.accentRose : AppTheme.surfaceBorder,
          width: device.isSystemDisk ? 2 : 1,
        ),
      ),
      child: Column(
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: _getMediaColor(device.mediaType).withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(14),
                ),
                child: Icon(
                  _getMediaIcon(device.mediaType),
                  color: _getMediaColor(device.mediaType),
                  size: 32,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            device.name,
                            style: GoogleFonts.outfit(
                              color: AppTheme.textPrimary,
                              fontSize: 20,
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                        ),
                        if (device.isWipedNoFilesystem)
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: AppTheme.accentEmerald.withValues(alpha: 0.2),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(color: AppTheme.accentEmerald),
                            ),
                            child: Text(
                              'WIPED / NO FILESYSTEM',
                              style: GoogleFonts.inter(
                                color: AppTheme.accentEmerald,
                                fontSize: 10,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          )
                        else if (device.isSystemDisk)
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: AppTheme.accentRose.withValues(alpha: 0.2),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(color: AppTheme.accentRose),
                            ),
                            child: Text(
                              'SYSTEM DISK — PROTECTED',
                              style: GoogleFonts.inter(
                                color: AppTheme.accentRose,
                                fontSize: 10,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      device.mediaType.displayName,
                      style: GoogleFonts.inter(
                        color: _getMediaColor(device.mediaType),
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),
          const Divider(color: AppTheme.surfaceBorder, height: 1),
          const SizedBox(height: 16),
          // Info grid
          Wrap(
            spacing: 24,
            runSpacing: 12,
            children: [
              _infoChip('Serial', device.serialNumber),
              _infoChip('Capacity', device.formattedCapacity),
              _infoChip('Interface', device.busType),
              _infoChip('Mount', device.mountPoint ?? 'Not mounted'),
              if (device.mediaType == MediaType.hdd && device.rotationalRpm != null && device.rotationalRpm! > 0)
                _infoChip('RPM', '${device.rotationalRpm}'),
              _infoChip('Encrypted', device.isHardwareEncrypted ? 'Yes (TCG OPAL)' : 'No'),
            ],
          ),
        ],
      ),
    );
  }

  Widget _infoChip(String label, String value) {
    return SizedBox(
      width: 180,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 70,
            child: Text(
              label,
              style: GoogleFonts.inter(
                color: AppTheme.textMuted,
                fontSize: 11,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: GoogleFonts.inter(
                color: AppTheme.textPrimary,
                fontSize: 12,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCapabilitiesTable(DeviceCapabilities caps) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.fact_check, color: AppTheme.accentBlue, size: 20),
              const SizedBox(width: 10),
              Text(
                'Storage Capabilities',
                style: GoogleFonts.outfit(
                  color: AppTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          ...caps.capabilities.map((cap) => _buildCapabilityRow(cap)),
        ],
      ),
    );
  }

  Widget _buildCapabilityRow(StorageCapability cap) {
    Color statusColor;
    switch (cap.status) {
      case CapabilityStatus.available:
        statusColor = AppTheme.accentEmerald;
        break;
      case CapabilityStatus.notAvailable:
        statusColor = AppTheme.accentRose;
        break;
      case CapabilityStatus.unknown:
        statusColor = AppTheme.accentOrange;
        break;
      case CapabilityStatus.notApplicable:
        statusColor = AppTheme.textMuted;
        break;
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Text(
            cap.status.icon,
            style: TextStyle(color: statusColor, fontSize: 16),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  cap.name,
                  style: GoogleFonts.inter(
                    color: AppTheme.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                Text(
                  cap.description,
                  style: GoogleFonts.inter(
                    color: AppTheme.textMuted,
                    fontSize: 10,
                  ),
                ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
            decoration: BoxDecoration(
              color: statusColor.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              cap.status.displayName,
              style: GoogleFonts.inter(
                color: statusColor,
                fontSize: 10,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRiskAndActions(BuildContext context, SanitizationController controller, DeviceProfile device) {
    // Compute sanitization support level from the shared model
    final supportLevel = computeSupportLevel(device);
    final reason = supportLevelReason(device);

    String badgeLabel;
    Color badgeColor;
    String badgeSubtitle;
    if (device.isSystemDisk) {
      badgeLabel = 'PROTECTED';
      badgeColor = AppTheme.accentRose;
      badgeSubtitle = 'SYSTEM DISK';
    } else {
      badgeLabel = supportLevel.badgeLabel;
      badgeColor = supportLevel.badgeColor;
      badgeSubtitle = 'SANITIZATION SUPPORT';
    }

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.shield, color: AppTheme.accentGold, size: 20),
              const SizedBox(width: 10),
              Text(
                'Support & Actions',
                style: GoogleFonts.outfit(
                  color: AppTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          // Support level badge
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: badgeColor.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: badgeColor.withValues(alpha: 0.3)),
            ),
            child: Column(
              children: [
                Text(
                  badgeLabel,
                  style: GoogleFonts.outfit(
                    color: badgeColor,
                    fontSize: 28,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                Text(
                  badgeSubtitle,
                  style: GoogleFonts.inter(
                    color: badgeColor,
                    fontSize: 10,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),

          // Reason line
          if (!device.isSystemDisk) ...[
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              decoration: BoxDecoration(
                color: badgeColor.withValues(alpha: 0.06),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: badgeColor.withValues(alpha: 0.2)),
              ),
              child: Row(
                children: [
                  Icon(Icons.info_outline, color: badgeColor, size: 16),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      reason,
                      style: GoogleFonts.inter(
                        color: AppTheme.textSecondary,
                        fontSize: 11,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],

          const SizedBox(height: 20),

          if (device.isSystemDisk) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppTheme.accentRose.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: AppTheme.accentRose.withValues(alpha: 0.3)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.block, color: AppTheme.accentRose, size: 18),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'System disk is protected. Sanitization is not available while running from this disk.',
                      style: GoogleFonts.inter(
                        color: AppTheme.accentRose,
                        fontSize: 12,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ] else ...[
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                icon: const Icon(Icons.cleaning_services, size: 18),
                label: Text(controller.isJobRunning ? 'SANITIZATION IN PROGRESS' : 'BEGIN SANITIZATION'),
                style: controller.isJobRunning
                    ? ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.surfaceBorder,
                        foregroundColor: AppTheme.textMuted,
                      )
                    : null,
                onPressed: controller.isJobRunning
                    ? null
                    : () {
                        controller.selectDevice(device);
                        context.go('/advanced/sanitize');
                      },
              ),
            ),
            const SizedBox(height: 10),
            SizedBox(
              width: double.infinity,
              child: OutlinedButton.icon(
                icon: const Icon(Icons.psychology, size: 18),
                label: const Text('ASK AI ABOUT THIS DEVICE'),
                onPressed: () => context.go('/advanced/ai'),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildTechnicalNotes(DeviceProfile device) {
    if (device.notes.isEmpty) return const SizedBox.shrink();

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.surfaceCard,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Row(
        children: [
          const Icon(Icons.info_outline, color: AppTheme.textMuted, size: 18),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              device.notes,
              style: GoogleFonts.inter(
                color: AppTheme.textSecondary,
                fontSize: 12,
              ),
            ),
          ),
        ],
      ),
    );
  }

  IconData _getMediaIcon(MediaType type) {
    switch (type) {
      case MediaType.hdd:
        return Icons.disc_full;
      case MediaType.sataSsd:
        return Icons.storage;
      case MediaType.nvmeSsd:
        return Icons.flash_on;
      case MediaType.emmc:
        return Icons.memory;
      case MediaType.usbFlash:
        return Icons.usb;
      case MediaType.unknown:
        return Icons.help_outline;
    }
  }

  Color _getMediaColor(MediaType type) {
    switch (type) {
      case MediaType.hdd:
        return AppTheme.accentOrange;
      case MediaType.sataSsd:
        return AppTheme.accentBlue;
      case MediaType.nvmeSsd:
        return AppTheme.accentGold;
      case MediaType.emmc:
        return AppTheme.accentEmerald;
      case MediaType.usbFlash:
        return AppTheme.accentRose;
      case MediaType.unknown:
        return AppTheme.textMuted;
    }
  }
}
