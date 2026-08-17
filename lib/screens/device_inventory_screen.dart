import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../models/device_profile.dart';
import '../services/sanitization_controller.dart';
import '../widgets/dev_control_panel.dart';
import '../widgets/theme.dart';

class DeviceInventoryScreen extends StatelessWidget {
  const DeviceInventoryScreen({super.key});

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

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final devices = controller.devices;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(6),
              decoration: BoxDecoration(
                color: AppTheme.accentGold.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.shield_outlined, color: AppTheme.accentGold, size: 22),
            ),
            const SizedBox(width: 10),
            const Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('ZERO TRACE 2.0', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                Text('SIH25070 • VCSE_DataCircuits', style: TextStyle(fontSize: 10, color: AppTheme.textSecondary)),
              ],
            ),
          ],
        ),
        actions: [
          InkWell(
            onTap: () => controller.toggleRealMode(!controller.isRealMode),
            borderRadius: BorderRadius.circular(20),
            child: Container(
              margin: const EdgeInsets.only(right: 8),
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: controller.isRealMode
                    ? AppTheme.accentEmerald.withValues(alpha: 0.2)
                    : AppTheme.accentGold.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: controller.isRealMode ? AppTheme.accentEmerald : AppTheme.accentGold,
                ),
              ),
              child: Row(
                children: [
                  Icon(
                    controller.isRealMode ? Icons.memory : Icons.tune,
                    color: controller.isRealMode ? AppTheme.accentEmerald : AppTheme.accentGold,
                    size: 14,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    controller.isRealMode ? 'REAL DISKS (lsblk)' : 'SIMULATED MODE',
                    style: TextStyle(
                      color: controller.isRealMode ? AppTheme.accentEmerald : AppTheme.accentGold,
                      fontSize: 11,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.settings, color: AppTheme.textSecondary),
            onPressed: () => DevControlPanel.show(context),
            tooltip: 'Review Control Panel',
          ),
        ],
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 12.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header description banner
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  gradient: const LinearGradient(
                    colors: [AppTheme.surfaceDark, AppTheme.surfaceCard],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: AppTheme.surfaceBorder),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Target Asset Inventory',
                      style: Theme.of(context).textTheme.titleLarge?.copyWith(
                            color: AppTheme.accentGold,
                            fontWeight: FontWeight.bold,
                          ),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Select a storage device profile to perform risk-based classification, method selection (NIST 800-88r2), and verifiable sanitization.',
                      style: TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.4),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'DISCOVERED STORAGE DEVICES (${devices.length})',
                style: const TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.0,
                ),
              ),
              const SizedBox(height: 10),

              // Device List
              Expanded(
                child: ListView.builder(
                  itemCount: devices.length,
                  itemBuilder: (context, index) {
                    final device = devices[index];
                    final isSelected = controller.selectedDevice?.id == device.id;

                    return Padding(
                      padding: const EdgeInsets.only(bottom: 12.0),
                      child: InkWell(
                        onTap: () {
                          controller.selectDevice(device);
                          context.push('/risk-assessment');
                        },
                        borderRadius: BorderRadius.circular(16),
                        child: Container(
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: isSelected ? AppTheme.surfaceCard : AppTheme.surfaceDark,
                            borderRadius: BorderRadius.circular(16),
                            border: Border.all(
                              color: isSelected ? AppTheme.accentGold : AppTheme.surfaceBorder,
                              width: isSelected ? 2 : 1,
                            ),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  Container(
                                    padding: const EdgeInsets.all(12),
                                    decoration: BoxDecoration(
                                      color: _getMediaColor(device.mediaType).withValues(alpha: 0.15),
                                      borderRadius: BorderRadius.circular(12),
                                    ),
                                    child: Icon(
                                      _getMediaIcon(device.mediaType),
                                      color: _getMediaColor(device.mediaType),
                                      size: 26,
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
                                            fontSize: 16,
                                            fontWeight: FontWeight.bold,
                                            color: AppTheme.textPrimary,
                                          ),
                                        ),
                                        const SizedBox(height: 4),
                                        Text(
                                          'S/N: ${device.serialNumber} • ${device.busType}',
                                          style: const TextStyle(
                                            fontSize: 12,
                                            color: AppTheme.textSecondary,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                                    decoration: BoxDecoration(
                                      color: AppTheme.surfaceCard,
                                      borderRadius: BorderRadius.circular(8),
                                      border: Border.all(color: AppTheme.surfaceBorder),
                                    ),
                                    child: Text(
                                      device.formattedCapacity,
                                      style: const TextStyle(
                                        color: AppTheme.accentGold,
                                        fontWeight: FontWeight.bold,
                                        fontSize: 13,
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 12),
                              const Divider(color: AppTheme.surfaceBorder, height: 1),
                              const SizedBox(height: 10),

                              // Capabilities badges row
                              Wrap(
                                spacing: 8,
                                runSpacing: 6,
                                children: [
                                  _buildBadge(device.mediaType.shortTag, _getMediaColor(device.mediaType)),
                                  if (device.isHardwareEncrypted)
                                    _buildBadge('TCG OPAL Encrypted', AppTheme.accentEmerald),
                                  if (device.supportsAtaSanitize || device.supportsNvmeSanitize || device.supportsEmmcSanitize)
                                    _buildBadge('Sanitize Primitive', AppTheme.accentBlue),
                                  if (device.supportsAtaSecureErase)
                                    _buildBadge('ATA Secure Erase', AppTheme.accentBlue),
                                  if (device.hpaDcoPresent)
                                    _buildBadge('HPA/DCO Hidden Sectors', AppTheme.accentRose),
                                ],
                              ),
                            ],
                          ),
                        ),
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildBadge(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Text(
        label,
        style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.bold),
      ),
    );
  }
}
