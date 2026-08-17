import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../models/device_profile.dart';
import '../services/sanitization_controller.dart';
import '../widgets/dev_control_panel.dart';
import '../widgets/step_indicator.dart';
import '../widgets/theme.dart';

class DeviceInventoryScreen extends StatefulWidget {
  const DeviceInventoryScreen({super.key});

  @override
  State<DeviceInventoryScreen> createState() => _DeviceInventoryScreenState();
}

class _DeviceInventoryScreenState extends State<DeviceInventoryScreen> {
  String _searchQuery = '';

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
    final allDevices = controller.devices;

    final filteredDevices = allDevices.where((device) {
      final q = _searchQuery.toLowerCase();
      return device.name.toLowerCase().contains(q) ||
          device.busType.toLowerCase().contains(q) ||
          device.mediaType.displayName.toLowerCase().contains(q) ||
          device.serialNumber.toLowerCase().contains(q);
    }).toList();

    // Summary stats
    final totalCapacityBytes = allDevices.fold<int>(0, (sum, d) => sum + d.capacityBytes);
    final totalGb = (totalCapacityBytes / (1024 * 1024 * 1024)).toStringAsFixed(0);
    final encryptedCount = allDevices.where((d) => d.isHardwareEncrypted).length;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [AppTheme.accentGold, AppTheme.accentGoldLight],
                ),
                borderRadius: BorderRadius.circular(10),
              ),
              child: const Icon(Icons.shield, color: Colors.white, size: 20),
            ),
            const SizedBox(width: 12),
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
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: controller.isRealMode
                    ? AppTheme.accentEmerald.withValues(alpha: 0.15)
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
                  const SizedBox(width: 6),
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
          padding: const EdgeInsets.symmetric(horizontal: 20.0, vertical: 14.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Step Progress Wizard Header
              const StepIndicator(currentStep: 1),
              const SizedBox(height: 16),

              // Overview Quick Stats Bar
              LayoutBuilder(
                builder: (context, constraints) {
                  return Container(
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
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceAround,
                      children: [
                        _buildStatItem(
                          context,
                          label: 'TOTAL ASSETS',
                          value: '${allDevices.length}',
                          icon: Icons.storage,
                          color: AppTheme.accentBlue,
                        ),
                        _buildStatDivider(),
                        _buildStatItem(
                          context,
                          label: 'TOTAL STORAGE',
                          value: '$totalGb GB',
                          icon: Icons.pie_chart,
                          color: AppTheme.accentGold,
                        ),
                        _buildStatDivider(),
                        _buildStatItem(
                          context,
                          label: 'OPAL ENCRYPTED',
                          value: '$encryptedCount',
                          icon: Icons.lock,
                          color: AppTheme.accentEmerald,
                        ),
                      ],
                    ),
                  );
                },
              ),
              const SizedBox(height: 16),

              // Search & Filter Input Bar
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      decoration: InputDecoration(
                        hintText: 'Search assets by name, bus, serial, or media type...',
                        prefixIcon: const Icon(Icons.search, color: AppTheme.textSecondary, size: 20),
                        suffixIcon: _searchQuery.isNotEmpty
                            ? IconButton(
                                icon: const Icon(Icons.clear, size: 18),
                                onPressed: () => setState(() => _searchQuery = ''),
                              )
                            : null,
                        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                      ),
                      onChanged: (val) => setState(() => _searchQuery = val),
                    ),
                  ),
                  const SizedBox(width: 12),
                  IconButton.filledTonal(
                    icon: const Icon(Icons.refresh),
                    tooltip: 'Refresh Inventory',
                    onPressed: () => controller.refreshDevices(),
                  ),
                ],
              ),
              const SizedBox(height: 16),

              Text(
                'DISCOVERED STORAGE TARGETS (${filteredDevices.length})',
                style: const TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 11,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.0,
                ),
              ),
              const SizedBox(height: 10),

              // Responsive Device List Grid View
              Expanded(
                child: filteredDevices.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            const Icon(Icons.search_off, size: 48, color: AppTheme.textMuted),
                            const SizedBox(height: 12),
                            Text(
                              'No storage devices found matching "$_searchQuery"',
                              style: const TextStyle(color: AppTheme.textSecondary),
                            ),
                          ],
                        ),
                      )
                    : LayoutBuilder(
                        builder: (context, constraints) {
                          final crossAxisCount = constraints.maxWidth > 900 ? 2 : 1;

                          if (crossAxisCount == 1) {
                            return ListView.builder(
                              itemCount: filteredDevices.length,
                              itemBuilder: (context, index) {
                                return _buildDeviceCard(context, controller, filteredDevices[index]);
                              },
                            );
                          }

                          return GridView.builder(
                            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                              crossAxisCount: 2,
                              crossAxisSpacing: 14,
                              mainAxisSpacing: 14,
                              childAspectRatio: 2.2,
                            ),
                            itemCount: filteredDevices.length,
                            itemBuilder: (context, index) {
                              return _buildDeviceCard(context, controller, filteredDevices[index]);
                            },
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

  Widget _buildStatItem(
    BuildContext context, {
    required String label,
    required String value,
    required IconData icon,
    required Color color,
  }) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: color, size: 16),
            const SizedBox(width: 6),
            Text(
              value,
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: color,
              ),
            ),
          ],
        ),
        const SizedBox(height: 2),
        Text(
          label,
          style: const TextStyle(
            color: AppTheme.textMuted,
            fontSize: 10,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.5,
          ),
        ),
      ],
    );
  }

  Widget _buildStatDivider() {
    return Container(
      height: 30,
      width: 1,
      color: AppTheme.surfaceBorder,
    );
  }

  Widget _buildDeviceCard(BuildContext context, SanitizationController controller, DeviceProfile device) {
    final isSelected = controller.selectedDevice?.id == device.id;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12.0),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: () {
            controller.selectDevice(device);
            context.go('/devices/details/${device.id}');
          },
          borderRadius: BorderRadius.circular(16),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: isSelected ? AppTheme.surfaceCard : AppTheme.surfaceDark,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: device.isSystemDisk
                    ? AppTheme.accentRose
                    : (isSelected ? AppTheme.accentGold : AppTheme.surfaceBorder),
                width: isSelected || device.isSystemDisk ? 2 : 1,
              ),
              boxShadow: isSelected
                  ? [
                      BoxShadow(
                        color: AppTheme.accentGold.withValues(alpha: 0.15),
                        blurRadius: 12,
                        spreadRadius: 2,
                      )
                    ]
                  : null,
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
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
                          Row(
                            children: [
                              Expanded(
                                child: Text(
                                  device.name,
                                  style: const TextStyle(
                                    fontSize: 16,
                                    fontWeight: FontWeight.bold,
                                    color: AppTheme.textPrimary,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              if (device.isSystemDisk) ...[
                                const SizedBox(width: 6),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                  decoration: BoxDecoration(
                                    color: AppTheme.accentRose.withValues(alpha: 0.2),
                                    borderRadius: BorderRadius.circular(6),
                                    border: Border.all(color: AppTheme.accentRose),
                                  ),
                                  child: const Text(
                                    'OS BOOT DISK',
                                    style: TextStyle(color: AppTheme.accentRose, fontSize: 9, fontWeight: FontWeight.bold),
                                  ),
                                ),
                              ],
                            ],
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
                    const SizedBox(width: 8),
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
                const SizedBox(height: 10),
                const Divider(color: AppTheme.surfaceBorder, height: 1),
                const SizedBox(height: 8),

                // Capabilities Badges Row
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
                      _buildBadge('HPA/DCO Sectors', AppTheme.accentRose),
                  ],
                ),
              ],
            ),
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
