import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/sanitization_controller.dart';
import 'theme.dart';

class DevControlPanel extends StatelessWidget {
  const DevControlPanel({super.key});

  static void show(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.surfaceDark,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => const DevControlPanel(),
    );
  }

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();

    return Padding(
      padding: const EdgeInsets.all(20.0),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.developer_mode, color: AppTheme.accentGold),
              const SizedBox(width: 10),
              Text(
                'Demo Review Control Panel',
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      color: AppTheme.accentGold,
                      fontWeight: FontWeight.bold,
                    ),
              ),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.close),
                onPressed: () => Navigator.pop(context),
              ),
            ],
          ),
          const Divider(color: AppTheme.surfaceBorder),
          const SizedBox(height: 10),
          SwitchListTile(
            title: const Text('Real Hardware Detection Mode'),
            subtitle: const Text('Discovers actual physical disks connected to this PC using lsblk'),
            activeThumbColor: AppTheme.accentEmerald,
            value: controller.isRealMode,
            onChanged: (val) {
              controller.toggleRealMode(val);
            },
          ),
          const SizedBox(height: 10),
          SwitchListTile(
            title: const Text('Simulate Failure Mode'),
            subtitle: const Text('Injects controller timeout error during sanitization stage'),
            activeThumbColor: AppTheme.accentRose,
            value: controller.simulateFailureMode,
            onChanged: (val) {
              controller.toggleSimulateFailureMode(val);
            },
          ),
          const SizedBox(height: 10),
          ListTile(
            leading: const Icon(Icons.refresh, color: AppTheme.accentBlue),
            title: const Text('Reset Device State & Clear History'),
            subtitle: const Text('Reloads hardware inventory & clears active job state'),
            onTap: () {
              controller.resetSimulator();
              Navigator.pop(context);
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Device inventory refreshed.'),
                  backgroundColor: AppTheme.accentBlue,
                ),
              );
            },
          ),
          const SizedBox(height: 10),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppTheme.surfaceCard,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: AppTheme.surfaceBorder),
            ),
            child: Row(
              children: [
                Icon(
                  controller.isRealMode ? Icons.memory : Icons.shield_outlined,
                  color: controller.isRealMode ? AppTheme.accentEmerald : AppTheme.accentGold,
                  size: 20,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    controller.isRealMode
                        ? 'REAL MODE ACTIVE: System boot disks are strictly protected by Policy Layer.'
                        : 'SAFETY MODE: SIMULATION ACTIVE (Mock Demo Profiles Loaded)',
                    style: const TextStyle(fontSize: 11, color: AppTheme.textSecondary, fontWeight: FontWeight.bold),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
