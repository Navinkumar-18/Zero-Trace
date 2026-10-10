import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';

/// EndDrawer for Simple Mode providing access to all advanced features.
class SimpleAdvancedDrawer extends StatelessWidget {
  const SimpleAdvancedDrawer({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final showInternal = controller.showInternalDrives;
    final isSimulated = !controller.isRealMode;

    return Drawer(
      backgroundColor: AppTheme.surfaceDark,
      width: 300,
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(20),
              decoration: const BoxDecoration(
                border: Border(
                  bottom: BorderSide(color: AppTheme.surfaceBorder),
                ),
              ),
              child: const Row(
                children: [
                  Icon(Icons.tune, color: AppTheme.simplePrimary, size: 24),
                  SizedBox(width: 12),
                  Text('Advanced',
                      style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                          color: AppTheme.textPrimary)),
                ],
              ),
            ),

            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(vertical: 8),
                children: [
                  // --- Mode section ---
                  _sectionHeader('Mode'),
                  SwitchListTile(
                    dense: true,
                    title: const Text('Simulated Mode',
                        style:
                            TextStyle(fontSize: 13, color: AppTheme.textPrimary)),
                    subtitle: Text(
                      isSimulated
                          ? 'No real drives modified'
                          : 'Real device operations',
                      style: const TextStyle(
                          fontSize: 11, color: AppTheme.textMuted),
                    ),
                    value: isSimulated,
                    activeThumbColor: AppTheme.accentGold,
                    onChanged: controller.isJobRunning
                        ? null
                        : (val) => _handleModeToggle(context, controller, val),
                  ),

                  // --- Display section ---
                  _sectionHeader('Display'),
                  SwitchListTile(
                    dense: true,
                    title: const Text('Show Internal Drives',
                        style:
                            TextStyle(fontSize: 13, color: AppTheme.textPrimary)),
                    subtitle: const Text(
                      'HDDs, SSDs, NVMe (resets on launch)',
                      style:
                          TextStyle(fontSize: 11, color: AppTheme.textMuted),
                    ),
                    value: showInternal,
                    activeThumbColor: AppTheme.simplePrimary,
                    onChanged: (val) =>
                        controller.setShowInternalDrives(val),
                  ),

                  const Divider(color: AppTheme.surfaceBorder),

                  // --- Advanced Tools ---
                  _sectionHeader('Advanced Tools'),
                  _navTile(
                    context,
                    icon: Icons.history,
                    label: 'History',
                    route: '/history',
                  ),
                  _navTile(
                    context,
                    icon: Icons.smart_toy_outlined,
                    label: 'AI Assistant',
                    route: '/advanced/ai',
                  ),
                  _navTile(
                    context,
                    icon: Icons.verified,
                    label: 'Certificate Verifier',
                    route: '/advanced/cert-verify',
                  ),
                  _navTile(
                    context,
                    icon: Icons.settings,
                    label: 'Settings',
                    route: '/advanced/settings',
                  ),
                ],
              ),
            ),

            // Back to Simple
            Container(
              padding: const EdgeInsets.all(16),
              decoration: const BoxDecoration(
                border: Border(
                  top: BorderSide(color: AppTheme.surfaceBorder),
                ),
              ),
              child: SizedBox(
                width: double.infinity,
                child: TextButton.icon(
                  icon: const Icon(Icons.arrow_back, size: 16),
                  label: const Text('Back to Simple'),
                  onPressed: () {
                    Navigator.of(context).pop(); // close drawer
                    context.go('/');
                  },
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _sectionHeader(String title) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
      child: Text(
        title.toUpperCase(),
        style: const TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.bold,
          color: AppTheme.textMuted,
          letterSpacing: 1.0,
        ),
      ),
    );
  }

  Widget _navTile(BuildContext context,
      {required IconData icon,
      required String label,
      required String route}) {
    return ListTile(
      dense: true,
      leading: Icon(icon, size: 20, color: AppTheme.textSecondary),
      title: Text(label,
          style: const TextStyle(fontSize: 13, color: AppTheme.textPrimary)),
      trailing: const Icon(Icons.chevron_right,
          size: 16, color: AppTheme.textMuted),
      onTap: () {
        Navigator.of(context).pop(); // close drawer
        context.go(route);
      },
    );
  }

  Future<void> _handleModeToggle(
    BuildContext context,
    SanitizationController controller,
    bool switchToSimulated,
  ) async {
    if (controller.isJobRunning) return;
    if (switchToSimulated) {
      // Switching to simulated is always safe
      await controller.toggleRealMode(false);
      return;
    }

    // Switching to Real Mode: warn with confirmation dialog
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.surfaceDark,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppTheme.accentRose, width: 1.5),
        ),
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: AppTheme.accentRose, size: 24),
            SizedBox(width: 10),
            Text('Enable Real Hardware Mode?',
                style: TextStyle(color: AppTheme.textPrimary, fontSize: 16)),
          ],
        ),
        content: const Text(
          'Warning: Real Mode enables destructive commands against physical connected storage hardware.\n\n'
          'All wipe operations in Real Mode permanently destroy data with NO possibility of recovery.\n\n'
          'Are you sure you want to switch to Real Mode?',
          style: TextStyle(color: AppTheme.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Keep Simulated'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.accentRose,
              foregroundColor: Colors.white,
            ),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Switch to Real'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await controller.toggleRealMode(true);
    }
  }
}
