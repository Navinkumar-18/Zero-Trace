import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../../../services/sanitization_controller.dart';
import '../../../widgets/theme.dart';
import '../../../widgets/dev_control_panel.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Text(
                'Settings',
                style: GoogleFonts.inter(
                  color: AppTheme.textPrimary,
                  fontSize: 28,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'Control scan behavior, privacy and secure erase options.',
                style: GoogleFonts.inter(
                  color: AppTheme.textSecondary,
                  fontSize: 13,
                ),
              ),
              const SizedBox(height: 24),

              // Demo Mode Section
              _buildSection(
                title: 'Operation Mode',
                icon: Icons.science,
                color: AppTheme.accentGold,
                children: [
                  _buildToggleTile(
                    title: 'Demo Mode',
                    subtitle: 'Uses simulated devices. No physical data will be destroyed.',
                    value: !controller.isRealMode,
                    activeColor: AppTheme.accentGold,
                    onChanged: (val) => controller.toggleRealMode(!val),
                  ),
                  _buildToggleTile(
                    title: 'Real Hardware Detection',
                    subtitle: 'Discovers actual physical storage devices via lsblk. '
                        'System boot disks are always protected.',
                    value: controller.isRealMode,
                    activeColor: AppTheme.accentEmerald,
                    onChanged: (val) => controller.toggleRealMode(val),
                  ),
                  _buildToggleTile(
                    title: 'Simulate Failure Mode',
                    subtitle: 'Injects a controller timeout error during sanitization '
                        'to test error handling and failed certificate generation.',
                    value: controller.simulateFailureMode,
                    activeColor: AppTheme.accentRose,
                    onChanged: (val) => controller.toggleSimulateFailureMode(val),
                  ),
                ],
              ),
              const SizedBox(height: 20),

              // Safety Configuration
              _buildSection(
                title: 'Safety Configuration',
                icon: Icons.security,
                color: AppTheme.accentEmerald,
                children: [
                  _buildInfoTile(
                    title: 'System Disk Protection',
                    subtitle: 'The currently running OS disk is always protected and '
                        'cannot be sanitized from this application.',
                    icon: Icons.shield,
                    color: AppTheme.accentEmerald,
                  ),
                  _buildInfoTile(
                    title: 'Policy Layer',
                    subtitle: 'All sanitization operations must pass through the '
                        'deterministic policy validation layer before execution.',
                    icon: Icons.gavel,
                    color: AppTheme.accentBlue,
                  ),
                  _buildInfoTile(
                    title: 'User Confirmation Required',
                    subtitle: 'Destructive operations require explicit user confirmation '
                        'including typing "SANITIZE" to proceed.',
                    icon: Icons.warning_amber,
                    color: AppTheme.accentOrange,
                  ),
                  _buildInfoTile(
                    title: 'AI Safety',
                    subtitle: 'The AI assistant is advisory only. It cannot execute '
                        'commands, select devices, or bypass safety checks.',
                    icon: Icons.psychology,
                    color: AppTheme.accentGold,
                  ),
                ],
              ),
              const SizedBox(height: 20),

              // Known Limitations
              _buildSection(
                title: 'Known Limitations',
                icon: Icons.report_problem_outlined,
                color: AppTheme.accentOrange,
                children: [
                  _buildInfoTile(
                    title: 'Flash Media Wear Remapping',
                    subtitle: 'Overwrite cannot reach hidden or remapped flash blocks on SD cards and USB drives.',
                    icon: Icons.memory,
                    color: AppTheme.accentOrange,
                  ),
                  _buildInfoTile(
                    title: 'Statistical Verification',
                    subtitle: 'Verification is statistical (50 sampled sectors plus entropy check), not a full-media read.',
                    icon: Icons.analytics_outlined,
                    color: AppTheme.accentOrange,
                  ),
                  _buildInfoTile(
                    title: 'Self-Signed Certificates',
                    subtitle: 'Certificates are self-signed with a local key; they prove integrity, not third-party validation.',
                    icon: Icons.vpn_key_outlined,
                    color: AppTheme.accentOrange,
                  ),
                  _buildInfoTile(
                    title: 'Operating Platform',
                    subtitle: 'Currently supported platform: Linux.',
                    icon: Icons.terminal,
                    color: AppTheme.accentOrange,
                  ),
                  _buildInfoTile(
                    title: 'Unsupported Media Types',
                    subtitle: 'Not supported yet: smartphones, RAID volumes, optical media, tape.',
                    icon: Icons.not_interested,
                    color: AppTheme.accentOrange,
                  ),
                ],
              ),
              const SizedBox(height: 20),

              // Developer Tools
              _buildSection(
                title: 'Developer Tools',
                icon: Icons.developer_mode,
                color: AppTheme.accentBlue,
                children: [
                  Material(
                    color: Colors.transparent,
                    child: ListTile(
                      leading: Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: AppTheme.accentBlue.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: const Icon(Icons.refresh, color: AppTheme.accentBlue, size: 20),
                      ),
                      title: Text(
                        'Reset Device State & Clear History',
                        style: GoogleFonts.inter(
                          color: AppTheme.textPrimary,
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      subtitle: Text(
                        'Reloads hardware inventory and clears active job state',
                        style: GoogleFonts.inter(
                          color: AppTheme.textMuted,
                          fontSize: 12,
                        ),
                      ),
                      onTap: () {
                        controller.resetSimulator();
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('Device inventory reset.'),
                            backgroundColor: AppTheme.accentBlue,
                          ),
                        );
                      },
                    ),
                  ),
                  Material(
                    color: Colors.transparent,
                    child: ListTile(
                      leading: Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: AppTheme.accentGold.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: const Icon(Icons.tune, color: AppTheme.accentGold, size: 20),
                      ),
                      title: Text(
                        'Open Control Panel',
                        style: GoogleFonts.inter(
                          color: AppTheme.textPrimary,
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      subtitle: Text(
                        'Quick access to demo and simulation controls',
                        style: GoogleFonts.inter(
                          color: AppTheme.textMuted,
                          fontSize: 12,
                        ),
                      ),
                      onTap: () => DevControlPanel.show(context),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 20),

              // About Section
              _buildSection(
                title: 'About',
                icon: Icons.info_outline,
                color: AppTheme.textMuted,
                children: [
                  _buildInfoTile(
                    title: 'Zero Trace 2.0',
                    subtitle: 'AI-Assisted Secure Data Sanitization for '
                        'Trustworthy IT Asset Recycling',
                    icon: Icons.shield,
                    color: AppTheme.accentGold,
                  ),
                  _buildAboutRow('Problem Statement', 'SIH25070'),
                  _buildAboutRow('Version', 'v2.0.0 (Phase 1 Build)'),
                  _buildAboutRow('Platform', 'Linux Desktop (Flutter)'),
                  _buildAboutRow('Standards', 'NIST SP 800-88 Rev. 2, IEEE 2883:2022'),
                  _buildAboutRow('Signature', 'ECDSA P-256 / SHA-256'),
                  _buildAboutRow('Research', 'PALES, EVSD'),
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: AppTheme.surfaceCard,
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Text(
                      'Zero Trace 2.0 is a research-oriented, media-aware secure '
                      'sanitization and verification platform that integrates '
                      'storage-device analysis, trusted sanitization mechanisms, '
                      'AI-assisted decision support, verification and auditable '
                      'certification.',
                      style: GoogleFonts.inter(
                        color: AppTheme.textSecondary,
                        fontSize: 12,
                        height: 1.5,
                        fontStyle: FontStyle.italic,
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSection({
    required String title,
    required IconData icon,
    required Color color,
    required List<Widget> children,
  }) {
    return Container(
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 20, 20, 12),
            child: Row(
              children: [
                Icon(icon, color: color, size: 20),
                const SizedBox(width: 10),
                Text(
                  title,
                  style: GoogleFonts.outfit(
                    color: AppTheme.textPrimary,
                    fontSize: 16,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ],
            ),
          ),
          const Divider(color: AppTheme.surfaceBorder, height: 1),
          ...children,
          const SizedBox(height: 8),
        ],
      ),
    );
  }

  Widget _buildToggleTile({
    required String title,
    required String subtitle,
    required bool value,
    required Color activeColor,
    required ValueChanged<bool> onChanged,
  }) {
    return Material(
      color: Colors.transparent,
      child: SwitchListTile(
        title: Text(
          title,
          style: GoogleFonts.inter(
            color: AppTheme.textPrimary,
            fontSize: 14,
            fontWeight: FontWeight.w600,
          ),
        ),
        subtitle: Text(
          subtitle,
          style: GoogleFonts.inter(
            color: AppTheme.textMuted,
            fontSize: 12,
          ),
        ),
        value: value,
        activeThumbColor: activeColor,
        onChanged: onChanged,
      ),
    );
  }

  Widget _buildInfoTile({
    required String title,
    required String subtitle,
    required IconData icon,
    required Color color,
  }) {
    return Material(
      color: Colors.transparent,
      child: ListTile(
        leading: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: color.withValues(alpha: 0.15),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(icon, color: color, size: 20),
        ),
        title: Text(
          title,
          style: GoogleFonts.inter(
            color: AppTheme.textPrimary,
            fontSize: 14,
            fontWeight: FontWeight.w600,
          ),
        ),
        subtitle: Text(
          subtitle,
          style: GoogleFonts.inter(
            color: AppTheme.textMuted,
            fontSize: 12,
          ),
        ),
      ),
    );
  }

  Widget _buildAboutRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 4),
      child: Row(
        children: [
          SizedBox(
            width: 130,
            child: Text(
              label,
              style: GoogleFonts.inter(
                color: AppTheme.textMuted,
                fontSize: 12,
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
              ),
            ),
          ),
        ],
      ),
    );
  }
}
