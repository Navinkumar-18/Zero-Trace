import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:intl/intl.dart';

import '../../../services/sanitization_controller.dart';
import '../../../services/demo_data_service.dart';
import '../../../widgets/theme.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final demoService = DemoDataService();
    final stats = demoService.getStats(controller.devices);
    final recentOps = demoService.getRecentOperations();

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Page Header
              _buildHeader(context),
              const SizedBox(height: 24),

              // Quick Stats Grid
              _buildStatsGrid(stats),
              const SizedBox(height: 24),

              // Main content row
              LayoutBuilder(
                builder: (context, constraints) {
                  if (constraints.maxWidth > 900) {
                    return Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          flex: 3,
                          child: _buildRecentOperations(context, recentOps),
                        ),
                        const SizedBox(width: 20),
                        Expanded(
                          flex: 2,
                          child: Column(
                            children: [
                              _buildSecurityStatus(stats),
                              const SizedBox(height: 20),
                              _buildQuickActions(context, controller),
                            ],
                          ),
                        ),
                      ],
                    );
                  }
                  return Column(
                    children: [
                      _buildRecentOperations(context, recentOps),
                      const SizedBox(height: 20),
                      _buildSecurityStatus(stats),
                      const SizedBox(height: 20),
                      _buildQuickActions(context, controller),
                    ],
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeader(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Dashboard',
                style: GoogleFonts.outfit(
                  color: AppTheme.textPrimary,
                  fontSize: 28,
                  fontWeight: FontWeight.w800,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'Secure Media Sanitization — Overview',
                style: GoogleFonts.inter(
                  color: AppTheme.textSecondary,
                  fontSize: 14,
                ),
              ),
            ],
          ),
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          decoration: BoxDecoration(
            color: AppTheme.accentGold.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.3)),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.science, color: AppTheme.accentGold, size: 16),
              const SizedBox(width: 8),
              Text(
                'DEMO MODE',
                style: GoogleFonts.outfit(
                  color: AppTheme.accentGold,
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildStatsGrid(DemoStats stats) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final crossCount = constraints.maxWidth > 900
            ? 4
            : constraints.maxWidth > 600
                ? 2
                : 2;
        final items = [
          _StatItem(
            label: 'Detected Devices',
            value: '${stats.totalDevices}',
            icon: Icons.dns,
            color: AppTheme.accentBlue,
            subtitle: '${stats.totalStorageGb} GB total',
          ),
          _StatItem(
            label: 'Ready',
            value: '${stats.readyDevices}',
            icon: Icons.check_circle_outline,
            color: AppTheme.accentEmerald,
            subtitle: 'Sanitization available',
          ),
          _StatItem(
            label: 'Needs Attention',
            value: '${stats.attentionDevices}',
            icon: Icons.warning_amber,
            color: stats.attentionDevices > 0 ? AppTheme.accentOrange : AppTheme.textMuted,
            subtitle: stats.attentionDevices > 0
                ? 'Insufficient capability'
                : 'All devices clear',
          ),
          _StatItem(
            label: 'Certificates',
            value: '${stats.certificatesGenerated}',
            icon: Icons.description,
            color: AppTheme.accentGold,
            subtitle: '${stats.verifiedCount} verified',
          ),
        ];

        return GridView.count(
          crossAxisCount: crossCount,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          crossAxisSpacing: 16,
          mainAxisSpacing: 16,
          childAspectRatio: 2.8,
          children: items.map((item) => _buildStatCard(item)).toList(),
        );
      },
    );
  }

  Widget _buildStatCard(_StatItem item) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(
                  item.label,
                  style: GoogleFonts.outfit(
                    color: AppTheme.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 2),
                Text(
                  item.subtitle,
                  style: GoogleFonts.inter(
                    color: AppTheme.textMuted,
                    fontSize: 10,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: item.color.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(item.icon, color: item.color, size: 18),
          ),
          const SizedBox(width: 8),
          Text(
            item.value,
            style: GoogleFonts.outfit(
              color: item.color,
              fontSize: 26,
              fontWeight: FontWeight.w800,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRecentOperations(BuildContext context, List<DemoOperation> ops) {
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
              const Icon(Icons.history, color: AppTheme.accentGold, size: 20),
              const SizedBox(width: 10),
              Text(
                'Recent Operations',
                style: GoogleFonts.outfit(
                  color: AppTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const Spacer(),
              Text(
                '${ops.length} total',
                style: GoogleFonts.inter(
                  color: AppTheme.textMuted,
                  fontSize: 12,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          const Divider(color: AppTheme.surfaceBorder, height: 1),
          const SizedBox(height: 8),
          ...ops.map((op) => _buildOperationRow(op)),
        ],
      ),
    );
  }

  Widget _buildOperationRow(DemoOperation op) {
    Color statusColor;
    IconData statusIcon;
    switch (op.status) {
      case 'Verified':
        statusColor = AppTheme.accentEmerald;
        statusIcon = Icons.check_circle;
        break;
      case 'Failed':
        statusColor = AppTheme.accentRose;
        statusIcon = Icons.error;
        break;
      case 'Insufficient Assurance':
        statusColor = AppTheme.accentOrange;
        statusIcon = Icons.warning;
        break;
      default:
        statusColor = AppTheme.textMuted;
        statusIcon = Icons.hourglass_empty;
    }

    final timeStr = DateFormat('MMM d, HH:mm').format(op.timestamp);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: statusColor.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(statusIcon, color: statusColor, size: 18),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  op.deviceName,
                  style: GoogleFonts.inter(
                    color: AppTheme.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                Text(
                  '${op.mediaType} • ${op.method}',
                  style: GoogleFonts.inter(
                    color: AppTheme.textMuted,
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: statusColor.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  op.status,
                  style: GoogleFonts.inter(
                    color: statusColor,
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              const SizedBox(height: 4),
              Text(
                timeStr,
                style: GoogleFonts.inter(
                  color: AppTheme.textMuted,
                  fontSize: 10,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityStatus(DemoStats stats) {
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
              const Icon(Icons.security, color: AppTheme.accentEmerald, size: 20),
              const SizedBox(width: 10),
              Text(
                'Security Status',
                style: GoogleFonts.outfit(
                  color: AppTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          _buildStatusRow('Sanitizations Completed', '${stats.completedSanitizations}', AppTheme.accentBlue),
          _buildStatusRow('Verified', '${stats.verifiedCount}', AppTheme.accentEmerald),
          _buildStatusRow('Certificates Issued', '${stats.certificatesGenerated}', AppTheme.accentGold),
          _buildStatusRow('Pending Attention', '${stats.attentionDevices}',
              stats.attentionDevices > 0 ? AppTheme.accentOrange : AppTheme.accentEmerald),
        ],
      ),
    );
  }

  Widget _buildStatusRow(String label, String value, Color color) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: GoogleFonts.inter(color: AppTheme.textSecondary, fontSize: 13),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              value,
              style: GoogleFonts.outfit(
                color: color,
                fontSize: 14,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQuickActions(BuildContext context, SanitizationController controller) {
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
          Text(
            'Quick Actions',
            style: GoogleFonts.outfit(
              color: AppTheme.textPrimary,
              fontSize: 16,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              icon: const Icon(Icons.search, size: 18),
              label: const Text('SCAN DEVICES'),
              onPressed: () {
                controller.refreshDevices();
                context.go('/devices');
              },
            ),
          ),
          const SizedBox(height: 10),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
              icon: const Icon(Icons.cleaning_services, size: 18),
              label: const Text('NEW SANITIZATION'),
              onPressed: () => context.go('/sanitize'),
            ),
          ),
          const SizedBox(height: 10),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
              icon: const Icon(Icons.psychology, size: 18),
              label: const Text('ASK AI ASSISTANT'),
              onPressed: () => context.go('/ai-assistant'),
            ),
          ),
        ],
      ),
    );
  }
}

class _StatItem {
  final String label;
  final String value;
  final IconData icon;
  final Color color;
  final String subtitle;

  const _StatItem({
    required this.label,
    required this.value,
    required this.icon,
    required this.color,
    required this.subtitle,
  });
}
