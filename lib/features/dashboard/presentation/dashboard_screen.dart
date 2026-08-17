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
    final isRealMode = controller.isRealMode;

    final demoService = DemoDataService();
    final stats = _getStats(controller);
    final recentOps = isRealMode
        ? _getRealRecentOps(controller)
        : demoService.getRecentOperations();

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Page Header
              _buildHeader(context, isRealMode),
              const SizedBox(height: 24),

              // Featured Hero Banner Card (Figma Smart Cleanup Banner)
              _buildSmartCleanupBanner(context),
              const SizedBox(height: 24),

              // Quick Stats Grid
              _buildStatsGrid(stats),
              const SizedBox(height: 24),

              // Main content grid
              LayoutBuilder(
                builder: (context, constraints) {
                  if (constraints.maxWidth > 900) {
                    return Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          flex: 3,
                          child: Column(
                            children: [
                              _buildStorageBreakdownCard(context),
                              const SizedBox(height: 20),
                              _buildRecentOperations(context, recentOps, isRealMode),
                            ],
                          ),
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
                      _buildStorageBreakdownCard(context),
                      const SizedBox(height: 20),
                      _buildRecentOperations(context, recentOps, isRealMode),
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

  DemoStats _getStats(SanitizationController controller) {
    final devices = controller.devices;
    final isRealMode = controller.isRealMode;

    if (!isRealMode) {
      return DemoDataService().getStats(devices);
    }

    final totalCapacityBytes = devices.fold<int>(0, (sum, d) => sum + d.capacityBytes);
    final totalGb = (totalCapacityBytes / (1024 * 1024 * 1024)).round();
    final attentionCount = devices.where((d) =>
        d.isSystemDisk ||
        d.hpaDcoPresent ||
        (!d.supportsAtaSanitize &&
            !d.supportsNvmeSanitize &&
            !d.supportsEmmcSanitize &&
            !d.supportsAtaSecureErase &&
            !d.isHardwareEncrypted)).length;
    final readyCount = devices.length - attentionCount;

    final hasCert = controller.completedCertificate != null;
    final completedCount = hasCert ? 1 : 0;
    final verifiedCount = (hasCert && controller.completedCertificate!.result == 'SUCCESS') ? 1 : 0;
    final certCount = hasCert ? 1 : 0;

    return DemoStats(
      totalDevices: devices.length,
      readyDevices: readyCount,
      attentionDevices: attentionCount,
      completedSanitizations: completedCount,
      verifiedCount: verifiedCount,
      certificatesGenerated: certCount,
      totalStorageGb: totalGb,
    );
  }

  List<DemoOperation> _getRealRecentOps(SanitizationController controller) {
    if (controller.completedCertificate != null) {
      final cert = controller.completedCertificate!;
      return [
        DemoOperation(
          deviceName: cert.deviceModel,
          mediaType: cert.mediaType,
          method: cert.method,
          status: cert.result == 'SUCCESS' ? 'Verified' : 'Failed',
          timestamp: cert.endTime,
          certificateId: cert.certificateId,
        ),
      ];
    }
    return [];
  }

  Widget _buildHeader(BuildContext context, bool isRealMode) {
    final badgeColor = isRealMode ? AppTheme.accentEmerald : AppTheme.accentGold;
    final badgeIcon = isRealMode ? Icons.memory : Icons.science;
    final badgeText = isRealMode ? 'REAL HARDWARE MODE' : 'DEMO MODE';

    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Private Storage',
                style: GoogleFonts.inter(
                  color: AppTheme.textPrimary,
                  fontSize: 28,
                  fontWeight: FontWeight.w800,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'Clean, secure and private device storage.',
                style: GoogleFonts.inter(
                  color: AppTheme.accentEmerald,
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          decoration: BoxDecoration(
            color: AppTheme.accentEmeraldLight,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppTheme.accentEmerald.withValues(alpha: 0.3)),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(badgeIcon, color: badgeColor, size: 16),
              const SizedBox(width: 8),
              Text(
                badgeText,
                style: GoogleFonts.inter(
                  color: badgeColor,
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

  Widget _buildSmartCleanupBanner(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color: AppTheme.accentEmeraldLight,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              'SMART CLEANUP READY',
              style: GoogleFonts.inter(
                color: AppTheme.accentEmerald,
                fontSize: 11,
                fontWeight: FontWeight.w700,
                letterSpacing: 0.5,
              ),
            ),
          ),
          const SizedBox(height: 12),
          Text(
            'Reclaim up to 12.6 GB',
            style: GoogleFonts.inter(
              color: AppTheme.textPrimary,
              fontSize: 32,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'Quick scan found safe-to-remove cache, duplicates and leftover files.',
            style: GoogleFonts.inter(
              color: AppTheme.textSecondary,
              fontSize: 14,
            ),
          ),
          const SizedBox(height: 20),
          Row(
            children: [
              ElevatedButton.icon(
                icon: const Icon(Icons.flash_on, size: 18),
                label: const Text('Start Smart Scan'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.accentEmerald,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
                onPressed: () => context.go('/sanitize'),
              ),
              const SizedBox(width: 12),
              OutlinedButton.icon(
                icon: const Icon(Icons.tune, size: 18),
                label: const Text('Manage Scope'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: AppTheme.textPrimary,
                  side: const BorderSide(color: AppTheme.surfaceBorder),
                  padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
                onPressed: () => context.go('/sanitize'),
              ),
            ],
          ),
        ],
      ),
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
            color: AppTheme.accentEmerald,
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
            color: stats.attentionDevices > 0 ? AppTheme.accentGold : AppTheme.textMuted,
            subtitle: stats.attentionDevices > 0
                ? 'Protected disk'
                : 'All devices clear',
          ),
          _StatItem(
            label: 'Certificates',
            value: '${stats.certificatesGenerated}',
            icon: Icons.description_outlined,
            color: AppTheme.accentEmerald,
            subtitle: '${stats.verifiedCount} verified',
          ),
        ];

        return GridView.count(
          crossAxisCount: crossCount,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          crossAxisSpacing: 16,
          mainAxisSpacing: 16,
          childAspectRatio: 2.6,
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
                  style: GoogleFonts.inter(
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
                    color: AppTheme.textSecondary,
                    fontSize: 10,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: item.color.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(item.icon, color: item.color, size: 18),
          ),
          const SizedBox(width: 8),
          Text(
            item.value,
            style: GoogleFonts.inter(
              color: item.color,
              fontSize: 24,
              fontWeight: FontWeight.w800,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStorageBreakdownCard(BuildContext context) {
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
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'STORAGE BREAKDOWN',
                style: GoogleFonts.inter(
                  color: AppTheme.textSecondary,
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 0.5,
                ),
              ),
              InkWell(
                onTap: () => context.go('/devices'),
                child: Text(
                  'View largest files',
                  style: GoogleFonts.inter(
                    color: AppTheme.accentEmerald,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          // Progress bar representation
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: SizedBox(
              height: 12,
              child: Row(
                children: [
                  Expanded(flex: 25, child: Container(color: AppTheme.accentEmerald)),
                  const SizedBox(width: 2),
                  Expanded(flex: 14, child: Container(color: AppTheme.accentBlue)),
                  const SizedBox(width: 2),
                  Expanded(flex: 10, child: Container(color: AppTheme.accentGold)),
                  const SizedBox(width: 2),
                  Expanded(flex: 18, child: Container(color: AppTheme.textSecondary.withValues(alpha: 0.3))),
                  const SizedBox(width: 2),
                  Expanded(flex: 33, child: Container(color: AppTheme.surfaceCard)),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              _buildCategoryLegend('Documents', '31.6 GB (25%)', AppTheme.accentEmerald),
              const SizedBox(width: 16),
              _buildCategoryLegend('Downloads', '18.4 GB (14%)', AppTheme.accentBlue),
              const SizedBox(width: 16),
              _buildCategoryLegend('Cache & temp', '12.6 GB (10%)', AppTheme.accentGold),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildCategoryLegend(String label, String value, Color color) {
    return Row(
      children: [
        Container(
          width: 10,
          height: 10,
          decoration: BoxDecoration(
            color: color,
            borderRadius: BorderRadius.circular(3),
          ),
        ),
        const SizedBox(width: 6),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.inter(
                color: AppTheme.textPrimary,
                fontSize: 11,
                fontWeight: FontWeight.w600,
              ),
            ),
            Text(
              value,
              style: GoogleFonts.inter(
                color: AppTheme.textSecondary,
                fontSize: 10,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildRecentOperations(BuildContext context, List<DemoOperation> ops, bool isRealMode) {
    final accentColor = isRealMode ? AppTheme.accentEmerald : AppTheme.accentGold;

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
              Icon(Icons.history, color: accentColor, size: 20),
              const SizedBox(width: 10),
              Text(
                'Recent Operations',
                style: GoogleFonts.inter(
                  color: AppTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const Spacer(),
              Text(
                '${ops.length} total',
                style: GoogleFonts.inter(
                  color: AppTheme.textSecondary,
                  fontSize: 12,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          const Divider(color: AppTheme.surfaceBorder, height: 1),
          const SizedBox(height: 8),
          if (ops.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 24),
              child: Center(
                child: Column(
                  children: [
                    Icon(
                      Icons.storage_outlined,
                      size: 40,
                      color: AppTheme.textSecondary.withValues(alpha: 0.5),
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'No Physical Disk Operations Recorded Yet',
                      style: GoogleFonts.inter(
                        color: AppTheme.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Connected drives are scanned in real-time via lsblk.\nAttach a USB pendrive or external disk to perform sanitization.',
                      textAlign: TextAlign.center,
                      style: GoogleFonts.inter(
                        color: AppTheme.textSecondary,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
            )
          else
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
        statusColor = AppTheme.accentGold;
        statusIcon = Icons.warning;
        break;
      default:
        statusColor = AppTheme.textSecondary;
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
                    color: AppTheme.textSecondary,
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
                  color: AppTheme.textSecondary,
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
                style: GoogleFonts.inter(
                  color: AppTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          _buildStatusRow('Sanitizations Completed', '${stats.completedSanitizations}', AppTheme.accentEmerald),
          _buildStatusRow('Verified', '${stats.verifiedCount}', AppTheme.accentEmerald),
          _buildStatusRow('Certificates Issued', '${stats.certificatesGenerated}', AppTheme.accentEmerald),
          _buildStatusRow('Pending Attention', '${stats.attentionDevices}',
              stats.attentionDevices > 0 ? AppTheme.accentGold : AppTheme.accentEmerald),
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
              style: GoogleFonts.inter(
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
            style: GoogleFonts.inter(
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
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.accentEmerald,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
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
              style: OutlinedButton.styleFrom(
                foregroundColor: AppTheme.textPrimary,
                side: const BorderSide(color: AppTheme.surfaceBorder),
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
              onPressed: () => context.go('/sanitize'),
            ),
          ),
          const SizedBox(height: 10),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
              icon: const Icon(Icons.psychology, size: 18),
              label: const Text('ASK AI ASSISTANT'),
              style: OutlinedButton.styleFrom(
                foregroundColor: AppTheme.textPrimary,
                side: const BorderSide(color: AppTheme.surfaceBorder),
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
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
