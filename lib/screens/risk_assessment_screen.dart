import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../models/device_profile.dart';
import '../models/sanitization_job.dart';
import '../services/sanitization_controller.dart';
import '../widgets/step_indicator.dart';
import '../widgets/theme.dart';

class RiskAssessmentScreen extends StatelessWidget {
  const RiskAssessmentScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final device = controller.selectedDevice;

    if (device == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Risk Assessment')),
        body: const Center(child: Text('No device selected.')),
      );
    }

    final job = controller.currentJob;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Risk Assessment'),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Step Progress Wizard Header
              const StepIndicator(currentStep: 2),
              const SizedBox(height: 16),

              // Target Device Brief Banner
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppTheme.surfaceDark,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: device.isSystemDisk ? AppTheme.accentRose : AppTheme.surfaceBorder,
                    width: device.isSystemDisk ? 2 : 1,
                  ),
                ),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: AppTheme.accentGold.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: const Icon(Icons.storage, color: AppTheme.accentGold, size: 24),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            device.name,
                            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                          ),
                          Text(
                            'S/N: ${device.serialNumber} • ${device.mediaType.displayName} • ${device.formattedCapacity}',
                            style: const TextStyle(color: AppTheme.textSecondary, fontSize: 12),
                          ),
                        ],
                      ),
                    ),
                    if (device.isSystemDisk)
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: AppTheme.accentRose.withValues(alpha: 0.2),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: AppTheme.accentRose),
                        ),
                        child: const Text(
                          'SYSTEM DISK',
                          style: TextStyle(color: AppTheme.accentRose, fontSize: 10, fontWeight: FontWeight.bold),
                        ),
                      ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              const Text(
                'INPUT RISK PARAMETERS',
                style: TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 11,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.0,
                ),
              ),
              const SizedBox(height: 12),

              // Sensitivity Selector
              _buildDropdownCard(
                context: context,
                title: '1. Data Sensitivity Level',
                subtitle: 'Weighted 50% of risk score · Security sensitivity tier of residual data on media',
                icon: Icons.shield_outlined,
                child: DropdownButtonFormField<DataSensitivity>(
                  initialValue: controller.dataSensitivity,
                  decoration: const InputDecoration(contentPadding: EdgeInsets.symmetric(horizontal: 14, vertical: 10)),
                  items: [
                    DropdownMenuItem(value: DataSensitivity.public, child: _buildDropdownLabel('Public / Unclassified Data', 'Weight: 0.0')),
                    DropdownMenuItem(value: DataSensitivity.internal, child: _buildDropdownLabel('Internal Operational Records', 'Weight: 0.33')),
                    DropdownMenuItem(value: DataSensitivity.confidential, child: _buildDropdownLabel('Confidential / PII / Financial', 'Weight: 0.66')),
                    DropdownMenuItem(value: DataSensitivity.restricted, child: _buildDropdownLabel('Restricted / Intellectual Property', 'Weight: 1.0')),
                  ],
                  onChanged: (val) => controller.setRiskInputs(sensitivity: val),
                ),
              ),
              const SizedBox(height: 14),

              // Device Condition Selector
              _buildDropdownCard(
                context: context,
                title: '2. Device Integrity',
                subtitle: 'Weighted 20% of risk score · Physical condition and firmware SMART diagnostics',
                icon: Icons.health_and_safety_outlined,
                child: DropdownButtonFormField<DeviceCondition>(
                  initialValue: controller.deviceCondition,
                  decoration: const InputDecoration(contentPadding: EdgeInsets.symmetric(horizontal: 14, vertical: 10)),
                  items: [
                    DropdownMenuItem(value: DeviceCondition.functional, child: _buildDropdownLabel('Functional — Fully Operational', 'Weight: 0.0')),
                    DropdownMenuItem(value: DeviceCondition.degraded, child: _buildDropdownLabel('Degraded — Intermittent SMART Alerts', 'Weight: 0.5')),
                    DropdownMenuItem(value: DeviceCondition.endOfLife, child: _buildDropdownLabel('End of Life — Non-Bootable / Dead Sector Pool', 'Weight: 1.0')),
                  ],
                  onChanged: (val) => controller.setRiskInputs(condition: val),
                ),
              ),
              const SizedBox(height: 14),

              // Disposal Path Selector
              _buildDropdownCard(
                context: context,
                title: '3. Asset Disposal Channel',
                subtitle: 'Weighted 30% of risk score · Intended lifecycle destination post-sanitization',
                icon: Icons.alt_route_outlined,
                child: DropdownButtonFormField<DisposalPath>(
                  initialValue: controller.disposalPath,
                  decoration: const InputDecoration(contentPadding: EdgeInsets.symmetric(horizontal: 14, vertical: 10)),
                  items: [
                    DropdownMenuItem(value: DisposalPath.internalReuse, child: _buildDropdownLabel('Internal Redeployment / Reuse', 'Weight: 0.0')),
                    DropdownMenuItem(value: DisposalPath.externalResale, child: _buildDropdownLabel('External Resale / Secondary Market', 'Weight: 0.4')),
                    DropdownMenuItem(value: DisposalPath.recycling, child: _buildDropdownLabel('E-Waste Recycling Partner', 'Weight: 0.8')),
                    DropdownMenuItem(value: DisposalPath.physicalDestruction, child: _buildDropdownLabel('Mandatory Physical Destruction', 'Weight: 1.0')),
                  ],
                  onChanged: (val) => controller.setRiskInputs(path: val),
                ),
              ),
              const SizedBox(height: 20),

              // Dynamic Risk Calculation Panel
              if (job != null) ...[
                Container(
                  padding: const EdgeInsets.all(18),
                  decoration: BoxDecoration(
                    color: AppTheme.surfaceDark,
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: _getRiskColor(job.riskScore).withValues(alpha: 0.5)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(10),
                            decoration: BoxDecoration(
                              color: _getRiskColor(job.riskScore).withValues(alpha: 0.15),
                              shape: BoxShape.circle,
                            ),
                            child: Icon(Icons.analytics, color: _getRiskColor(job.riskScore), size: 22),
                          ),
                          const SizedBox(width: 12),
                          Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'Risk Score: ${(job.riskScore * 100).toStringAsFixed(1)}%',
                                style: TextStyle(
                                  fontSize: 18,
                                  fontWeight: FontWeight.bold,
                                  color: _getRiskColor(job.riskScore),
                                ),
                              ),
                              const Text(
                                'Evaluated via weighted risk formula',
                                style: TextStyle(fontSize: 11, color: AppTheme.textMuted),
                              ),
                            ],
                          ),
                          const Spacer(),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                            decoration: BoxDecoration(
                              color: _getRiskColor(job.riskScore).withValues(alpha: 0.2),
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(color: _getRiskColor(job.riskScore)),
                            ),
                            child: Text(
                              job.targetCategory.displayName.split(' ')[0],
                              style: TextStyle(
                                color: _getRiskColor(job.riskScore),
                                fontWeight: FontWeight.bold,
                                fontSize: 12,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 14),
                      ClipRRect(
                        borderRadius: BorderRadius.circular(6),
                        child: LinearProgressIndicator(
                          value: job.riskScore,
                          minHeight: 8,
                          backgroundColor: AppTheme.surfaceCard,
                          valueColor: AlwaysStoppedAnimation<Color>(_getRiskColor(job.riskScore)),
                        ),
                      ),
                      const SizedBox(height: 12),
                      Text(
                        job.explanationText,
                        style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.4),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 24),

                // Navigation Buttons Row
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        icon: const Icon(Icons.arrow_back, size: 18),
                        label: const Text('CHANGE ASSET'),
                        onPressed: () => context.go('/devices'),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      flex: 2,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.arrow_forward, size: 18),
                        label: const Text('SELECT SANITIZATION METHOD'),
                        onPressed: () {
                          context.go('/sanitize/workflow');
                        },
                      ),
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Color _getRiskColor(double score) {
    if (score < 0.34) return AppTheme.accentEmerald;
    if (score < 0.70) return AppTheme.accentGold;
    return AppTheme.accentRose;
  }

  Widget _buildDropdownCard({
    required BuildContext context,
    required String title,
    required String subtitle,
    required IconData icon,
    required Widget child,
  }) {
    return Container(
      padding: const EdgeInsets.all(16),
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
              Icon(icon, color: AppTheme.accentGold, size: 18),
              const SizedBox(width: 8),
              Text(
                title,
                style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14, color: AppTheme.textPrimary),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(subtitle, style: const TextStyle(color: AppTheme.textMuted, fontSize: 11)),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }

  /// Builds a dropdown menu item with primary plain-language label and
  /// secondary smaller muted weight text.
  Widget _buildDropdownLabel(String primary, String secondary) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          primary,
          style: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w500,
            color: AppTheme.textPrimary,
          ),
        ),
        Text(
          secondary,
          style: const TextStyle(
            fontSize: 10,
            color: AppTheme.textMuted,
          ),
        ),
      ],
    );
  }
}
