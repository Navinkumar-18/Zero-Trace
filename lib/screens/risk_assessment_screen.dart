import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../models/device_profile.dart';
import '../models/sanitization_job.dart';
import '../services/sanitization_controller.dart';
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
        title: const Text('Algorithm 4 — Risk Assessment'),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Device Brief Header Card
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppTheme.surfaceDark,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: AppTheme.surfaceBorder),
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
                            '${device.mediaType.displayName} • ${device.formattedCapacity}',
                            style: const TextStyle(color: AppTheme.textSecondary, fontSize: 12),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              const Text(
                'RISK SCORE INPUT PARAMETERS',
                style: TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.0,
                ),
              ),
              const SizedBox(height: 12),

              // Sensitivity Dropdown Card
              _buildDropdownCard(
                context: context,
                title: '1. Data Sensitivity Classification',
                subtitle: 'Select security tier of data stored on asset',
                icon: Icons.shield,
                child: DropdownButtonFormField<DataSensitivity>(
                  initialValue: controller.dataSensitivity,
                  decoration: const InputDecoration(contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8)),
                  items: const [
                    DropdownMenuItem(value: DataSensitivity.public, child: Text('Public / Non-Sensitive Data')),
                    DropdownMenuItem(value: DataSensitivity.internal, child: Text('Internal Operational Data')),
                    DropdownMenuItem(value: DataSensitivity.confidential, child: Text('Confidential / PII / Financial')),
                    DropdownMenuItem(value: DataSensitivity.restricted, child: Text('Restricted / Critical Intellectual Property')),
                  ],
                  onChanged: (val) => controller.setRiskInputs(sensitivity: val),
                ),
              ),
              const SizedBox(height: 14),

              // Device Condition Dropdown Card
              _buildDropdownCard(
                context: context,
                title: '2. Asset Operational Condition',
                subtitle: 'Assess physical & firmware integrity',
                icon: Icons.health_and_safety,
                child: DropdownButtonFormField<DeviceCondition>(
                  initialValue: controller.deviceCondition,
                  decoration: const InputDecoration(contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8)),
                  items: const [
                    DropdownMenuItem(value: DeviceCondition.functional, child: Text('Functional (No bad sectors)')),
                    DropdownMenuItem(value: DeviceCondition.degraded, child: Text('Degraded (Intermittent SMART warnings)')),
                    DropdownMenuItem(value: DeviceCondition.endOfLife, child: Text('End of Life / Non-Bootable Controller')),
                  ],
                  onChanged: (val) => controller.setRiskInputs(condition: val),
                ),
              ),
              const SizedBox(height: 14),

              // Disposal Path Dropdown Card
              _buildDropdownCard(
                context: context,
                title: '3. Asset Disposal Channel',
                subtitle: 'Intended destination post-sanitization',
                icon: Icons.alt_route,
                child: DropdownButtonFormField<DisposalPath>(
                  initialValue: controller.disposalPath,
                  decoration: const InputDecoration(contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8)),
                  items: const [
                    DropdownMenuItem(value: DisposalPath.internalReuse, child: Text('Internal Redeployment / Reuse')),
                    DropdownMenuItem(value: DisposalPath.externalResale, child: Text('External Secondary Resale / Donation')),
                    DropdownMenuItem(value: DisposalPath.recycling, child: Text('E-Waste Recycling Facility')),
                    DropdownMenuItem(value: DisposalPath.physicalDestruction, child: Text('Mandatory Physical Destruction')),
                  ],
                  onChanged: (val) => controller.setRiskInputs(path: val),
                ),
              ),
              const SizedBox(height: 20),

              // Dynamic Risk Score Result Panel
              if (job != null) ...[
                Container(
                  padding: const EdgeInsets.all(16),
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
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: _getRiskColor(job.riskScore).withValues(alpha: 0.15),
                              shape: BoxShape.circle,
                            ),
                            child: Icon(Icons.analytics, color: _getRiskColor(job.riskScore), size: 20),
                          ),
                          const SizedBox(width: 10),
                          Text(
                            'Calculated Risk Score: ${(job.riskScore * 100).toStringAsFixed(1)}%',
                            style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                              color: _getRiskColor(job.riskScore),
                            ),
                          ),
                          const Spacer(),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                            decoration: BoxDecoration(
                              color: _getRiskColor(job.riskScore).withValues(alpha: 0.15),
                              borderRadius: BorderRadius.circular(12),
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
                      const SizedBox(height: 10),
                      Text(
                        job.explanationText,
                        style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.4),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 24),

                // Action Button
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    icon: const Icon(Icons.psychology, size: 20),
                    label: const Text('COMPUTE METHOD RECOMMENDATION'),
                    onPressed: () {
                      context.push('/workflow');
                    },
                  ),
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
}
