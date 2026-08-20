import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../models/sanitization_job.dart';
import '../services/sanitization_controller.dart';
import '../widgets/step_indicator.dart';
import '../widgets/theme.dart';
import '../widgets/confirmation_dialog.dart';

class SanitizationWorkflowScreen extends StatelessWidget {
  const SanitizationWorkflowScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final job = controller.currentJob;
    final policy = controller.lastPolicyResult;

    if (job == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Sanitization Plan')),
        body: const Center(child: Text('No active job found.')),
      );
    }

    final isAllowed = policy?.isAllowed ?? false;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Method Selection'),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Step Progress Wizard Header
              const StepIndicator(currentStep: 3),
              const SizedBox(height: 16),

              // Standard Compliance Banner
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppTheme.accentGold.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.4)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.verified_user_outlined, color: AppTheme.accentGold, size: 26),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'COMPLIANCE STANDARD REFERENCE',
                            style: TextStyle(color: AppTheme.accentGold, fontSize: 10, fontWeight: FontWeight.bold),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            job.standardReference,
                            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14, color: AppTheme.textPrimary),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // Recommended Method Card
              Container(
                padding: const EdgeInsets.all(20),
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
                        Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: AppTheme.accentBlue.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: const Icon(Icons.cleaning_services, color: AppTheme.accentBlue, size: 26),
                        ),
                        const SizedBox(width: 14),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Text(
                                'RECOMMENDED TECHNIQUE',
                                style: TextStyle(color: AppTheme.textMuted, fontSize: 11, fontWeight: FontWeight.bold),
                              ),
                              Text(
                                job.recommendedMethod.displayName,
                                style: const TextStyle(
                                  fontSize: 18,
                                  fontWeight: FontWeight.bold,
                                  color: AppTheme.accentGold,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    const Divider(color: AppTheme.surfaceBorder),
                    const SizedBox(height: 12),
                    const Text(
                      'Technical Mechanism & Operational Scope:',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: AppTheme.textPrimary),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      job.explanationText,
                      style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.5),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // Policy Layer Safety Wall Status Card
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: isAllowed
                      ? AppTheme.accentEmerald.withValues(alpha: 0.1)
                      : AppTheme.accentRose.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: isAllowed
                        ? AppTheme.accentEmerald.withValues(alpha: 0.4)
                        : AppTheme.accentRose.withValues(alpha: 0.4),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(
                          isAllowed ? Icons.gavel : Icons.block,
                          color: isAllowed ? AppTheme.accentEmerald : AppTheme.accentRose,
                          size: 22,
                        ),
                        const SizedBox(width: 10),
                        Text(
                          isAllowed ? 'POLICY LAYER APPROVED' : 'POLICY LAYER REJECTED',
                          style: TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.bold,
                            color: isAllowed ? AppTheme.accentEmerald : AppTheme.accentRose,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      policy?.policyMessage ?? 'Validating policy layer...',
                      style: const TextStyle(fontSize: 12, color: AppTheme.textSecondary),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              // Action Buttons Row
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      icon: const Icon(Icons.arrow_back, size: 18),
                      label: const Text('BACK'),
                      onPressed: () => context.go('/sanitize'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    flex: 2,
                    child: ElevatedButton.icon(
                      icon: const Icon(Icons.play_arrow, size: 22),
                      label: Text(isAllowed ? 'START PIPELINE' : 'BLOCKED BY POLICY'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: isAllowed ? AppTheme.accentGold : AppTheme.surfaceBorder,
                        foregroundColor: isAllowed ? Colors.white : AppTheme.textMuted,
                      ),
                      onPressed: isAllowed
                          ? () async {
                              final confirmed = await ConfirmationDialog.show(
                                context,
                                device: job.device,
                                method: job.recommendedMethod,
                                nistCategory: job.targetCategory.displayName,
                              );
                              if (confirmed) {
                                controller.runSanitizationPipeline();
                                if (context.mounted) {
                                  context.go('/sanitize/progress');
                                }
                              }
                            }
                          : null,
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
}
