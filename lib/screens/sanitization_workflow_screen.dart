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
    final isDestroyRecommended = job.targetCategory == NistCategory.destroy ||
        job.recommendedMethod == SanitizationMethod.physicalDestructionRecommended ||
        job.recommendedMethod == SanitizationMethod.unsupportedFlagForDestroy;
    final hasOverriddenToSoftware = job.effectiveMethod != SanitizationMethod.physicalDestructionRecommended &&
        job.effectiveMethod != SanitizationMethod.unsupportedFlagForDestroy;
    final requiresAcknowledgment = isDestroyRecommended && hasOverriddenToSoftware;
    final isAcknowledged = job.destroyAcknowledged;
    final canStart = isAllowed && !controller.isJobRunning && (!requiresAcknowledgment || isAcknowledged);

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

                    // If physical destruction was recommended, offer manual override to overwrite
                    if (isDestroyRecommended) ...[
                      const SizedBox(height: 16),
                      const Divider(color: AppTheme.surfaceBorder),
                      const SizedBox(height: 12),
                      const Text(
                        'Method Override / Alternative:',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: AppTheme.textPrimary),
                      ),
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
                        decoration: BoxDecoration(
                          color: AppTheme.surfaceDark,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: AppTheme.surfaceBorder),
                        ),
                        child: DropdownButton<SanitizationMethod>(
                          value: job.effectiveMethod,
                          isExpanded: true,
                          underline: const SizedBox.shrink(),
                          dropdownColor: AppTheme.surfaceDark,
                          items: [
                            DropdownMenuItem(
                              value: job.recommendedMethod,
                              child: const Text(
                                'Physical Destruction (Recommended)',
                                style: TextStyle(color: AppTheme.accentRose, fontWeight: FontWeight.w600),
                              ),
                            ),
                            const DropdownMenuItem(
                              value: SanitizationMethod.singlePassOverwrite,
                              child: Text('Single-Pass Zero Overwrite (Clear only)'),
                            ),
                            const DropdownMenuItem(
                              value: SanitizationMethod.multiPassOverwrite,
                              child: Text('Multi-Pass Overwrite (Clear only)'),
                            ),
                          ],
                          onChanged: controller.isJobRunning
                              ? null
                              : (method) {
                                  controller.setOverriddenMethod(method);
                                },
                        ),
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // Destroy Acknowledgment Checkbox (when user selects overwrite despite Destroy recommendation)
              if (requiresAcknowledgment) ...[
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: AppTheme.accentOrange.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: AppTheme.accentOrange.withValues(alpha: 0.5)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Row(
                        children: [
                          Icon(Icons.warning_amber_rounded, color: AppTheme.accentOrange, size: 22),
                          SizedBox(width: 8),
                          Text(
                            'OPERATOR ACKNOWLEDGMENT REQUIRED',
                            style: TextStyle(
                              color: AppTheme.accentOrange,
                              fontWeight: FontWeight.bold,
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'NIST SP 800-88 specifies Physical Destruction for this media and sensitivity tier. Logical overwrite cannot reach wear-remapped or over-provisioned NAND blocks. Residual confidential data may remain on the device.',
                        style: TextStyle(fontSize: 12, color: AppTheme.textSecondary, height: 1.4),
                      ),
                      const SizedBox(height: 12),
                      Theme(
                        data: ThemeData(unselectedWidgetColor: AppTheme.accentOrange),
                        child: CheckboxListTile(
                          contentPadding: EdgeInsets.zero,
                          activeColor: AppTheme.accentOrange,
                          checkColor: Colors.black,
                          value: isAcknowledged,
                          title: const Text(
                            'I acknowledge this device may retain data',
                            style: TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.bold,
                              color: AppTheme.textPrimary,
                            ),
                          ),
                          onChanged: controller.isJobRunning
                              ? null
                              : (val) {
                                  controller.setDestroyAcknowledged(val ?? false);
                                },
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 20),
              ],

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
                      onPressed: () => context.go('/advanced/sanitize'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    flex: 2,
                    child: ElevatedButton.icon(
                      icon: const Icon(Icons.play_arrow, size: 22),
                      label: Text(
                        controller.isJobRunning
                            ? 'JOB ALREADY IN PROGRESS'
                            : (!isAllowed
                                ? 'BLOCKED BY POLICY'
                                : (requiresAcknowledgment && !isAcknowledged
                                    ? 'ACKNOWLEDGMENT REQUIRED'
                                    : 'START PIPELINE')),
                      ),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: canStart ? AppTheme.accentGold : AppTheme.surfaceBorder,
                        foregroundColor: canStart ? Colors.white : AppTheme.textMuted,
                      ),
                      onPressed: canStart
                          ? () async {
                              final confirmed = await ConfirmationDialog.show(
                                context,
                                device: job.device,
                                method: job.effectiveMethod,
                                nistCategory: job.effectiveNistCategoryDisplayName,
                              );
                              if (confirmed) {
                                controller.runSanitizationPipeline();
                                if (context.mounted) {
                                  context.go('/advanced/sanitize/progress');
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
