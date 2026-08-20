import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../models/sanitization_job.dart';
import '../services/sanitization_controller.dart';
import '../widgets/step_indicator.dart';
import '../widgets/theme.dart';

class ProgressScreen extends StatelessWidget {
  const ProgressScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final job = controller.currentJob;

    if (job == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Sanitization Progress')),
        body: const Center(child: Text('No active execution found.')),
      );
    }

    final isFinished = job.status == JobStatus.completed || job.status == JobStatus.failed;
    final isFailed = job.status == JobStatus.failed;
    final isSucceeded = job.status == JobStatus.completed;

    final devicePath = job.device.id.startsWith('real_')
        ? '/dev/${job.device.id.substring(5)}'
        : '/dev/sdb (Simulated)';

    return Scaffold(
      appBar: AppBar(
        title: const Text('Sanitization Progress'),
        automaticallyImplyLeading: !isFinished,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Step Progress Wizard Header
              const StepIndicator(currentStep: 4),
              const SizedBox(height: 16),

              // Target Asset Complete Summary Card
              Container(
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
                        const Icon(Icons.dns, color: AppTheme.accentGold, size: 24),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            job.device.name,
                            style: const TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: 15,
                              color: AppTheme.textPrimary,
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                          decoration: BoxDecoration(
                            color: AppTheme.codeBackground,
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(color: AppTheme.surfaceBorder),
                          ),
                          child: Text(
                            devicePath,
                            style: const TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                              color: AppTheme.accentBlue,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    const Divider(color: AppTheme.surfaceBorder),
                    const SizedBox(height: 8),
                    _buildMetaRow('Capacity:', job.device.formattedCapacity),
                    const SizedBox(height: 4),
                    _buildMetaRow('Sanitization Method:', job.recommendedMethod.displayName),
                    const SizedBox(height: 4),
                    _buildMetaRow('NIST Category:', job.targetCategory.displayName),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              // Progress Circular Indicator / Status Badge
              Center(
                child: Column(
                  children: [
                    if (isSucceeded)
                      Container(
                        margin: const EdgeInsets.only(bottom: 16),
                        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                        decoration: BoxDecoration(
                          color: AppTheme.accentEmerald.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(30),
                          border: Border.all(color: AppTheme.accentEmerald, width: 2),
                        ),
                        child: const Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.verified, color: AppTheme.accentEmerald, size: 24),
                            SizedBox(width: 8),
                            Text(
                              'SECURELY WIPED',
                              style: TextStyle(
                                color: AppTheme.accentEmerald,
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                                letterSpacing: 1.0,
                              ),
                            ),
                          ],
                        ),
                      )
                    else if (isFailed)
                      Container(
                        margin: const EdgeInsets.only(bottom: 16),
                        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                        decoration: BoxDecoration(
                          color: AppTheme.accentRose.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(30),
                          border: Border.all(color: AppTheme.accentRose, width: 2),
                        ),
                        child: const Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.gpp_bad, color: AppTheme.accentRose, size: 24),
                            SizedBox(width: 8),
                            Text(
                              'SANITIZATION FAILED',
                              style: TextStyle(
                                color: AppTheme.accentRose,
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                                letterSpacing: 1.0,
                              ),
                            ),
                          ],
                        ),
                      )
                    else
                      SizedBox(
                        width: 120,
                        height: 120,
                        child: Stack(
                          alignment: Alignment.center,
                          children: [
                            CircularProgressIndicator(
                              value: job.progress,
                              strokeWidth: 10,
                              backgroundColor: AppTheme.surfaceDark,
                              valueColor: AlwaysStoppedAnimation<Color>(
                                isFailed ? AppTheme.accentRose : AppTheme.accentGold,
                              ),
                            ),
                            Text(
                              '${(job.progress * 100).toInt()}%',
                              style: TextStyle(
                                fontSize: 26,
                                fontWeight: FontWeight.bold,
                                color: isFailed ? AppTheme.accentRose : AppTheme.textPrimary,
                              ),
                            ),
                          ],
                        ),
                      ),
                    const SizedBox(height: 16),
                    Text(
                      job.currentStageDescription,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                        color: isFailed ? AppTheme.accentRose : AppTheme.accentBlue,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              const Text(
                'LIVE PIPELINE LOGS & TELEMETRY STREAM',
                style: TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 11,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.0,
                ),
              ),
              const SizedBox(height: 8),

              // Log Stream Box
              Expanded(
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppTheme.codeBackground,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppTheme.surfaceBorder),
                  ),
                  child: ListView.builder(
                    itemCount: job.logs.length,
                    itemBuilder: (context, index) {
                      final log = job.logs[index];
                      Color logColor = AppTheme.textSecondary;
                      if (log.contains('ERROR')) {
                        logColor = AppTheme.accentRose;
                      } else if (log.contains('SUCCESS') || log.contains('VERIFICATION')) {
                        logColor = AppTheme.accentEmerald;
                      } else if (log.contains('POLICY') || log.contains('EXECUTION')) {
                        logColor = AppTheme.accentGold;
                      }

                      return Padding(
                        padding: const EdgeInsets.only(bottom: 4.0),
                        child: Text(
                          log,
                          style: TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 11,
                            color: logColor,
                          ),
                        ),
                      );
                    },
                  ),
                ),
              ),
              const SizedBox(height: 16),

              if (isFinished)
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    icon: const Icon(Icons.assessment, size: 20),
                    label: const Text('PROCEED TO VERIFICATION & CERTIFICATE'),
                    onPressed: () {
                      context.go('/verification');
                    },
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildMetaRow(String label, String value) {
    return Row(
      children: [
        Text(
          label + ' ',
          style: const TextStyle(
            fontSize: 12,
            color: AppTheme.textMuted,
            fontWeight: FontWeight.bold,
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: const TextStyle(
              fontSize: 12,
              color: AppTheme.textSecondary,
            ),
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}
