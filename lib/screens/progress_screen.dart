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
        appBar: AppBar(title: const Text('Pipeline Execution')),
        body: const Center(child: Text('No active execution found.')),
      );
    }

    final isFinished = job.status == JobStatus.completed || job.status == JobStatus.failed;
    final isFailed = job.status == JobStatus.failed;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Orchestration Pipeline Execution'),
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

              // Target Asset Brief Card
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: AppTheme.surfaceDark,
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: AppTheme.surfaceBorder),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.dns, color: AppTheme.accentGold, size: 22),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'Target: ${job.device.name} [${job.device.serialNumber}]',
                        style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // Progress Circular Indicator
              Center(
                child: Column(
                  children: [
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
                    color: Colors.black,
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
                      context.push('/results');
                    },
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
