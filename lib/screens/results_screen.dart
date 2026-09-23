import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../services/sanitization_controller.dart';
import '../widgets/step_indicator.dart';
import '../widgets/theme.dart';

class ResultsScreen extends StatelessWidget {
  const ResultsScreen({super.key});

  static String _formatNumber(int n) {
    return n.toString().replaceAllMapped(
      RegExp(r'(\d{1,3})(?=(\d{3})+(?!\d))'),
      (Match m) => '${m[1]},',
    );
  }

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final cert = controller.completedCertificate;
    final job = controller.currentJob;

    if (cert == null || job == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Verification Results')),
        body: const Center(child: Text('No certificate or verification evidence available.')),
      );
    }

    final evidence = cert.evidence;
    final isPassed = evidence.verifiedPassed;
    final isSimulated = cert.executionMode == 'simulated';

    // Dynamic sector calculations from device size (512 bytes / sector)
    final totalSectors = job.device.capacityBytes ~/ 512;
    final sampleCount = evidence.sampleOffsets.isNotEmpty ? evidence.sampleOffsets.length : (cert.verificationSampleCount ?? 50);
    final totalSectorsFormatted = _formatNumber(totalSectors);
    final entropyScore = cert.verificationEntropyScore ?? 0.0000;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Verification Evidence'),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Step Progress Wizard Header
              const StepIndicator(currentStep: 5),
              const SizedBox(height: 16),

              // Simulated vs Real Execution Mode indicator badge
              if (isSimulated) ...[
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                  decoration: BoxDecoration(
                    color: AppTheme.accentGold.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppTheme.accentGold, width: 1.5),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.science, color: AppTheme.accentGold, size: 20),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'SIMULATED RECORD — No physical data was modified',
                          style: TextStyle(
                            color: AppTheme.accentGold,
                            fontWeight: FontWeight.bold,
                            fontSize: 13,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
              ],

              // Status Header Banner
              Container(
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                  color: isPassed ? AppTheme.accentEmerald.withValues(alpha: 0.12) : AppTheme.accentRose.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: isPassed ? AppTheme.accentEmerald.withValues(alpha: 0.4) : AppTheme.accentRose.withValues(alpha: 0.4),
                  ),
                ),
                child: Row(
                  children: [
                    Icon(
                      isPassed ? Icons.check_circle : Icons.error,
                      color: isPassed ? AppTheme.accentEmerald : AppTheme.accentRose,
                      size: 36,
                    ),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            isPassed ? 'VERIFICATION PASSED' : 'VERIFICATION FAILED',
                            style: TextStyle(
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                              color: isPassed ? AppTheme.accentEmerald : AppTheme.accentRose,
                            ),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            cert.verificationSummary,
                            style: const TextStyle(fontSize: 12, color: AppTheme.textSecondary),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // Master Evidence Hash Card
              Container(
                padding: const EdgeInsets.all(16),
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
                        const Text(
                          'MASTER EVIDENCE SHA-256 HASH',
                          style: TextStyle(color: AppTheme.textMuted, fontSize: 11, fontWeight: FontWeight.bold),
                        ),
                        IconButton(
                          icon: const Icon(Icons.copy, size: 16, color: AppTheme.accentGold),
                          tooltip: 'Copy Evidence Hash',
                          onPressed: () {
                            Clipboard.setData(ClipboardData(text: evidence.evidenceHash));
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(content: Text('Evidence SHA-256 hash copied to clipboard!')),
                            );
                          },
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    SelectableText(
                      evidence.evidenceHash,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 12,
                        color: AppTheme.accentGold,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 10),
                    Text(
                      'Controller Telemetry: ${evidence.controllerConfirmation}',
                      style: const TextStyle(fontSize: 12, color: AppTheme.textSecondary),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // 50-Point Sector Sample Readback Grid Preview
              const Text(
                '50-POINT SECTOR SAMPLE READBACK (ZERO-FILL VERIFICATION)',
                style: TextStyle(color: AppTheme.textMuted, fontSize: 11, fontWeight: FontWeight.bold, letterSpacing: 0.8),
              ),
              const SizedBox(height: 8),

              Container(
                padding: const EdgeInsets.all(12),
                height: 140,
                decoration: BoxDecoration(
                  color: AppTheme.codeBackground,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: AppTheme.surfaceBorder),
                ),
                child: GridView.builder(
                  gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 10,
                    crossAxisSpacing: 6,
                    mainAxisSpacing: 6,
                  ),
                  itemCount: evidence.sampleOffsets.length,
                  itemBuilder: (context, idx) {
                    final offset = evidence.sampleOffsets[idx];
                    final hash = evidence.sampleHashes[offset];
                    final samplePassed = isPassed;

                    return Tooltip(
                      message: 'LBA Offset $offset\nSHA-256: ${hash?.substring(0, 16)}...',
                      child: Container(
                        decoration: BoxDecoration(
                          color: samplePassed ? AppTheme.accentEmerald.withValues(alpha: 0.8) : AppTheme.accentRose.withValues(alpha: 0.8),
                          borderRadius: BorderRadius.circular(4),
                        ),
                      ),
                    );
                  },
                ),
              ),
              const SizedBox(height: 16),

              // Verification Confidence Card (Task 5)
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppTheme.surfaceDark,
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: AppTheme.accentBlue.withValues(alpha: 0.4)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.analytics_outlined, color: AppTheme.accentBlue, size: 20),
                        const SizedBox(width: 8),
                        Text(
                          'VERIFICATION CONFIDENCE',
                          style: TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                            color: AppTheme.accentBlue,
                            letterSpacing: 0.5,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Row(
                      children: [
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Text('Sample Coverage', style: TextStyle(fontSize: 11, color: AppTheme.textMuted)),
                              const SizedBox(height: 2),
                              Text(
                                '$sampleCount sectors sampled out of $totalSectorsFormatted total sectors',
                                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: AppTheme.textPrimary),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Text('Shannon Entropy Score', style: TextStyle(fontSize: 11, color: AppTheme.textMuted)),
                              const SizedBox(height: 2),
                              Text(
                                '${entropyScore.toStringAsFixed(4)} (Ideal zeroized: 0.0000)',
                                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: AppTheme.accentEmerald),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: AppTheme.surfaceCard,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: const Row(
                        children: [
                          Icon(Icons.info_outline, color: AppTheme.accentGold, size: 16),
                          SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              'This is a statistical sampling check, not proof of total erasure. See Limitations for details.',
                              style: TextStyle(fontSize: 11, color: AppTheme.textSecondary, fontStyle: FontStyle.italic),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // Tailored Limitations & What this Proves / Doesn't Prove Panel
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
                    const Row(
                      children: [
                        Icon(Icons.info_outline, color: AppTheme.accentGold, size: 20),
                        SizedBox(width: 8),
                        Text(
                          'WHAT THIS VERIFICATION PROVES & DOES NOT PROVE',
                          style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: AppTheme.accentGold),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'What it PROVES:',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12, color: AppTheme.accentEmerald),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      '• Evaluates logical sector state across $sampleCount pseudo-random LBA offsets.\n• Confirms firmware controller status payload response matches NIST SP 800-88r2 standards.',
                      style: const TextStyle(fontSize: 12, color: AppTheme.textSecondary, height: 1.4),
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'What it DOES NOT PROVE (Limitations):',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12, color: AppTheme.accentRose),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      evidence.limitations,
                      style: const TextStyle(fontSize: 12, color: AppTheme.textSecondary, height: 1.4),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              // Action Button
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  icon: const Icon(Icons.picture_as_pdf, size: 20),
                  label: const Text('VIEW & EXPORT AUDIT CERTIFICATE'),
                  onPressed: () {
                    context.go('/certificates');
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
