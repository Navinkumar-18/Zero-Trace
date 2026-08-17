import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';

class ResultsScreen extends StatelessWidget {
  const ResultsScreen({super.key});

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

    return Scaffold(
      appBar: AppBar(
        title: const Text('Algorithm 3 — Verification Evidence'),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Status Header Banner
              Container(
                padding: const EdgeInsets.all(16),
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
                      size: 32,
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
                    const Text(
                      'MASTER EVIDENCE SHA-256 HASH',
                      style: TextStyle(color: AppTheme.textMuted, fontSize: 11, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 6),
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
                  color: Colors.black,
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
                      '• Evaluates logical sector state across 50 pseudo-random LBA offsets.\n• Confirms firmware controller status payload response matches NIST SP 800-88r2 standards.',
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
                    context.push('/certificate');
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
