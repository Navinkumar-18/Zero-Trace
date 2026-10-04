import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:printing/printing.dart';

import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';
import 'error_messages.dart';

class SimpleCertificateDialog extends StatelessWidget {
  const SimpleCertificateDialog({super.key});

  static Future<void> show(BuildContext context) {
    return showDialog(
      context: context,
      builder: (_) => ChangeNotifierProvider.value(
        value: context.read<SanitizationController>(),
        child: const SimpleCertificateDialog(),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final cert = controller.completedCertificate;

    if (cert == null) {
      return Dialog(
        backgroundColor: AppTheme.surfaceDark,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        child: const Padding(
          padding: EdgeInsets.all(32),
          child: Text('No certificate available.',
              style: TextStyle(color: AppTheme.textMuted)),
        ),
      );
    }

    final passed = cert.evidence.verifiedPassed;
    final isSimulated = cert.executionMode == 'simulated';
    final isFailed = cert.result == 'FAILED';
    final isFlash = cert.mediaType.toLowerCase().contains('flash') ||
        cert.mediaType.toLowerCase().contains('usb') ||
        cert.mediaType.toLowerCase().contains('emmc');
    final badgeText = isFailed
        ? 'WIPE FAILED'
        : SimpleErrorMessages.wipeBadgeText(
            sanitizationCategory: cert.sanitizationCategory,
            isFlashMedia: isFlash,
            verificationPassed: passed,
          );
    final badgeColor = (passed && !isFailed)
        ? AppTheme.simpleSuccess
        : AppTheme.simpleDestructive;
    final flashCaveat = SimpleErrorMessages.flashCaveat(
      isFlashMedia: isFlash,
      sanitizationCategory: cert.sanitizationCategory,
    );

    return Dialog(
      backgroundColor: AppTheme.surfaceDark,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: Container(
        constraints: const BoxConstraints(maxWidth: 520, maxHeight: 650),
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Title
            Row(
              children: [
                Icon(
                  isFailed ? Icons.report_problem : Icons.description,
                  color: badgeColor,
                  size: 28,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    isFailed ? 'Failure Report' : 'Sanitization Certificate',
                    style: const TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: AppTheme.textPrimary,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),

            Expanded(
              child: SingleChildScrollView(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Simulated banner
                    if (isSimulated)
                      Container(
                        width: double.infinity,
                        padding:
                            const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        margin: const EdgeInsets.only(bottom: 12),
                        decoration: BoxDecoration(
                          color: AppTheme.accentGold.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: AppTheme.accentGold),
                        ),
                        child: const Row(
                          children: [
                            Icon(Icons.science, color: AppTheme.accentGold, size: 16),
                            SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                'SIMULATED — Not a valid sanitization record',
                                style: TextStyle(
                                  color: AppTheme.accentGold,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 11,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),

                    // FAILED banner
                    if (isFailed)
                      Container(
                        width: double.infinity,
                        padding:
                            const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        margin: const EdgeInsets.only(bottom: 12),
                        decoration: BoxDecoration(
                          color: AppTheme.accentRose.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: AppTheme.accentRose),
                        ),
                        child: const Row(
                          children: [
                            Icon(Icons.gpp_bad, color: AppTheme.accentRose, size: 16),
                            SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                'FAILED — This is a failure report, not a sanitization certificate. '
                                'The drive may still contain data.',
                                style: TextStyle(
                                  color: AppTheme.accentRose,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 11,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),

                    // Badge
                    Center(
                      child: Container(
                        padding:
                            const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        decoration: BoxDecoration(
                          color: badgeColor.withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(color: badgeColor, width: 1.5),
                        ),
                        child: Text(badgeText,
                            style: TextStyle(
                                color: badgeColor,
                                fontWeight: FontWeight.bold,
                                fontSize: 14)),
                      ),
                    ),
                    const SizedBox(height: 16),

                    // Certificate details
                    _row('Certificate ID:', cert.certificateId),
                    _row('Device:', '${cert.deviceModel} (${cert.deviceSerial})'),
                    _row('Method:', cert.method),
                    _row('Category:', cert.sanitizationCategory),
                    _row('Support Level:', cert.supportLevel),
                    _row('Standard:', cert.standardReference),
                    _row('Result:', cert.result),
                    _row('Time:',
                        cert.startTime.toLocal().toString().substring(0, 19)),

                    // Flash caveat
                    if (flashCaveat != null) ...[
                      const SizedBox(height: 8),
                      Text(flashCaveat,
                          style: const TextStyle(
                              color: AppTheme.accentGold,
                              fontSize: 11,
                              fontStyle: FontStyle.italic)),
                    ],

                    // Warning line from cert
                    if (cert.warningLine != null) ...[
                      const SizedBox(height: 8),
                      Text('⚠ ${cert.warningLine}',
                          style: const TextStyle(
                              color: AppTheme.accentGold, fontSize: 11)),
                    ],
                  ],
                ),
              ),
            ),

            const SizedBox(height: 16),

            // Actions
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    icon: const Icon(Icons.picture_as_pdf, size: 16),
                    label: Text(isFailed ? 'Download Report' : 'Download PDF',
                        style: const TextStyle(fontSize: 12)),
                    onPressed: () async {
                      final pdfBytes =
                          await controller.getPdfCertificateBytes();
                      if (pdfBytes != null && context.mounted) {
                        await Printing.sharePdf(
                          bytes: pdfBytes,
                          filename: '${cert.certificateId}.pdf',
                        );
                      }
                    },
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: ElevatedButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('Close'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _row(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 110,
            child: Text(label,
                style: const TextStyle(
                    fontSize: 11,
                    color: AppTheme.textMuted,
                    fontWeight: FontWeight.w600)),
          ),
          Expanded(
            child: Text(value,
                style: const TextStyle(
                    fontSize: 11, color: AppTheme.textPrimary)),
          ),
        ],
      ),
    );
  }
}
