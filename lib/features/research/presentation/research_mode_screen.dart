import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../widgets/theme.dart';

class ResearchModeScreen extends StatelessWidget {
  const ResearchModeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Text(
                'Research Mode',
                style: GoogleFonts.outfit(
                  color: AppTheme.textPrimary,
                  fontSize: 28,
                  fontWeight: FontWeight.w800,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'Technical foundations and academic references for sanitization decisions',
                style: GoogleFonts.inter(
                  color: AppTheme.textSecondary,
                  fontSize: 14,
                ),
              ),
              const SizedBox(height: 24),

              // PALES Section
              _buildResearchSection(
                title: 'PALES — SSD Secure Deletion Research',
                subtitle: 'Optimizing Secure Data Deletion in SSDs via Page Group and Reprogram Speedup',
                icon: Icons.memory,
                color: AppTheme.accentBlue,
                content: 'PALES demonstrates that SSD secure deletion is fundamentally different '
                    'from simple filesystem overwriting due to the internal architecture of '
                    'flash-based storage.',
                keyInsights: const [
                  _ResearchInsight(
                    title: 'Flash Translation Layer (FTL)',
                    detail: 'SSDs use an FTL to map logical block addresses to physical '
                        'NAND pages. The host OS cannot control which physical page receives '
                        'a write operation, making logical overwrite unreliable for sanitization.',
                  ),
                  _ResearchInsight(
                    title: 'Wear Leveling',
                    detail: 'The controller distributes writes across all NAND blocks to '
                        'extend drive lifespan. Previously written pages may retain original '
                        'data even after logical overwrite.',
                  ),
                  _ResearchInsight(
                    title: 'Garbage Collection',
                    detail: 'SSDs reclaim invalid pages asynchronously. Data marked for '
                        'deletion may physically persist until the GC cycle processes the '
                        'containing block.',
                  ),
                  _ResearchInsight(
                    title: 'Spare Blocks & Over-provisioning',
                    detail: 'A portion of flash capacity (typically 7-28%) is reserved by '
                        'the controller. These regions are not addressable via standard I/O '
                        'and may contain remnant data.',
                  ),
                ],
                implication: 'Zero Trace uses these research insights to justify media-aware '
                    'sanitization. When an SSD or NVMe device is detected, the recommendation '
                    'engine prefers device-supported sanitization commands that operate below '
                    'the FTL rather than simple logical overwriting.',
              ),
              const SizedBox(height: 24),

              // NIST Section
              _buildResearchSection(
                title: 'NIST SP 800-88 Rev. 2',
                subtitle: 'Guidelines for Media Sanitization',
                icon: Icons.verified_user,
                color: AppTheme.accentGold,
                content: 'The National Institute of Standards and Technology defines media '
                    'sanitization categories and guidelines for federal information systems.',
                keyInsights: const [
                  _ResearchInsight(
                    title: 'CLEAR',
                    detail: 'Logical techniques that protect against simple, non-invasive '
                        'data recovery attempts. Example: Full disk overwrite with zeros. '
                        'Appropriate for low-sensitivity data and internal reuse scenarios.',
                  ),
                  _ResearchInsight(
                    title: 'PURGE',
                    detail: 'Physical or logical techniques rendering data recovery infeasible '
                        'using state-of-the-art laboratory techniques. Examples: ATA Sanitize, '
                        'NVMe Sanitize, Cryptographic Erase. Required for confidential data '
                        'leaving organizational control.',
                  ),
                  _ResearchInsight(
                    title: 'DESTROY',
                    detail: 'Physical destruction rendering media unusable: disintegration, '
                        'incineration, shredding. Required for the highest classification data '
                        'or when device-level sanitization mechanisms are unavailable.',
                  ),
                  _ResearchInsight(
                    title: 'Cryptographic Erase',
                    detail: 'Destruction of the encryption key on self-encrypting devices (SEDs). '
                        'Can satisfy Purge requirements when properly implemented with TCG OPAL '
                        'or NVMe crypto erase support.',
                  ),
                ],
                implication: 'Zero Trace maps risk assessment inputs (data sensitivity, device '
                    'condition, disposal path) to NIST categories using a weighted scoring '
                    'algorithm. The recommendation engine selects methods appropriate to the '
                    'target category.',
              ),
              const SizedBox(height: 24),

              // EVSD Section
              _buildResearchSection(
                title: 'EVSD — Verifiable Secure Deletion',
                subtitle: 'Cryptographic verification and evidence integrity',
                icon: Icons.enhanced_encryption,
                color: AppTheme.accentEmerald,
                content: 'Research into Evidence-based Verifiable Secure Deletion explores '
                    'mechanisms for proving that deletion has occurred, using cryptographic '
                    'techniques.',
                keyInsights: const [
                  _ResearchInsight(
                    title: 'Cryptographic Deletion Evidence',
                    detail: 'Using hash chains and Merkle trees to create tamper-evident '
                        'records of deletion operations. The evidence itself can be verified '
                        'without access to the original data.',
                  ),
                  _ResearchInsight(
                    title: 'Hash-based Integrity',
                    detail: 'SHA-256 hashes protect the integrity of evidence records. '
                        'Important distinction: hashing proves the evidence has not been '
                        'modified — it does NOT prove physical erasure of underlying media.',
                  ),
                  _ResearchInsight(
                    title: 'Verification Sampling',
                    detail: 'Pseudo-random sector sampling across the full LBA range provides '
                        'statistical evidence of sanitization. 50-point readback verification '
                        'checks zero-fill state at distributed offsets.',
                  ),
                  _ResearchInsight(
                    title: 'Digital Signatures',
                    detail: 'ECDSA P-256 signatures on certificate payloads provide '
                        'non-repudiation and tamper detection. The verification process '
                        'can detect if any certificate field has been modified after issuance.',
                  ),
                ],
                implication: 'Zero Trace uses EVSD principles to generate cryptographically '
                    'signed sanitization certificates with SHA-256 evidence hashing and '
                    'ECDSA digital signatures. The certificate explicitly states what the '
                    'evidence proves and what it does not prove.',
              ),
              const SizedBox(height: 24),

              // IEEE 2883 Section
              _buildResearchSection(
                title: 'IEEE 2883:2022',
                subtitle: 'Standard for Sanitizing Storage',
                icon: Icons.gavel,
                color: AppTheme.accentOrange,
                content: 'IEEE 2883 provides detailed sanitization procedures for '
                    'different storage technologies including HDDs, SSDs, and NVMe devices.',
                keyInsights: const [
                  _ResearchInsight(
                    title: 'Technology-Specific Procedures',
                    detail: 'Unlike NIST which provides general guidelines, IEEE 2883 '
                        'specifies exact procedures per storage technology — ATA commands '
                        'for SATA devices, NVMe sanitize for NVMe devices, etc.',
                  ),
                  _ResearchInsight(
                    title: 'Verification Requirements',
                    detail: 'Defines verification procedures that should follow sanitization, '
                        'including controller status checks and sample readback verification.',
                  ),
                ],
                implication: 'Zero Trace references IEEE 2883:2022 alongside NIST SP 800-88 '
                    'in sanitization recommendations and certificate standard references.',
              ),
              const SizedBox(height: 24),

              // Disclaimer
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppTheme.accentOrange.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: AppTheme.accentOrange.withValues(alpha: 0.3)),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.info_outline, color: AppTheme.accentOrange, size: 20),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'Zero Trace does not claim to implement any research paper exactly. '
                        'Research insights are used to justify media-aware sanitization decisions '
                        'and to provide academic context for the recommendation engine. '
                        'This research mode is designed for educational and presentation purposes.',
                        style: GoogleFonts.inter(
                          color: AppTheme.textSecondary,
                          fontSize: 12,
                          height: 1.5,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildResearchSection({
    required String title,
    required String subtitle,
    required IconData icon,
    required Color color,
    required String content,
    required List<_ResearchInsight> keyInsights,
    required String implication,
  }) {
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
          // Section header
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: color.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(icon, color: color, size: 24),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: GoogleFonts.outfit(
                        color: AppTheme.textPrimary,
                        fontSize: 18,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    Text(
                      subtitle,
                      style: GoogleFonts.inter(
                        color: color,
                        fontSize: 12,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          Text(
            content,
            style: GoogleFonts.inter(
              color: AppTheme.textSecondary,
              fontSize: 13,
              height: 1.5,
            ),
          ),
          const SizedBox(height: 16),

          // Key insights
          Text(
            'KEY INSIGHTS',
            style: GoogleFonts.inter(
              color: AppTheme.textMuted,
              fontSize: 10,
              fontWeight: FontWeight.w700,
              letterSpacing: 1,
            ),
          ),
          const SizedBox(height: 10),

          ...keyInsights.map((insight) => Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppTheme.surfaceCard,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppTheme.surfaceBorder),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        insight.title,
                        style: GoogleFonts.outfit(
                          color: color,
                          fontSize: 14,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        insight.detail,
                        style: GoogleFonts.inter(
                          color: AppTheme.textSecondary,
                          fontSize: 12,
                          height: 1.5,
                        ),
                      ),
                    ],
                  ),
                ),
              )),

          // Implication
          const SizedBox(height: 4),
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.06),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: color.withValues(alpha: 0.2)),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.lightbulb_outline, color: color, size: 18),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'IMPLICATION FOR ZERO TRACE',
                        style: GoogleFonts.inter(
                          color: color,
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 0.5,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        implication,
                        style: GoogleFonts.inter(
                          color: AppTheme.textSecondary,
                          fontSize: 12,
                          height: 1.5,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _ResearchInsight {
  final String title;
  final String detail;
  const _ResearchInsight({required this.title, required this.detail});
}
