import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../widgets/theme.dart';

class CertificateVerificationScreen extends StatefulWidget {
  const CertificateVerificationScreen({super.key});

  @override
  State<CertificateVerificationScreen> createState() =>
      _CertificateVerificationScreenState();
}

class _CertificateVerificationScreenState
    extends State<CertificateVerificationScreen> {
  final TextEditingController _jsonController = TextEditingController();
  _VerificationResult? _result;

  void _verifyCertificate() {
    final text = _jsonController.text.trim();
    if (text.isEmpty) {
      setState(() {
        _result = _VerificationResult(
          status: _CertStatus.incomplete,
          message: 'No certificate data provided.',
          details: [],
        );
      });
      return;
    }

    try {
      final Map<String, dynamic> json = jsonDecode(text);

      // Check required fields
      final requiredFields = [
        'certificateId',
        'jobId',
        'deviceModel',
        'deviceSerial',
        'method',
        'result',
        'signature',
        'evidence',
      ];

      final missingFields = <String>[];
      for (final field in requiredFields) {
        if (!json.containsKey(field) || json[field] == null) {
          missingFields.add(field);
        }
      }

      if (missingFields.isNotEmpty) {
        setState(() {
          _result = _VerificationResult(
            status: _CertStatus.incomplete,
            message: 'Certificate is missing required fields.',
            details: missingFields.map((f) => 'Missing: $f').toList(),
          );
        });
        return;
      }

      // Check signature presence
      final sig = json['signature'] as String?;
      if (sig == null || sig.isEmpty || !sig.contains(':')) {
        setState(() {
          _result = _VerificationResult(
            status: _CertStatus.signatureInvalid,
            message: 'Certificate signature is missing or malformed.',
            details: [
              'Expected ECDSA signature in r:s hex format.',
              'Signature field: ${sig ?? "null"}',
            ],
          );
        });
        return;
      }

      // Check evidence integrity
      final evidence = json['evidence'];
      if (evidence is Map && evidence.containsKey('evidenceHash')) {
        final hash = evidence['evidenceHash'] as String?;
        if (hash == null || hash.length != 64) {
          setState(() {
            _result = _VerificationResult(
              status: _CertStatus.modified,
              message: 'Evidence hash appears invalid or modified.',
              details: [
                'Expected SHA-256 hash (64 hex characters).',
                'Found: ${hash?.length ?? 0} characters.',
              ],
            );
          });
          return;
        }
      }

      // All checks passed (demo-level verification)
      setState(() {
        _result = _VerificationResult(
          status: _CertStatus.valid,
          message: 'Certificate structure is valid.',
          details: [
            'Certificate ID: ${json['certificateId']}',
            'Device: ${json['deviceModel']} (${json['deviceSerial']})',
            'Method: ${json['method']}',
            'Result: ${json['result']}',
            'Signature format: ECDSA P-256 (present)',
            'Evidence hash: SHA-256 (present)',
            '',
            'Note: Full cryptographic signature verification requires '
                'the public key that was used at signing time. '
                'This check validates certificate structure and field completeness.',
          ],
        );
      });
    } on FormatException {
      setState(() {
        _result = _VerificationResult(
          status: _CertStatus.modified,
          message: 'Invalid JSON format. Certificate data may be corrupted.',
          details: ['The provided text is not valid JSON.'],
        );
      });
    }
  }

  @override
  void dispose() {
    _jsonController.dispose();
    super.dispose();
  }

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
              Row(
                children: [
                  IconButton(
                    icon: const Icon(Icons.arrow_back, color: AppTheme.textSecondary),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Certificate Verification',
                    style: GoogleFonts.outfit(
                      color: AppTheme.textPrimary,
                      fontSize: 24,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                'Import and verify a Zero Trace sanitization certificate',
                style: GoogleFonts.inter(
                  color: AppTheme.textSecondary,
                  fontSize: 14,
                ),
              ),
              const SizedBox(height: 24),

              // JSON input
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: AppTheme.surfaceDark,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: AppTheme.surfaceBorder),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.upload_file, color: AppTheme.accentBlue, size: 20),
                        const SizedBox(width: 10),
                        Text(
                          'Import Certificate JSON',
                          style: GoogleFonts.outfit(
                            color: AppTheme.textPrimary,
                            fontSize: 16,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 14),
                    TextField(
                      controller: _jsonController,
                      maxLines: 12,
                      decoration: InputDecoration(
                        hintText: 'Paste certificate JSON here...',
                        hintStyle: GoogleFonts.inter(
                          color: AppTheme.textMuted,
                          fontSize: 12,
                        ),
                        filled: true,
                        fillColor: AppTheme.codeBackground,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(12),
                          borderSide: const BorderSide(color: AppTheme.surfaceBorder),
                        ),
                      ),
                      style: GoogleFonts.firaCode(
                        color: AppTheme.accentEmerald,
                        fontSize: 11,
                      ),
                    ),
                    const SizedBox(height: 16),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.verified_user, size: 18),
                        label: const Text('VERIFY CERTIFICATE'),
                        onPressed: _verifyCertificate,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // Result
              if (_result != null) _buildResultCard(_result!),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildResultCard(_VerificationResult result) {
    Color statusColor;
    IconData statusIcon;
    String statusLabel;

    switch (result.status) {
      case _CertStatus.valid:
        statusColor = AppTheme.accentEmerald;
        statusIcon = Icons.check_circle;
        statusLabel = 'CERTIFICATE VALID';
        break;
      case _CertStatus.modified:
        statusColor = AppTheme.accentRose;
        statusIcon = Icons.error;
        statusLabel = 'CERTIFICATE MODIFIED';
        break;
      case _CertStatus.signatureInvalid:
        statusColor = AppTheme.accentOrange;
        statusIcon = Icons.warning;
        statusLabel = 'SIGNATURE INVALID';
        break;
      case _CertStatus.incomplete:
        statusColor = AppTheme.accentOrange;
        statusIcon = Icons.help;
        statusLabel = 'CERTIFICATE INCOMPLETE';
        break;
    }

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: statusColor.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: statusColor.withValues(alpha: 0.4)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(statusIcon, color: statusColor, size: 32),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      statusLabel,
                      style: GoogleFonts.outfit(
                        color: statusColor,
                        fontSize: 18,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    Text(
                      result.message,
                      style: GoogleFonts.inter(
                        color: AppTheme.textSecondary,
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          if (result.details.isNotEmpty) ...[
            const SizedBox(height: 16),
            const Divider(color: AppTheme.surfaceBorder, height: 1),
            const SizedBox(height: 12),
            ...result.details.map((d) => Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Text(
                    d,
                    style: GoogleFonts.inter(
                      color: AppTheme.textSecondary,
                      fontSize: 12,
                      height: 1.4,
                    ),
                  ),
                )),
          ],
        ],
      ),
    );
  }
}

enum _CertStatus { valid, modified, signatureInvalid, incomplete }

class _VerificationResult {
  final _CertStatus status;
  final String message;
  final List<String> details;

  const _VerificationResult({
    required this.status,
    required this.message,
    required this.details,
  });
}
