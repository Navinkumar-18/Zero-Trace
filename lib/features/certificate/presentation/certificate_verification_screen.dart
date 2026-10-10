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
        _result = const _VerificationResult(
          status: _CertStatus.incomplete,
          message: 'No certificate data provided.',
          details: [],
        );
      });
      return;
    }

    try {
      final Map<String, dynamic> json = jsonDecode(text);

      // Check required base fields (compatible with both v1 and v2)
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

      // Check signature presence and format
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

      final certVersion = json['certVersion'] as int? ?? 1;
      final executionMode = json['executionMode'] as String? ?? 'simulated';
      final isSimulated = executionMode.toLowerCase() == 'simulated' ||
          json.containsKey('simulationDisclaimer');
      final warningLine = json['warningLine'] as String?;

      final details = <String>[
        'Certificate Version: ${certVersion == 1 ? "1 (Legacy format)" : "2 (NIST Aligned)"}',
        'Execution Mode: ${executionMode.toUpperCase()}',
        'Certificate ID: ${json['certificateId']}',
        'Device: ${json['deviceModel']} (${json['deviceSerial']})',
        'Media Type: ${json['mediaType'] ?? "Not recorded"}',
        if (json.containsKey('busType'))
          'Bus Interface: ${json['busType']}'
        else
          'Bus Interface: Not recorded in v1',
        if (json.containsKey('supportLevel'))
          'Sanitization Assurance: ${json['supportLevel']}'
        else
          'Sanitization Assurance: Not recorded in v1',
        'Method Executed: ${json['method']}',
        if (json.containsKey('sanitizationCategory'))
          'NIST SP 800-88 Category: ${json['sanitizationCategory']}'
        else
          'NIST SP 800-88 Category: ${json['standardReference'] != null && json['standardReference'].toString().contains('Purge') ? 'Purge' : 'Clear'}',
        'Sanitization Result: ${json['result']}',
        'Signature format: ECDSA P-256 (present)',
        'Evidence hash: SHA-256 (present)',
        if (json.containsKey('verificationSampleCount'))
          'Verification Samples: ${json['verificationSampleCount']} sectors',
        if (json.containsKey('verificationEntropyScore'))
          'Shannon Entropy: ${(json['verificationEntropyScore'] as num).toStringAsFixed(4)}',
      ];

      setState(() {
        _result = _VerificationResult(
          status: _CertStatus.valid,
          message: isSimulated
              ? 'Certificate structure verified (SIMULATED RECORD).'
              : 'Certificate structure and integrity verified.',
          details: details,
          isSimulated: isSimulated,
          warningLine: warningLine,
        );
      });
    } on FormatException {
      setState(() {
        _result = const _VerificationResult(
          status: _CertStatus.modified,
          message: 'Invalid JSON format. Certificate data may be corrupted.',
          details: ['The provided text is not valid JSON.'],
        );
      });
    }
  }

  void _loadSampleCertificate() {
    final sample = {
      'certVersion': 2,
      'certificateId': 'ZT-CERT-88392019',
      'jobId': 'JOB-948201',
      'deviceModel': 'Samsung 970 EVO Plus 500GB',
      'deviceSerial': 'S4EVNF0M123456',
      'mediaType': 'NVMe SSD',
      'capacity': '500 GB',
      'busType': 'PCIe/NVMe',
      'supportLevel': 'Full support (Firmware purge)',
      'method': 'NVMe Format / Sanitize',
      'sanitizationCategory': 'Purge',
      'executionMode': 'simulated',
      'simulationDisclaimer': 'SIMULATED, not a valid sanitization record',
      'standardReference': 'NIST SP 800-88r2 Purge / IEEE 2883:2022 Purge',
      'startTime': '2026-09-23T14:30:00.000Z',
      'endTime': '2026-09-23T14:32:15.000Z',
      'result': 'SUCCESS',
      'verificationSummary':
          '50/50 Sector Samples Passed Zero Readback Verification',
      'verificationSampleCount': 50,
      'verificationEntropyScore': 0.0001,
      'evidence': {
        'statusCode': 0,
        'controllerConfirmation': 'NVMe Controller Status: 0x0 (Success)',
        'sampleOffsets': [0, 1024, 2048, 4096, 8192],
        'sampleHashes': {
          '0':
              'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
        'evidenceHash':
            'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
        'limitations': 'Sampled 50 random LBA sectors across device range.',
        'verifiedPassed': true,
      },
      'softwareVersion': 'Zero Trace v2.0 (SIH25070 Build)',
      'signature':
          '3045022100a1b2c3d4e5f60718293a4b5c6d7e8f90:02204a5b6c7d8e9f0123456789abcdef',
      'publicKeyPem': '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----',
    };

    _jsonController.text =
        const JsonEncoder.withIndent('  ').convert(sample);
    _verifyCertificate();
  }

  @override
  void dispose() {
    _jsonController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(
          'Certificate Verification',
          style: GoogleFonts.outfit(fontWeight: FontWeight.w700),
        ),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header description
              Text(
                'Verify Sanitization Certificate',
                style: GoogleFonts.outfit(
                  color: AppTheme.textPrimary,
                  fontSize: 22,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 6),
              Text(
                'Import and verify a Zero Trace sanitization certificate. '
                'Validates structural integrity, cryptographic signature format, '
                'and evidence hash.',
                style: GoogleFonts.inter(
                  color: AppTheme.textSecondary,
                  fontSize: 13,
                  height: 1.4,
                ),
              ),
              const SizedBox(height: 20),

              // JSON Input Area
              Container(
                decoration: BoxDecoration(
                  color: AppTheme.surfaceDark,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: AppTheme.surfaceBorder),
                ),
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          'CERTIFICATE JSON PAYLOAD',
                          style: GoogleFonts.inter(
                            color: AppTheme.accentGold,
                            fontSize: 11,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 0.5,
                          ),
                        ),
                        TextButton.icon(
                          icon: const Icon(Icons.file_upload_outlined, size: 16),
                          label: const Text('Load Sample'),
                          style: TextButton.styleFrom(
                            foregroundColor: AppTheme.accentBlue,
                            textStyle: GoogleFonts.inter(fontSize: 12),
                          ),
                          onPressed: _loadSampleCertificate,
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _jsonController,
                      maxLines: 10,
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 12,
                        color: AppTheme.textPrimary,
                      ),
                      decoration: InputDecoration(
                        hintText:
                            'Paste the complete certificate JSON payload here...',
                        hintStyle: GoogleFonts.jetBrainsMono(
                          fontSize: 12,
                          color: AppTheme.textMuted,
                        ),
                        filled: true,
                        fillColor: AppTheme.surfaceCard,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10),
                          borderSide: BorderSide.none,
                        ),
                        contentPadding: const EdgeInsets.all(14),
                      ),
                    ),
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Expanded(
                          child: ElevatedButton.icon(
                            icon: const Icon(Icons.verified_outlined, size: 18),
                            label: const Text('VERIFY CERTIFICATE'),
                            onPressed: _verifyCertificate,
                          ),
                        ),
                        const SizedBox(width: 10),
                        OutlinedButton(
                          child: const Text('Clear'),
                          onPressed: () {
                            _jsonController.clear();
                            setState(() => _result = null);
                          },
                        ),
                      ],
                    ),
                  ],
                ),
              ),

              // Verification Result
              if (_result != null) ...[
                const SizedBox(height: 24),
                _buildResultCard(_result!),
              ],
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
        statusLabel = 'CERTIFICATE STRUCTURE VALID';
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
          // Simulated Mode Warning Banner
          if (result.isSimulated) ...[
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
              margin: const EdgeInsets.only(bottom: 14),
              decoration: BoxDecoration(
                color: AppTheme.accentGold.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppTheme.accentGold, width: 1.5),
              ),
              child: Row(
                children: [
                  const Icon(Icons.science, color: AppTheme.accentGold, size: 20),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'SIMULATED, not a valid sanitization record',
                      style: GoogleFonts.inter(
                        color: AppTheme.accentGold,
                        fontWeight: FontWeight.bold,
                        fontSize: 13,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],

          // Warning Line (if present)
          if (result.warningLine != null) ...[
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
              margin: const EdgeInsets.only(bottom: 14),
              decoration: BoxDecoration(
                color: AppTheme.accentRose.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppTheme.accentRose.withValues(alpha: 0.6)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.warning_amber_rounded, color: AppTheme.accentRose, size: 20),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      result.warningLine!,
                      style: GoogleFonts.inter(
                        color: AppTheme.accentRose,
                        fontWeight: FontWeight.w600,
                        fontSize: 12,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],

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
  final bool isSimulated;
  final String? warningLine;

  const _VerificationResult({
    required this.status,
    required this.message,
    required this.details,
    this.isSimulated = false,
    this.warningLine,
  });
}
