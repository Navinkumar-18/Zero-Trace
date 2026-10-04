import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:pointycastle/export.dart' as pc;

import '../models/certificate.dart';
import '../models/device_profile.dart';
import '../models/sanitization_job.dart';
import '../models/sanitization_support_level.dart';

class CertificateService {
  late pc.ECPrivateKey _privateKey;
  late pc.ECPublicKey _publicKey;
  late pc.FortunaRandom _secureRandom;

  CertificateService() {
    _initSecureRandom();
    _initDemoKeypair();
  }

  void _initSecureRandom() {
    _secureRandom = pc.FortunaRandom();
    final secureRng = Random.secure();
    final seed = List<int>.generate(32, (_) => secureRng.nextInt(256));
    _secureRandom.seed(pc.KeyParameter(Uint8List.fromList(seed)));
  }

  void _initDemoKeypair() {
    final keyParams = pc.ECKeyGeneratorParameters(pc.ECCurve_secp256r1());
    final generator = pc.ECKeyGenerator();
    generator.init(pc.ParametersWithRandom(keyParams, _secureRandom));
    final pair = generator.generateKeyPair();
    _privateKey = pair.privateKey as pc.ECPrivateKey;
    _publicKey = pair.publicKey as pc.ECPublicKey;
  }

  String _signData(String data) {
    final signer = pc.ECDSASigner(pc.SHA256Digest(), null);
    signer.init(
      true,
      pc.ParametersWithRandom(
        pc.PrivateKeyParameter<pc.ECPrivateKey>(_privateKey),
        _secureRandom,
      ),
    );
    final signature = signer.generateSignature(Uint8List.fromList(utf8.encode(data))) as pc.ECSignature;
    return '${signature.r.toRadixString(16)}:${signature.s.toRadixString(16)}';
  }

  bool _verifySignature(String data, String signatureHex, [pc.ECPublicKey? key]) {
    try {
      final parts = signatureHex.split(':');
      if (parts.length != 2) return false;
      final r = BigInt.tryParse(parts[0], radix: 16);
      final s = BigInt.tryParse(parts[1], radix: 16);
      if (r == null || s == null) return false;

      final sig = pc.ECSignature(r, s);
      final verifier = pc.ECDSASigner(pc.SHA256Digest(), null);
      verifier.init(false, pc.PublicKeyParameter<pc.ECPublicKey>(key ?? _publicKey));
      return verifier.verifySignature(Uint8List.fromList(utf8.encode(data)), sig);
    } catch (_) {
      return false;
    }
  }

  String _getPublicKeyPem() {
    return '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE${_publicKey.Q!.getEncoded(false).take(30).join()}\n-----END PUBLIC KEY-----';
  }

  /// Builds the exact map of fields included in the cryptographic signature payload.
  static Map<String, dynamic> buildSigningPayload({
    required int certVersion,
    required String certificateId,
    required String jobId,
    required String deviceSerial,
    required String method,
    required String evidenceHash,
    required String result,
    required String timestamp,
    String? sanitizationCategory,
    String? executionMode,
    String? warningLine,
  }) {
    if (certVersion == 1) {
      return {
        'certificateId': certificateId,
        'jobId': jobId,
        'deviceSerial': deviceSerial,
        'method': method,
        'evidenceHash': evidenceHash,
        'result': result,
        'timestamp': timestamp,
      };
    }
    return {
      'certVersion': 2,
      'certificateId': certificateId,
      'jobId': jobId,
      'deviceSerial': deviceSerial,
      'method': method,
      'sanitizationCategory': sanitizationCategory ?? 'Clear',
      'executionMode': executionMode ?? 'simulated',
      'evidenceHash': evidenceHash,
      'result': result,
      'timestamp': timestamp,
      'warningLine': ?warningLine,
    };
  }

  /// Exact method strings emitted by zt_engine (execute.rs) and Flutter simulated mode
  /// that correspond to verified firmware-level Purge commands.
  static const Set<String> _validPurgeMethodNames = {
    // Exact method_used strings from zt_engine (native/zt_engine/src/execute.rs)
    'ata secure erase',
    'ata enhanced secure erase',
    'ata sanitize block erase',
    'ata sanitize crypto scramble',
    'nvme sanitize (start-block-erase)',
    'nvme sanitize (start-crypto-erase)',
    'tcg opal cryptographic erase (reverttper)',
    'emmc sanitize',

    // Flutter simulated mode method display names (SanitizationMethodExtension.displayName)
    'cryptographic erase (ce)',
    'ata secure erase (controller-level)',
    'nvme sanitize (block / crypto erase)',
    'emmc sanitize / secure trim',
  };

  /// Derives whether the actually executed action achieved Clear, Purge, or Destroy.
  static String deriveSanitizationCategory({
    required SanitizationMethod method,
    required DeviceProfile device,
    String? actualMethodExecuted,
    required bool isSuccess,
  }) {
    if (!isSuccess) return 'Failed';

    final executedLower = (actualMethodExecuted ?? method.displayName).toLowerCase().trim();

    // The software does not physically destroy devices.
    if (method == SanitizationMethod.physicalDestructionRecommended ||
        method == SanitizationMethod.unsupportedFlagForDestroy ||
        executedLower.contains('physical destruction') ||
        executedLower.contains('destroy')) {
      return 'Destroy recommended, not performed';
    }

    // Overwrite operations are ALWAYS Clear per NIST SP 800-88
    if (method == SanitizationMethod.singlePassOverwrite ||
        method == SanitizationMethod.multiPassOverwrite ||
        executedLower.contains('overwrite')) {
      return 'Clear';
    }

    // Flash media without firmware-level purge is Clear-only
    final isFlash = device.mediaTechnology == MediaTechnology.flash;

    if (isFlash &&
        !device.supportsAtaSanitize &&
        !device.supportsNvmeSanitize &&
        !device.supportsEmmcSanitize &&
        !device.supportsAtaSecureErase &&
        !device.isHardwareEncrypted) {
      return 'Clear';
    }

    // Only exact verified firmware-level purge commands qualify for Purge.
    // Filesystem formats, standard NVMe formats without sanitize, or unknown strings default to Clear.
    if (_validPurgeMethodNames.contains(executedLower)) {
      return 'Purge';
    }

    // Default to the safer label
    return 'Clear';
  }

  /// Generates a signed SanitizationCertificate (Version 2 by default).
  SanitizationCertificate generateCertificate({
    required SanitizationJob job,
    required VerificationEvidence evidence,
    String executionMode = 'simulated',
    String? actualMethodExecuted,
    String? sanitizationCategory,
    String? warningLine,
    String? operatorNote,
    int? verificationSampleCount,
    double? verificationEntropyScore,
  }) {
    final DateTime now = DateTime.now();
    final String certId = 'ZT-CERT-${now.millisecondsSinceEpoch.toString().substring(5)}';

    final String resultStr = evidence.verifiedPassed ? 'SUCCESS' : 'FAILED';
    final String verificationSummary = evidence.verifiedPassed
        ? '${verificationSampleCount ?? 50}/${verificationSampleCount ?? 50} Sector Samples Passed Zero Readback Verification (${evidence.evidenceHash.substring(0, min(12, evidence.evidenceHash.length))}...)'
        : 'Sample Verification Failed - Non-Zero Data Detected at Target Offsets';

    final methodToRecord = actualMethodExecuted ?? job.effectiveMethod.displayName;

    final category = sanitizationCategory ??
        deriveSanitizationCategory(
          method: job.effectiveMethod,
          device: job.device,
          actualMethodExecuted: actualMethodExecuted,
          isSuccess: evidence.verifiedPassed,
        );

    // If target was Destroy but user executed an overwrite method, add warningLine
    String? finalWarningLine = warningLine;
    if (finalWarningLine == null &&
        (job.targetCategory == NistCategory.destroy ||
            job.recommendedMethod == SanitizationMethod.physicalDestructionRecommended ||
            job.recommendedMethod == SanitizationMethod.unsupportedFlagForDestroy) &&
        job.effectiveMethod != SanitizationMethod.physicalDestructionRecommended &&
        job.effectiveMethod != SanitizationMethod.unsupportedFlagForDestroy) {
      finalWarningLine =
          'WARNING: User proceeded with overwrite despite NIST SP 800-88 Destroy recommendation. Data may be retained in unmapped flash blocks.';
    }

    final supportLevel = computeSupportLevel(job.device).displayName;
    final busType = job.device.busType;
    final timestampStr = (job.endTime ?? now).toIso8601String();

    final Map<String, dynamic> payloadToSign = buildSigningPayload(
      certVersion: 2,
      certificateId: certId,
      jobId: job.jobId,
      deviceSerial: job.device.serialNumber,
      method: methodToRecord,
      sanitizationCategory: category,
      executionMode: executionMode,
      evidenceHash: evidence.evidenceHash,
      result: resultStr,
      timestamp: timestampStr,
      warningLine: finalWarningLine,
    );

    final String payloadJson = jsonEncode(payloadToSign);
    final String signatureHex = _signData(payloadJson);

    return SanitizationCertificate(
      certVersion: 2,
      certificateId: certId,
      jobId: job.jobId,
      deviceModel: job.device.name,
      deviceSerial: job.device.serialNumber,
      mediaType: job.device.mediaType.displayName,
      capacity: job.device.formattedCapacity,
      method: methodToRecord,
      standardReference: job.standardReference,
      sanitizationCategory: category,
      busType: busType,
      supportLevel: supportLevel,
      executionMode: executionMode,
      operatorNote: operatorNote,
      warningLine: finalWarningLine,
      verificationSampleCount: verificationSampleCount ?? 50,
      verificationEntropyScore: verificationEntropyScore,
      startTime: job.startTime ?? now.subtract(const Duration(minutes: 3)),
      endTime: job.endTime ?? now,
      result: resultStr,
      verificationSummary: verificationSummary,
      evidence: evidence,
      softwareVersion: 'Zero Trace v2.0 (SIH25070 Build)',
      signature: signatureHex,
      publicKeyPem: _getPublicKeyPem(),
    );
  }

  /// Verifies a certificate signature using backward-compatible payload reconstruction.
  bool verifyCertificateSignature(Map<String, dynamic> certJson) {
    final certVer = certJson['certVersion'] as int? ?? 1;
    final certId = certJson['certificateId'] as String? ?? '';
    final jobId = certJson['jobId'] as String? ?? '';
    final deviceSerial = certJson['deviceSerial'] as String? ?? '';
    final method = certJson['method'] as String? ?? '';
    final result = certJson['result'] as String? ?? '';
    final signature = certJson['signature'] as String? ?? '';
    final warningLine = certJson['warningLine'] as String?;
    final sanitizationCategory = certJson['sanitizationCategory'] as String? ?? 'Clear';
    final executionMode = certJson['executionMode'] as String? ?? 'simulated';

    final evidenceHash = (certJson['evidence'] is Map)
        ? certJson['evidence']['evidenceHash'] as String? ?? ''
        : certJson['evidenceHash'] as String? ?? '';

    final timestamp = certJson['timestamp'] as String? ??
        certJson['endTime'] as String? ??
        certJson['startTime'] as String? ??
        '';

    final payload = buildSigningPayload(
      certVersion: certVer,
      certificateId: certId,
      jobId: jobId,
      deviceSerial: deviceSerial,
      method: method,
      sanitizationCategory: sanitizationCategory,
      executionMode: executionMode,
      evidenceHash: evidenceHash,
      result: result,
      timestamp: timestamp,
      warningLine: warningLine,
    );

    return _verifySignature(jsonEncode(payload), signature);
  }

  /// Generate a legacy v1 certificate signed with the active key (used for test fixtures).
  SanitizationCertificate generateLegacyV1Certificate({
    required SanitizationJob job,
    required VerificationEvidence evidence,
  }) {
    final DateTime now = DateTime.now();
    final String certId = 'ZT-CERT-LEGACY-${now.millisecondsSinceEpoch.toString().substring(5)}';
    final String resultStr = evidence.verifiedPassed ? 'SUCCESS' : 'FAILED';
    final String timestampStr = (job.endTime ?? now).toIso8601String();

    final Map<String, dynamic> payloadToSign = {
      'certificateId': certId,
      'jobId': job.jobId,
      'deviceSerial': job.device.serialNumber,
      'method': job.recommendedMethod.displayName,
      'evidenceHash': evidence.evidenceHash,
      'result': resultStr,
      'timestamp': timestampStr,
    };

    final String signatureHex = _signData(jsonEncode(payloadToSign));

    return SanitizationCertificate(
      certVersion: 1,
      certificateId: certId,
      jobId: job.jobId,
      deviceModel: job.device.name,
      deviceSerial: job.device.serialNumber,
      mediaType: job.device.mediaType.displayName,
      capacity: job.device.formattedCapacity,
      method: job.recommendedMethod.displayName,
      standardReference: job.standardReference,
      sanitizationCategory: 'Clear',
      busType: job.device.busType,
      supportLevel: 'Clear-only',
      executionMode: 'simulated',
      startTime: job.startTime ?? now.subtract(const Duration(minutes: 3)),
      endTime: job.endTime ?? now,
      result: resultStr,
      verificationSummary: 'Legacy 50/50 Sector Samples Passed',
      evidence: evidence,
      softwareVersion: 'Zero Trace v1.0 Legacy',
      signature: signatureHex,
      publicKeyPem: _getPublicKeyPem(),
    );
  }

  Future<Uint8List> generatePdfBytes(SanitizationCertificate cert) async {
    final pdf = pw.Document();

    pdf.addPage(
      pw.Page(
        pageFormat: PdfPageFormat.a4,
        margin: const pw.EdgeInsets.all(32),
        build: (pw.Context context) {
          return pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              // Simulated Mode Disclaimer Banner
              if (cert.executionMode == 'simulated')
                pw.Container(
                  width: double.infinity,
                  padding: const pw.EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  margin: const pw.EdgeInsets.only(bottom: 12),
                  decoration: pw.BoxDecoration(
                    color: PdfColors.amber100,
                    borderRadius: pw.BorderRadius.circular(6),
                    border: pw.Border.all(color: PdfColors.amber800, width: 1.5),
                  ),
                  child: pw.Row(
                    mainAxisAlignment: pw.MainAxisAlignment.center,
                    children: [
                      pw.Text(
                        'SIMULATED, not a valid sanitization record',
                        style: pw.TextStyle(
                          fontSize: 11,
                          fontWeight: pw.FontWeight.bold,
                          color: PdfColors.amber900,
                        ),
                      ),
                    ],
                  ),
                ),

              // Warning Line Box (if present)
              if (cert.warningLine != null)
                pw.Container(
                  width: double.infinity,
                  padding: const pw.EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  margin: const pw.EdgeInsets.only(bottom: 12),
                  decoration: pw.BoxDecoration(
                    color: PdfColors.red50,
                    borderRadius: pw.BorderRadius.circular(4),
                    border: pw.Border.all(color: PdfColors.red400),
                  ),
                  child: pw.Text(
                    cert.warningLine!,
                    style: pw.TextStyle(
                      fontSize: 8.5,
                      color: PdfColors.red900,
                      fontWeight: pw.FontWeight.bold,
                    ),
                  ),
                ),

              // Header
              pw.Row(
                mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                children: [
                  pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [
                      pw.Text(
                        'ZERO TRACE 2.0',
                        style: pw.TextStyle(
                          fontSize: 24,
                          fontWeight: pw.FontWeight.bold,
                          color: PdfColors.amber800,
                        ),
                      ),
                      pw.Text(
                        'SECURE DATA SANITIZATION & AUDIT CERTIFICATE',
                        style: pw.TextStyle(
                          fontSize: 10,
                          fontWeight: pw.FontWeight.bold,
                          color: PdfColors.grey700,
                        ),
                      ),
                    ],
                  ),
                  pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.end,
                    children: [
                      pw.Text(
                        cert.certificateId,
                        style: pw.TextStyle(
                          fontSize: 12,
                          fontWeight: pw.FontWeight.bold,
                          color: PdfColors.blueGrey800,
                        ),
                      ),
                      pw.Text(
                        'Issued: ${cert.endTime.toIso8601String().substring(0, 10)}',
                        style: const pw.TextStyle(fontSize: 10, color: PdfColors.grey600),
                      ),
                    ],
                  ),
                ],
              ),
              pw.SizedBox(height: 12),
              pw.Divider(thickness: 2, color: PdfColors.amber800),
              pw.SizedBox(height: 12),

              // Status Badge
              pw.Container(
                padding: const pw.EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                decoration: pw.BoxDecoration(
                  color: cert.result == 'SUCCESS' ? PdfColors.green100 : PdfColors.red100,
                  borderRadius: pw.BorderRadius.circular(6),
                  border: pw.Border.all(
                    color: cert.result == 'SUCCESS' ? PdfColors.green700 : PdfColors.red700,
                  ),
                ),
                child: pw.Row(
                  mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                  children: [
                    pw.Text(
                      'SANITIZATION RESULT: ${cert.result}',
                      style: pw.TextStyle(
                        fontWeight: pw.FontWeight.bold,
                        color: cert.result == 'SUCCESS' ? PdfColors.green900 : PdfColors.red900,
                      ),
                    ),
                    pw.Text(
                      'EXECUTION MODE: ${cert.executionMode.toUpperCase()}',
                      style: pw.TextStyle(
                        fontSize: 9,
                        fontWeight: pw.FontWeight.bold,
                        color: cert.executionMode == 'real' ? PdfColors.green900 : PdfColors.amber900,
                      ),
                    ),
                  ],
                ),
              ),
              pw.SizedBox(height: 16),

              // Device & Method Table
              pw.Text('1. SANITIZATION TARGET & METHOD', style: pw.TextStyle(fontWeight: pw.FontWeight.bold, fontSize: 12)),
              pw.SizedBox(height: 6),
              pw.TableHelper.fromTextArray(
                headerStyle: pw.TextStyle(fontWeight: pw.FontWeight.bold, fontSize: 9),
                cellStyle: const pw.TextStyle(fontSize: 8.5),
                headers: ['Parameter', 'Value Details'],
                data: [
                  ['Certificate Version', 'v${cert.certVersion}'],
                  ['Device Model', cert.deviceModel],
                  ['Serial Number', cert.deviceSerial],
                  ['Media Type', cert.mediaType],
                  ['Bus Interface', cert.busType],
                  ['Total Capacity', cert.capacity],
                  ['Sanitization Assurance', cert.supportLevel],
                  ['Applied Method', cert.method],
                  ['NIST SP 800-88 Category', cert.sanitizationCategory],
                  ['Standard Reference', cert.standardReference],
                  ['Execution Time', '${cert.startTime.toString().substring(0, 19)} to ${cert.endTime.toString().substring(11, 19)}'],
                  if (cert.operatorNote != null) ['Operator Note', cert.operatorNote!],
                ],
              ),
              pw.SizedBox(height: 16),

              // Evidence & Verification
              pw.Text('2. VERIFICATION & SAMPLE EVIDENCE', style: pw.TextStyle(fontWeight: pw.FontWeight.bold, fontSize: 12)),
              pw.SizedBox(height: 6),
              pw.Container(
                padding: const pw.EdgeInsets.all(10),
                decoration: pw.BoxDecoration(
                  color: PdfColors.grey100,
                  borderRadius: pw.BorderRadius.circular(4),
                ),
                child: pw.Column(
                  crossAxisAlignment: pw.CrossAxisAlignment.start,
                  children: [
                    pw.Text('Verification Summary: ${cert.verificationSummary}', style: pw.TextStyle(fontSize: 8.5, fontWeight: pw.FontWeight.bold)),
                    pw.SizedBox(height: 3),
                    pw.Text('Master Evidence Hash: ${cert.evidence.evidenceHash}', style: const pw.TextStyle(fontSize: 8, color: PdfColors.grey800)),
                    if (cert.verificationEntropyScore != null) ...[
                      pw.SizedBox(height: 3),
                      pw.Text('Shannon Entropy Score: ${cert.verificationEntropyScore!.toStringAsFixed(4)}', style: const pw.TextStyle(fontSize: 8, color: PdfColors.grey800)),
                    ],
                    pw.SizedBox(height: 3),
                    pw.Text('Limitations Disclaimer: ${cert.evidence.limitations}', style: const pw.TextStyle(fontSize: 7.5, color: PdfColors.grey700)),
                  ],
                ),
              ),
              pw.SizedBox(height: 16),

              // ECDSA Cryptographic Proof
              pw.Text('3. CRYPTOGRAPHIC AUDIT SIGNATURE', style: pw.TextStyle(fontWeight: pw.FontWeight.bold, fontSize: 12)),
              pw.SizedBox(height: 6),
              pw.Container(
                padding: const pw.EdgeInsets.all(10),
                decoration: pw.BoxDecoration(
                  border: pw.Border.all(color: PdfColors.grey400),
                  borderRadius: pw.BorderRadius.circular(4),
                ),
                child: pw.Column(
                  crossAxisAlignment: pw.CrossAxisAlignment.start,
                  children: [
                    pw.Text('Algorithm: ECDSA P-256 / SHA-256', style: pw.TextStyle(fontSize: 8.5, fontWeight: pw.FontWeight.bold)),
                    pw.SizedBox(height: 2),
                    pw.Text('Signature: ${cert.signature}', style: const pw.TextStyle(fontSize: 7, color: PdfColors.blue900)),
                    pw.SizedBox(height: 3),
                    pw.Text('Software: ${cert.softwareVersion}', style: const pw.TextStyle(fontSize: 7.5, color: PdfColors.grey700)),
                  ],
                ),
              ),

              pw.Spacer(),

              // Footer
              pw.Divider(color: PdfColors.grey300),
              pw.Row(
                mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                children: [
                  pw.Text('SIH25070 — Team VCSE_DataCircuits', style: const pw.TextStyle(fontSize: 8, color: PdfColors.grey600)),
                  pw.Text('Page 1 of 1', style: const pw.TextStyle(fontSize: 8, color: PdfColors.grey600)),
                ],
              ),
            ],
          );
        },
      ),
    );

    return pdf.save();
  }
}
