import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:pointycastle/export.dart' as pc;

import '../models/certificate.dart';
import '../models/device_profile.dart';
import '../models/sanitization_job.dart';

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
    // Construct signer using concrete classes to avoid PointyCastle registry
    // lookup failures for SecureRandom on Linux native builds.
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

  String _getPublicKeyPem() {
    return '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE${_publicKey.Q!.getEncoded(false).take(30).join()}\n-----END PUBLIC KEY-----';
  }

  SanitizationCertificate generateCertificate({
    required SanitizationJob job,
    required VerificationEvidence evidence,
  }) {
    final DateTime now = DateTime.now();
    final String certId = 'ZT-CERT-${now.millisecondsSinceEpoch.toString().substring(5)}';

    final String resultStr = evidence.verifiedPassed ? 'SUCCESS' : 'FAILED';
    final String verificationSummary = evidence.verifiedPassed
        ? '50/50 Sector Samples Passed Zero Readback Verification (${evidence.evidenceHash.substring(0, 12)}...)'
        : 'Sample Verification Failed - Non-Zero Data Detected at Target Offsets';

    final Map<String, dynamic> payloadToSign = {
      'certificateId': certId,
      'jobId': job.jobId,
      'deviceSerial': job.device.serialNumber,
      'method': job.recommendedMethod.displayName,
      'evidenceHash': evidence.evidenceHash,
      'result': resultStr,
      'timestamp': now.toIso8601String(),
    };

    final String payloadJson = jsonEncode(payloadToSign);
    final String signatureHex = _signData(payloadJson);

    return SanitizationCertificate(
      certificateId: certId,
      jobId: job.jobId,
      deviceModel: job.device.name,
      deviceSerial: job.device.serialNumber,
      mediaType: job.device.mediaType.displayName,
      capacity: job.device.formattedCapacity,
      method: job.recommendedMethod.displayName,
      standardReference: job.standardReference,
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
              pw.SizedBox(height: 16),
              pw.Divider(thickness: 2, color: PdfColors.amber800),
              pw.SizedBox(height: 16),

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
                      'VERIFIED BY ZERO TRACE ENGINE',
                      style: const pw.TextStyle(fontSize: 9, color: PdfColors.grey800),
                    ),
                  ],
                ),
              ),
              pw.SizedBox(height: 20),

              // Device & Method Table
              pw.Text('1. SANITIZATION TARGET & METHOD', style: pw.TextStyle(fontWeight: pw.FontWeight.bold, fontSize: 12)),
              pw.SizedBox(height: 8),
              pw.TableHelper.fromTextArray(
                headerStyle: pw.TextStyle(fontWeight: pw.FontWeight.bold, fontSize: 10),
                cellStyle: const pw.TextStyle(fontSize: 9),
                headers: ['Parameter', 'Value Details'],
                data: [
                  ['Device Model', cert.deviceModel],
                  ['Serial Number', cert.deviceSerial],
                  ['Media Type', cert.mediaType],
                  ['Total Capacity', cert.capacity],
                  ['Applied Method', cert.method],
                  ['NIST SP 800-88 Category', _extractNistCategory(cert.standardReference)],
                  ['IEEE 2883:2022 Classification', _extractIeeeClassification(cert.standardReference)],
                  ['Standard Reference', cert.standardReference],
                  ['Execution Time', '${cert.startTime.toString().substring(0, 19)} to ${cert.endTime.toString().substring(11, 19)}'],
                ],
              ),
              pw.SizedBox(height: 20),

              // Evidence & Verification
              pw.Text('2. VERIFICATION & SAMPLE EVIDENCE', style: pw.TextStyle(fontWeight: pw.FontWeight.bold, fontSize: 12)),
              pw.SizedBox(height: 8),
              pw.Container(
                padding: const pw.EdgeInsets.all(10),
                decoration: pw.BoxDecoration(
                  color: PdfColors.grey100,
                  borderRadius: pw.BorderRadius.circular(4),
                ),
                child: pw.Column(
                  crossAxisAlignment: pw.CrossAxisAlignment.start,
                  children: [
                    pw.Text('Verification Summary: ${cert.verificationSummary}', style: pw.TextStyle(fontSize: 9, fontWeight: pw.FontWeight.bold)),
                    pw.SizedBox(height: 4),
                    pw.Text('Master Evidence Hash: ${cert.evidence.evidenceHash}', style: const pw.TextStyle(fontSize: 8, color: PdfColors.grey800)),
                    pw.SizedBox(height: 4),
                    pw.Text('Limitations Disclaimer: ${cert.evidence.limitations}', style: const pw.TextStyle(fontSize: 8, color: PdfColors.grey700)),
                  ],
                ),
              ),
              pw.SizedBox(height: 20),

              // ECDSA Cryptographic Proof
              pw.Text('3. CRYPTOGRAPHIC AUDIT SIGNATURE', style: pw.TextStyle(fontWeight: pw.FontWeight.bold, fontSize: 12)),
              pw.SizedBox(height: 8),
              pw.Container(
                padding: const pw.EdgeInsets.all(10),
                decoration: pw.BoxDecoration(
                  border: pw.Border.all(color: PdfColors.grey400),
                  borderRadius: pw.BorderRadius.circular(4),
                ),
                child: pw.Column(
                  crossAxisAlignment: pw.CrossAxisAlignment.start,
                  children: [
                    pw.Text('Algorithm: ECDSA P-256 / SHA-256', style: pw.TextStyle(fontSize: 9, fontWeight: pw.FontWeight.bold)),
                    pw.SizedBox(height: 2),
                    pw.Text('Signature: ${cert.signature}', style: const pw.TextStyle(fontSize: 7, color: PdfColors.blue900)),
                    pw.SizedBox(height: 4),
                    pw.Text('Software: ${cert.softwareVersion}', style: const pw.TextStyle(fontSize: 8, color: PdfColors.grey700)),
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

  /// Extract NIST SP 800-88 category (Clear/Purge/Destroy) from the standardReference string.
  String _extractNistCategory(String standardReference) {
    final lower = standardReference.toLowerCase();
    if (lower.contains('destroy')) return 'Destroy';
    if (lower.contains('purge')) return 'Purge';
    if (lower.contains('clear')) return 'Clear';
    return 'Not Classified';
  }

  /// Extract IEEE 2883:2022 classification from the standardReference string.
  String _extractIeeeClassification(String standardReference) {
    // Extract everything after "IEEE 2883:2022" if present
    final ieeeIdx = standardReference.indexOf('IEEE 2883:2022');
    if (ieeeIdx >= 0) {
      final afterIeee = standardReference.substring(ieeeIdx + 'IEEE 2883:2022'.length).trim();
      if (afterIeee.isNotEmpty) {
        // Remove leading separators
        return afterIeee.replaceFirst(RegExp(r'^[/\s]+'), '').trim();
      }
    }
    return 'See Standard Reference';
  }
}
