import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';

import '../models/certificate.dart';
import '../models/sanitization_job.dart';

class VerificationService {
  VerificationEvidence verify(SanitizationJob job, {bool isSuccess = true}) {
    final Random random = Random(job.jobId.hashCode);
    final List<int> sampleOffsets = [];
    final Map<int, String> sampleHashes = {};

    // Pick 50 pseudo-random block offsets across full capacity
    final int step = (job.device.capacityBytes / 50).floor();
    for (int i = 0; i < 50; i++) {
      final int baseOffset = i * step;
      final int randomOffset = baseOffset + random.nextInt(max(1, step - 512));
      sampleOffsets.add(randomOffset);

      // Simulated read-back: If success, all zero byte pattern (SHA-256 hash of 512 zeroes)
      if (isSuccess) {
        // SHA-256 of 512 zero bytes
        final zeroes = List<int>.filled(512, 0);
        sampleHashes[randomOffset] = sha256.convert(zeroes).toString();
      } else {
        // Random dirty sector hash
        final randomBytes = List<int>.generate(512, (_) => random.nextInt(256));
        sampleHashes[randomOffset] = sha256.convert(randomBytes).toString();
      }
    }

    final int statusCode = isSuccess ? 0 : 1;
    final String controllerConfirmation = isSuccess
        ? 'CONTROLLER_STATUS_OK: Command completed successfully, status block zeroed.'
        : 'CONTROLLER_ERROR: Interrupted or controller reported error status.';

    // Serialize payload to derive master Evidence Hash
    final String rawEvidenceData = jsonEncode({
      'jobId': job.jobId,
      'deviceSerial': job.device.serialNumber,
      'statusCode': statusCode,
      'controllerConfirmation': controllerConfirmation,
      'samplesCount': sampleOffsets.length,
      'firstSampleHash': sampleHashes[sampleOffsets.first],
      'lastSampleHash': sampleHashes[sampleOffsets.last],
    });

    final String evidenceHash = sha256.convert(utf8.encode(rawEvidenceData)).toString();

    final String limitations = getTailoredLimitations(job.recommendedMethod);

    return VerificationEvidence(
      statusCode: statusCode,
      controllerConfirmation: controllerConfirmation,
      sampleOffsets: sampleOffsets,
      sampleHashes: sampleHashes,
      evidenceHash: evidenceHash,
      limitations: limitations,
      verifiedPassed: isSuccess,
    );
  }

  String getTailoredLimitations(SanitizationMethod method) {
    switch (method) {
      case SanitizationMethod.cryptographicErase:
        return 'Verifies cryptographic key zeroization & block sample un-readability. Does not verify physical erasure of underlying encrypted NAND flash cells.';
      case SanitizationMethod.ataSanitizeBlockErase:
      case SanitizationMethod.nvmeSanitize:
        return 'Verifies controller sanitize completion flag & sampled LBA zero readbacks. Physical NAND flash block status verified via controller telemetry.';
      case SanitizationMethod.singlePassOverwrite:
      case SanitizationMethod.multiPassOverwrite:
        return 'Verifies logical-layer zero pattern read-back at sampled sector addresses. Does not verify hidden reallocated sectors or DCO/HPA regions.';
      default:
        return 'Verifies logical-layer state at 50 sampled sector addresses only; does not verify physical-media erasure or non-addressable spare blocks.';
    }
  }
}
