class VerificationEvidence {
  final int statusCode;
  final String controllerConfirmation;
  final List<int> sampleOffsets;
  final Map<int, String> sampleHashes;
  final String evidenceHash;
  final String limitations;
  final bool verifiedPassed;

  VerificationEvidence({
    required this.statusCode,
    required this.controllerConfirmation,
    required this.sampleOffsets,
    required this.sampleHashes,
    required this.evidenceHash,
    required this.limitations,
    required this.verifiedPassed,
  });

  Map<String, dynamic> toJson() => {
        'statusCode': statusCode,
        'controllerConfirmation': controllerConfirmation,
        'sampleOffsets': sampleOffsets,
        'sampleHashes': sampleHashes.map((k, v) => MapEntry(k.toString(), v)),
        'evidenceHash': evidenceHash,
        'limitations': limitations,
        'verifiedPassed': verifiedPassed,
      };
}

class SanitizationCertificate {
  final String certificateId;
  final String jobId;
  final String deviceModel;
  final String deviceSerial;
  final String mediaType;
  final String capacity;
  final String method;
  final String standardReference;
  final DateTime startTime;
  final DateTime endTime;
  final String result; // "SUCCESS", "FAILED", "UNSUPPORTED"
  final String verificationSummary;
  final VerificationEvidence evidence;
  final String softwareVersion;
  final String signature; // ECDSA Signature Hex string
  final String publicKeyPem;

  SanitizationCertificate({
    required this.certificateId,
    required this.jobId,
    required this.deviceModel,
    required this.deviceSerial,
    required this.mediaType,
    required this.capacity,
    required this.method,
    required this.standardReference,
    required this.startTime,
    required this.endTime,
    required this.result,
    required this.verificationSummary,
    required this.evidence,
    required this.softwareVersion,
    required this.signature,
    required this.publicKeyPem,
  });

  Map<String, dynamic> toJson() => {
        'certificateId': certificateId,
        'jobId': jobId,
        'deviceModel': deviceModel,
        'deviceSerial': deviceSerial,
        'mediaType': mediaType,
        'capacity': capacity,
        'method': method,
        'standardReference': standardReference,
        'startTime': startTime.toIso8601String(),
        'endTime': endTime.toIso8601String(),
        'result': result,
        'verificationSummary': verificationSummary,
        'evidence': evidence.toJson(),
        'softwareVersion': softwareVersion,
        'signature': signature,
        'publicKeyPem': publicKeyPem,
      };
}
