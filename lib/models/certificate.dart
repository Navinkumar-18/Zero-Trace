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

  factory VerificationEvidence.fromJson(Map<String, dynamic> json) {
    final rawHashes = json['sampleHashes'] as Map<String, dynamic>? ?? {};
    final sampleHashes = rawHashes.map(
      (k, v) => MapEntry(int.tryParse(k) ?? 0, v.toString()),
    );

    return VerificationEvidence(
      statusCode: json['statusCode'] as int? ?? 0,
      controllerConfirmation: json['controllerConfirmation'] as String? ?? '',
      sampleOffsets: (json['sampleOffsets'] as List<dynamic>?)
              ?.map((e) => (e as num).toInt())
              .toList() ??
          [],
      sampleHashes: sampleHashes,
      evidenceHash: json['evidenceHash'] as String? ?? '',
      limitations: json['limitations'] as String? ?? '',
      verifiedPassed: json['verifiedPassed'] as bool? ?? true,
    );
  }

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
  final int certVersion;
  final String certificateId;
  final String jobId;
  final String deviceModel;
  final String deviceSerial;
  final String mediaType;
  final String capacity;
  final String method;
  final String standardReference;
  final String sanitizationCategory; // "Clear", "Purge", "Destroy"
  final String busType;
  final String supportLevel;
  final String executionMode; // "real", "simulated"
  final String? operatorNote;
  final String? warningLine;
  final int? verificationSampleCount;
  final double? verificationEntropyScore;
  final String? simulationDisclaimer;
  final DateTime startTime;
  final DateTime endTime;
  final String result; // "SUCCESS", "FAILED", "UNSUPPORTED"
  final String verificationSummary;
  final VerificationEvidence evidence;
  final String softwareVersion;
  final String signature; // ECDSA Signature Hex string
  final String publicKeyPem;
  final String? scope; // "full" or "partial"
  final String? limitation;
  final List<Map<String, dynamic>>? partitionsWiped;
  final int? bytesOverwritten;
  final int? totalDeviceBytes;

  /// A7 (v4): NIST SP 800-88 level this wipe actually achieved
  /// ("Clear", "Purge", "Failed").
  final String? sanitizationLevel;

  /// A7 (v4): ordered steps actually executed during the wipe (engine command
  /// log in real mode, timestamped job log in simulated mode).
  final List<String>? stepsExecuted;

  /// B5: human-readable boot-environment wording for the PDF and UI
  /// ("Booted from live medium" — the operator-facing claim; the raw token is
  /// what the signature covers).
  String? get bootEnvironmentDisplay {
    switch (bootEnvironment) {
      case 'live':
        return 'Booted from live medium (internal disks wipeable)';
      case 'container':
        return 'Booted in container environment';
      case 'normal':
        return 'Booted from installed system';
      default:
        return null;
    }
  }

  /// B5 (v4): boot environment the wipe ran in — "live", "normal" or
  /// "container" ([BootMode] name). Signed so a certificate cannot claim it
  /// booted from a live medium when it did not.
  final String? bootEnvironment;

  /// C7 (v4): platform and engine backend that issued this certificate
  /// (e.g. "linux"/"linux"). Signed when present so the issuing-platform
  /// claim cannot be forged after the fact; absent on pre-C7 certificates
  /// so they still round-trip and verify byte-identically.
  final String? platform;
  final String? backend;

  SanitizationCertificate({
    this.certVersion = 2,
    required this.certificateId,
    required this.jobId,
    required this.deviceModel,
    required this.deviceSerial,
    required this.mediaType,
    required this.capacity,
    required this.method,
    required this.standardReference,
    this.sanitizationCategory = 'Clear',
    this.busType = 'Unknown',
    this.supportLevel = 'Unknown',
    this.executionMode = 'simulated',
    this.operatorNote,
    this.warningLine,
    this.verificationSampleCount,
    this.verificationEntropyScore,
    String? simulationDisclaimer,
    required this.startTime,
    required this.endTime,
    required this.result,
    required this.verificationSummary,
    required this.evidence,
    required this.softwareVersion,
    required this.signature,
    required this.publicKeyPem,
    this.scope,
    this.limitation,
    this.partitionsWiped,
    this.bytesOverwritten,
    this.totalDeviceBytes,
    this.sanitizationLevel,
    this.stepsExecuted,
    this.bootEnvironment,
    this.platform,
    this.backend,
  }) : simulationDisclaimer = simulationDisclaimer ??
            (executionMode == 'simulated'
                ? 'SIMULATED, not a valid sanitization record'
                : null);

  factory SanitizationCertificate.fromJson(Map<String, dynamic> json) {
    final certVer = json['certVersion'] as int? ?? 1;
    final evidenceRaw = json['evidence'];
    final evidence = evidenceRaw is Map<String, dynamic>
        ? VerificationEvidence.fromJson(evidenceRaw)
        : VerificationEvidence(
            statusCode: 0,
            controllerConfirmation: '',
            sampleOffsets: [],
            sampleHashes: {},
            evidenceHash: '',
            limitations: '',
            verifiedPassed: json['result'] == 'SUCCESS',
          );

    // v4 stores partitions under 'partitions'; v3 under 'partitionsWiped'.
    final rawWiped = (json['partitions'] as List<dynamic>?) ??
        (json['partitionsWiped'] as List<dynamic>?);
    final partitionsWiped = rawWiped?.map((e) => Map<String, dynamic>.from(e as Map)).toList();

    return SanitizationCertificate(
      certVersion: certVer,
      certificateId: json['certificateId'] as String? ?? '',
      jobId: json['jobId'] as String? ?? '',
      deviceModel: json['deviceModel'] as String? ?? '',
      deviceSerial: json['deviceSerial'] as String? ?? '',
      mediaType: json['mediaType'] as String? ?? 'Unknown',
      capacity: json['capacity'] as String? ?? '',
      method: json['method'] as String? ?? '',
      standardReference: json['standardReference'] as String? ?? '',
      sanitizationCategory: json['sanitizationCategory'] as String? ??
          (json['standardReference'] != null &&
                  json['standardReference'].toString().toLowerCase().contains('purge')
              ? 'Purge'
              : 'Clear'),
      busType: json['busType'] as String? ?? 'Unknown',
      supportLevel: json['supportLevel'] as String? ?? 'Unknown',
      executionMode: json['executionMode'] as String? ?? 'simulated',
      operatorNote: json['operatorNote'] as String?,
      warningLine: json['warningLine'] as String?,
      verificationSampleCount: json['verificationSampleCount'] as int?,
      verificationEntropyScore:
          (json['verificationEntropyScore'] as num?)?.toDouble(),
      simulationDisclaimer: json['simulationDisclaimer'] as String?,
      startTime: json['startTime'] != null
          ? DateTime.tryParse(json['startTime'].toString()) ?? DateTime.now()
          : DateTime.now(),
      endTime: json['endTime'] != null
          ? DateTime.tryParse(json['endTime'].toString()) ?? DateTime.now()
          : DateTime.now(),
      result: json['result'] as String? ?? 'UNKNOWN',
      verificationSummary: json['verificationSummary'] as String? ?? '',
      evidence: evidence,
      softwareVersion: json['softwareVersion'] as String? ?? 'Zero Trace v2.0',
      signature: json['signature'] as String? ?? '',
      publicKeyPem: json['publicKeyPem'] as String? ?? '',
      scope: json['scope'] as String?,
      limitation: json['limitation'] as String?,
      partitionsWiped: partitionsWiped,
      bytesOverwritten: (json['bytesOverwritten'] as num?)?.toInt(),
      totalDeviceBytes: (json['totalDeviceBytes'] as num?)?.toInt(),
      sanitizationLevel: json['sanitizationLevel'] as String?,
      stepsExecuted: (json['stepsExecuted'] as List<dynamic>?)
          ?.map((e) => e.toString())
          .toList(),
      bootEnvironment: json['bootEnvironment'] as String?,
      platform: json['platform'] as String?,
      backend: json['backend'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'certVersion': certVersion,
        'certificateId': certificateId,
        'jobId': jobId,
        'deviceModel': deviceModel,
        'deviceSerial': deviceSerial,
        'mediaType': mediaType,
        'capacity': capacity,
        'method': method,
        'standardReference': standardReference,
        'sanitizationCategory': sanitizationCategory,
        'busType': busType,
        'supportLevel': supportLevel,
        'executionMode': executionMode,
        if (simulationDisclaimer != null)
          'simulationDisclaimer': simulationDisclaimer,
        if (operatorNote != null) 'operatorNote': operatorNote,
        if (warningLine != null) 'warningLine': warningLine,
        if (verificationSampleCount != null)
          'verificationSampleCount': verificationSampleCount,
        if (verificationEntropyScore != null)
          'verificationEntropyScore': verificationEntropyScore,
        if (certVersion >= 3 && scope != null) 'scope': scope,
        if (certVersion >= 3 && limitation != null) 'limitation': limitation,
        // v3 serialized partitions under 'partitionsWiped'; v4 uses 'partitions'.
        if (certVersion == 3 && partitionsWiped != null) 'partitionsWiped': partitionsWiped,
        if (certVersion >= 4 && partitionsWiped != null) 'partitions': partitionsWiped,
        if (certVersion >= 3 && bytesOverwritten != null) 'bytesOverwritten': bytesOverwritten,
        if (certVersion >= 3 && totalDeviceBytes != null) 'totalDeviceBytes': totalDeviceBytes,
        if (certVersion >= 4 && sanitizationLevel != null)
          'sanitizationLevel': sanitizationLevel,
        if (certVersion >= 4 && stepsExecuted != null) 'stepsExecuted': stepsExecuted,
        // B5: signed boot-environment claim ("live"/"normal"/"container");
        // omitted when absent so pre-B5 v4 certificates still round-trip.
        if (certVersion >= 4 && bootEnvironment != null)
          'bootEnvironment': bootEnvironment,
        // C7: signed platform/backend identity of the issuer; omitted when
        // absent so pre-C7 certificates round-trip byte-identically.
        if (certVersion >= 4 && platform != null) 'platform': platform,
        if (certVersion >= 4 && backend != null) 'backend': backend,
        'startTime': startTime.toIso8601String(),
        'endTime': endTime.toIso8601String(),
        'timestamp': endTime.toIso8601String(),
        'result': result,
        'verificationSummary': verificationSummary,
        'evidence': evidence.toJson(),
        'softwareVersion': softwareVersion,
        'signature': signature,
        'publicKeyPem': publicKeyPem,
      };
}
