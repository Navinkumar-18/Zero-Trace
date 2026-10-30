import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:meta/meta.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:pointycastle/export.dart' as pc;

import '../models/certificate.dart';
import '../models/device_profile.dart';
import '../models/partition_info.dart';
import '../models/sanitization_job.dart';
import '../models/sanitization_support_level.dart';
import 'failure_report_wording.dart';
import 'platform_backend.dart';

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
    final signature =
        signer.generateSignature(Uint8List.fromList(utf8.encode(data)))
            as pc.ECSignature;
    return '${signature.r.toRadixString(16)}:${signature.s.toRadixString(16)}';
  }

  bool _verifySignature(
    String data,
    String signatureHex, [
    pc.ECPublicKey? key,
  ]) {
    try {
      final parts = signatureHex.split(':');
      if (parts.length != 2) return false;
      final r = BigInt.tryParse(parts[0], radix: 16);
      final s = BigInt.tryParse(parts[1], radix: 16);
      if (r == null || s == null) return false;

      final sig = pc.ECSignature(r, s);
      final verifier = pc.ECDSASigner(pc.SHA256Digest(), null);
      verifier.init(
        false,
        pc.PublicKeyParameter<pc.ECPublicKey>(key ?? _publicKey),
      );
      return verifier.verifySignature(
        Uint8List.fromList(utf8.encode(data)),
        sig,
      );
    } catch (_) {
      return false;
    }
  }

  String _getPublicKeyPem() {
    return '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE${_publicKey.Q!.getEncoded(false).take(30).join()}\n-----END PUBLIC KEY-----';
  }

  /// Builds the exact map of fields included in the cryptographic signature payload.
  ///
  /// A7: v4 adds `sanitizationLevel`, `scope`, the ordered `stepsExecuted`
  /// list and a `partitions[]` list. v1–v3 payloads are kept byte-for-byte so
  /// certificates issued by older builds still verify.
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
    String? scope,
    String? limitation,
    List<Map<String, dynamic>>? partitionsWiped,
    String? sanitizationLevel,
    List<String>? stepsExecuted,
    int? bytesOverwritten,
    int? totalDeviceBytes,
    // B5: boot-environment claim ("live"/"normal"/"container"), signed only
    // when present so pre-B5 v4 certificates keep verifying byte-identically.
    // The disk model stays a recorded display field; the serial is the signed
    // device identity.
    String? bootEnvironment,
    // C7: issuing platform + engine backend name, signed only when present
    // so pre-C7 v4 certificates keep verifying byte-identically.
    String? platform,
    String? backend,
    // Phase F: optional post-wipe format-step record, signed only when a
    // format actually ran so wipe-only v4 certificates stay byte-identical.
    FilesystemRecreationRecord? filesystemRecreation,
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
    if (certVersion == 4) {
      return {
        'certVersion': 4,
        'certificateId': certificateId,
        'jobId': jobId,
        'deviceSerial': deviceSerial,
        'method': method,
        'sanitizationCategory': sanitizationCategory ?? 'Clear',
        'executionMode': executionMode ?? 'simulated',
        'sanitizationLevel': sanitizationLevel ?? 'Clear',
        'scope': scope ?? 'full',
        'limitation': ?limitation,
        'partitions': ?partitionsWiped,
        'stepsExecuted': ?stepsExecuted,
        'bytesOverwritten': ?bytesOverwritten,
        'totalDeviceBytes': ?totalDeviceBytes,
        'bootEnvironment': ?bootEnvironment,
        'platform': ?platform,
        'backend': ?backend,
        if (filesystemRecreation != null)
          'filesystemRecreation': filesystemRecreation.toJson(),
        'evidenceHash': evidenceHash,
        'result': result,
        'timestamp': timestamp,
        'warningLine': ?warningLine,
      };
    }
    if (certVersion == 3) {
      return {
        'certVersion': 3,
        'certificateId': certificateId,
        'jobId': jobId,
        'deviceSerial': deviceSerial,
        'method': method,
        'sanitizationCategory': sanitizationCategory ?? 'Clear',
        'executionMode': executionMode ?? 'simulated',
        'scope': scope ?? 'partial',
        'limitation':
            limitation ??
            'Partition wipe: partition table and unselected sectors are not overwritten',
        'partitionsWiped': ?partitionsWiped,
        'bytesOverwritten': ?bytesOverwritten,
        'totalDeviceBytes': ?totalDeviceBytes,
        'evidenceHash': evidenceHash,
        'result': result,
        'timestamp': timestamp,
        'warningLine': ?warningLine,
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

    final executedLower = (actualMethodExecuted ?? method.displayName)
        .toLowerCase()
        .trim();

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

  /// Generates a signed SanitizationCertificate (A7: payload v4).
  SanitizationCertificate generateCertificate({
    required SanitizationJob job,
    required VerificationEvidence evidence,
    String executionMode = 'simulated',
    String? actualMethodExecuted,
    String? sanitizationCategory,
    String? warningLine,
    String? operatorNote,
    List<String>? stepsExecuted,
    int? verificationSampleCount,
    double? verificationEntropyScore,
    // B5: boot environment the wipe ran in ("live"/"normal"/"container");
    // signed so the live-medium claim cannot be forged after the fact.
    String? bootEnvironment,
    // Phase F: optional format-step record (present only when the operator
    // recreated a filesystem after the verified wipe).
    FilesystemRecreationRecord? filesystemRecreation,
    bool? wipeCompleted,
    String? failedStage,
    String? engineStderr,
    String? targetMountState,
    String? siblingMountState,
  }) {
    final DateTime now = DateTime.now();
    final String certId =
        'ZT-CERT-${now.millisecondsSinceEpoch.toString().substring(5)}';

    final String resultStr = evidence.verifiedPassed ? 'SUCCESS' : 'FAILED';
    final bool hasVerificationEvidence =
        FailureReportWording.hasUsableEvidence(evidence);
    final String verificationSummary = !hasVerificationEvidence
        ? FailureReportWording.verificationNotRun
        : evidence.verifiedPassed
        ? '${verificationSampleCount ?? 50}/${verificationSampleCount ?? 50} Sector Samples Passed Zero Readback Verification (${evidence.evidenceHash.substring(0, min(12, evidence.evidenceHash.length))}...)'
        : 'Sample Verification Failed - Non-Zero Data Detected at Target Offsets';

    final methodToRecord =
        actualMethodExecuted ?? job.effectiveMethod.displayName;

    final category =
        sanitizationCategory ??
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
            job.recommendedMethod ==
                SanitizationMethod.physicalDestructionRecommended ||
            job.recommendedMethod ==
                SanitizationMethod.unsupportedFlagForDestroy) &&
        job.effectiveMethod !=
            SanitizationMethod.physicalDestructionRecommended &&
        job.effectiveMethod != SanitizationMethod.unsupportedFlagForDestroy) {
      finalWarningLine =
          'WARNING: User proceeded with overwrite despite NIST SP 800-88 Destroy recommendation. Data may be retained in unmapped flash blocks.';
    }

    final supportLevel = computeSupportLevel(job.device).displayName;
    final busType = job.device.busType;
    final timestampStr = (job.endTime ?? now).toIso8601String();

    // C7: identity of the issuing platform backend (Linux today) — signed
    // into every newly issued v4 certificate. Older certificates simply
    // lack these fields and still verify byte-identically.
    final issuingBackend = currentPlatformBackend();

    final bool isPartition = job.isPartitionScope;
    // A7: every newly issued certificate uses payload v4 (scope, partitions[],
    // ordered steps executed, sanitization level, limitations). Older v1–v3
    // certificates remain verifiable through buildSigningPayload.
    const int version = 4;
    final String scope = isPartition ? 'partial' : 'full';
    final String? limitation = isPartition
        ? 'Partition wipe: partition table and unselected sectors are not overwritten'
        : (category == 'Clear' && _isFlashWithoutPurge(job.device)
              ? 'Clear only: overwrite cannot reach remapped or over-provisioned flash blocks'
              : null);
    // B4: record every partition the job actually targeted — the sequential
    // subset wipe lists all selected partitions in one certificate.
    final List<PartitionInfo> wipedParts = job.isPartitionScope
        ? (job.targetPartitions.isEmpty && job.targetPartition != null
              ? [job.targetPartition!]
              : job.targetPartitions)
        : const [];
    final List<Map<String, dynamic>>? partitionsWiped = wipedParts.isEmpty
        ? null
        : [
            for (final p in wipedParts)
              {
                'name': p.name,
                'partition_number': p.partitionNumber,
                'start_sector': p.startSector,
                'size_bytes': p.sizeBytes,
              },
          ];
    // NIST SP 800-88 level this wipe actually achieved, derived from the
    // executed-method category (never from the device's capability alone).
    final String sanitizationLevel = category == 'Purge'
        ? 'Purge'
        : category == 'Failed'
        ? 'Failed'
        : 'Clear';
    // Ordered steps actually executed: the engine command log wins when the
    // caller passes it; the timestamped job log is the fallback (simulated
    // mode / engine log unavailable).
    final List<String>? steps =
        stepsExecuted ??
        (job.logs.isNotEmpty ? List<String>.from(job.logs) : null);
    // B4: bytes overwritten = sum of every targeted partition (identical to
    // the single-partition value when only one partition was selected).
    final int? bytesOverwritten = isPartition
        ? wipedParts.fold<int>(0, (sum, p) => sum + p.sizeBytes)
        : null;
    final int totalDeviceBytes = job.device.capacityBytes;

    final Map<String, dynamic> payloadToSign = buildSigningPayload(
      certVersion: version,
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
      scope: scope,
      limitation: limitation,
      partitionsWiped: partitionsWiped,
      sanitizationLevel: sanitizationLevel,
      stepsExecuted: steps,
      bytesOverwritten: bytesOverwritten,
      totalDeviceBytes: totalDeviceBytes,
      bootEnvironment: bootEnvironment,
      platform: issuingBackend.platformName,
      backend: issuingBackend.backendId,
      filesystemRecreation: filesystemRecreation,
    );

    final String payloadJson = jsonEncode(payloadToSign);
    final String signatureHex = _signData(payloadJson);

    return SanitizationCertificate(
      certVersion: version,
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
      scope: scope,
      limitation: limitation,
      partitionsWiped: partitionsWiped,
      sanitizationLevel: sanitizationLevel,
      stepsExecuted: steps,
      bytesOverwritten: bytesOverwritten,
      totalDeviceBytes: totalDeviceBytes,
      bootEnvironment: bootEnvironment,
      platform: issuingBackend.platformName,
      backend: issuingBackend.backendId,
      filesystemRecreation: filesystemRecreation,
      wipeCompleted: wipeCompleted ?? job.wipeCompleted,
      failedStage: failedStage ??
          (resultStr == 'FAILED'
              ? (filesystemRecreation != null
                    ? 'format'
                    : ((wipeCompleted ?? job.wipeCompleted) && !evidence.verifiedPassed
                          ? 'verify'
                          : ((engineStderr ?? '').toLowerCase().contains('table re-read') ||
                                  (engineStderr ?? '').toLowerCase().contains('partition table re-read') ||
                                  (engineStderr ?? '').toLowerCase().contains('blkrrpart')
                              ? 'table re-read'
                              : ((engineStderr ?? '').toLowerCase().contains('umount') ||
                                      (engineStderr ?? '').toLowerCase().contains('unmount') ||
                                      job.status == JobStatus.unmounting
                                  ? 'unmount'
                                  : (job.logs.any((l) =>
                                          l.toLowerCase().contains('writing to media') ||
                                          l.toLowerCase().contains('pass 1 of') ||
                                          l.toLowerCase().contains('progress: [overwrite]'))
                                      ? 'overwrite'
                                      : 'guard')))))
              : null),
      engineStderr: engineStderr,
      targetMountState: targetMountState ??
          (resultStr == 'FAILED'
              ? (job.isPartitionScope && job.targetPartition != null
                    ? '${job.targetPartition!.devicePath}: ${job.targetPartition!.isMounted ? "mounted at ${job.targetPartition!.mountPoint}" : "unmounted"}'
                    : '${job.device.name}: ${(job.device.mountPoint != null && job.device.mountPoint!.isNotEmpty) ? "mounted at ${job.device.mountPoint}" : "unmounted"}')
              : null),
      siblingMountState: siblingMountState ??
          (resultStr == 'FAILED'
              ? (job.isPartitionScope
                    ? (job.device.partitions
                              .where((p) => p.devicePath != job.targetPartition?.devicePath)
                              .map((p) =>
                                  '${p.name}: ${p.isMounted ? "mounted at ${p.mountPoint}" : "unmounted"}')
                              .join(', ')
                              .isNotEmpty
                          ? job.device.partitions
                              .where((p) => p.devicePath != job.targetPartition?.devicePath)
                              .map((p) =>
                                  '${p.name}: ${p.isMounted ? "mounted at ${p.mountPoint}" : "unmounted"}')
                              .join(', ')
                          : 'None')
                    : 'None')
              : null),
    );
  }

  /// Phase F: re-sign an already issued (v4) certificate with an additional
  /// format-step record. The wipe fields are copied verbatim from [cert], so
  /// the only change in the signed payload is the new
  /// `filesystemRecreation` entry. Certificates without a format step are
  /// never touched.
  SanitizationCertificate withFilesystemRecreation(
    SanitizationCertificate cert,
    FilesystemRecreationRecord record,
  ) {
    final payloadToSign = buildSigningPayload(
      certVersion: cert.certVersion,
      certificateId: cert.certificateId,
      jobId: cert.jobId,
      deviceSerial: cert.deviceSerial,
      method: cert.method,
      sanitizationCategory: cert.sanitizationCategory,
      executionMode: cert.executionMode,
      evidenceHash: cert.evidence.evidenceHash,
      result: cert.result,
      timestamp: cert.endTime.toIso8601String(),
      warningLine: cert.warningLine,
      scope: cert.scope,
      limitation: cert.limitation,
      partitionsWiped: cert.partitionsWiped,
      sanitizationLevel: cert.sanitizationLevel,
      stepsExecuted: cert.stepsExecuted,
      bytesOverwritten: cert.bytesOverwritten,
      totalDeviceBytes: cert.totalDeviceBytes,
      bootEnvironment: cert.bootEnvironment,
      platform: cert.platform,
      backend: cert.backend,
      filesystemRecreation: record,
    );

    return SanitizationCertificate(
      certVersion: cert.certVersion,
      certificateId: cert.certificateId,
      jobId: cert.jobId,
      deviceModel: cert.deviceModel,
      deviceSerial: cert.deviceSerial,
      mediaType: cert.mediaType,
      capacity: cert.capacity,
      method: cert.method,
      standardReference: cert.standardReference,
      sanitizationCategory: cert.sanitizationCategory,
      busType: cert.busType,
      supportLevel: cert.supportLevel,
      executionMode: cert.executionMode,
      operatorNote: cert.operatorNote,
      warningLine: cert.warningLine,
      verificationSampleCount: cert.verificationSampleCount,
      verificationEntropyScore: cert.verificationEntropyScore,
      simulationDisclaimer: cert.simulationDisclaimer,
      startTime: cert.startTime,
      endTime: cert.endTime,
      result: cert.result,
      verificationSummary: cert.verificationSummary,
      evidence: cert.evidence,
      softwareVersion: cert.softwareVersion,
      signature: _signData(jsonEncode(payloadToSign)),
      publicKeyPem: cert.publicKeyPem,
      scope: cert.scope,
      limitation: cert.limitation,
      partitionsWiped: cert.partitionsWiped,
      bytesOverwritten: cert.bytesOverwritten,
      totalDeviceBytes: cert.totalDeviceBytes,
      sanitizationLevel: cert.sanitizationLevel,
      stepsExecuted: cert.stepsExecuted,
      bootEnvironment: cert.bootEnvironment,
      platform: cert.platform,
      backend: cert.backend,
      filesystemRecreation: record,
    );
  }

  /// Flash media without any firmware purge capability: software overwrite is
  /// Clear-only (cannot reach remapped / over-provisioned blocks).
  static bool _isFlashWithoutPurge(DeviceProfile device) =>
      device.mediaTechnology == MediaTechnology.flash &&
      !device.supportsAtaSanitize &&
      !device.supportsNvmeSanitize &&
      !device.supportsEmmcSanitize &&
      !device.supportsAtaSecureErase &&
      !device.isHardwareEncrypted;

  /// Test-only signing entry point so fixture suites can mint genuine v1–v3
  /// payload signatures against the active keypair.
  @visibleForTesting
  String signPayloadForTesting(String payloadJson) => _signData(payloadJson);

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
    final sanitizationCategory =
        certJson['sanitizationCategory'] as String? ?? 'Clear';
    final executionMode = certJson['executionMode'] as String? ?? 'simulated';
    final scope = certJson['scope'] as String?;
    final limitation = certJson['limitation'] as String?;
    // v4 stores partitions under 'partitions'; accept the v3 key as fallback.
    final rawWiped =
        ((certVer >= 4
                ? (certJson['partitions'] ?? certJson['partitionsWiped'])
                : certJson['partitionsWiped'])
            as List<dynamic>?);
    final partitionsWiped = rawWiped
        ?.map((e) => Map<String, dynamic>.from(e as Map))
        .toList();
    final sanitizationLevel = certJson['sanitizationLevel'] as String?;
    final stepsExecuted = (certJson['stepsExecuted'] as List<dynamic>?)
        ?.map((e) => e.toString())
        .toList();
    final bytesOverwritten = (certJson['bytesOverwritten'] as num?)?.toInt();
    final totalDeviceBytes = (certJson['totalDeviceBytes'] as num?)?.toInt();
    // B5: optional signed boot-environment claim; absent on pre-B5 v4 certs.
    final bootEnvironment = certJson['bootEnvironment'] as String?;
    // C7: optional signed platform/backend claim; absent on pre-C7 certs.
    final platform = certJson['platform'] as String?;
    final backend = certJson['backend'] as String?;
    // Phase F: optional signed format-step record; absent on wipe-only certs.
    final rawFormat = certJson['filesystemRecreation'];
    final filesystemRecreation = rawFormat is Map
        ? FilesystemRecreationRecord.fromJson(
            Map<String, dynamic>.from(rawFormat),
          )
        : null;

    final evidenceHash = (certJson['evidence'] is Map)
        ? certJson['evidence']['evidenceHash'] as String? ?? ''
        : certJson['evidenceHash'] as String? ?? '';

    final timestamp =
        certJson['timestamp'] as String? ??
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
      scope: scope,
      limitation: limitation,
      partitionsWiped: partitionsWiped,
      sanitizationLevel: sanitizationLevel,
      stepsExecuted: stepsExecuted,
      bytesOverwritten: bytesOverwritten,
      totalDeviceBytes: totalDeviceBytes,
      bootEnvironment: bootEnvironment,
      platform: platform,
      backend: backend,
      filesystemRecreation: filesystemRecreation,
    );

    return _verifySignature(jsonEncode(payload), signature);
  }

  /// Generate a legacy v1 certificate signed with the active key (used for test fixtures).
  SanitizationCertificate generateLegacyV1Certificate({
    required SanitizationJob job,
    required VerificationEvidence evidence,
  }) {
    final DateTime now = DateTime.now();
    final String certId =
        'ZT-CERT-LEGACY-${now.millisecondsSinceEpoch.toString().substring(5)}';
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
                  padding: const pw.EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 8,
                  ),
                  margin: const pw.EdgeInsets.only(bottom: 12),
                  decoration: pw.BoxDecoration(
                    color: PdfColors.amber100,
                    borderRadius: pw.BorderRadius.circular(6),
                    border: pw.Border.all(
                      color: PdfColors.amber800,
                      width: 1.5,
                    ),
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
                  padding: const pw.EdgeInsets.symmetric(
                    horizontal: 12,
                    vertical: 6,
                  ),
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

              // Scope Limitation Box (if present, e.g. partition wipe)
              if (cert.limitation != null)
                pw.Container(
                  width: double.infinity,
                  padding: const pw.EdgeInsets.symmetric(
                    horizontal: 12,
                    vertical: 6,
                  ),
                  margin: const pw.EdgeInsets.only(bottom: 12),
                  decoration: pw.BoxDecoration(
                    color: PdfColors.orange50,
                    borderRadius: pw.BorderRadius.circular(4),
                    border: pw.Border.all(color: PdfColors.orange400),
                  ),
                  child: pw.Text(
                    'SCOPE LIMITATION: ${cert.limitation!}',
                    style: pw.TextStyle(
                      fontSize: 8.5,
                      color: PdfColors.orange900,
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
                        style: const pw.TextStyle(
                          fontSize: 10,
                          color: PdfColors.grey600,
                        ),
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
                padding: const pw.EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 8,
                ),
                decoration: pw.BoxDecoration(
                  color: cert.result == 'SUCCESS'
                      ? PdfColors.green100
                      : PdfColors.red100,
                  borderRadius: pw.BorderRadius.circular(6),
                  border: pw.Border.all(
                    color: cert.result == 'SUCCESS'
                        ? PdfColors.green700
                        : PdfColors.red700,
                  ),
                ),
                child: pw.Row(
                  mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                  children: [
                    pw.Text(
                      'SANITIZATION RESULT: ${cert.result}',
                      style: pw.TextStyle(
                        fontWeight: pw.FontWeight.bold,
                        color: cert.result == 'SUCCESS'
                            ? PdfColors.green900
                            : PdfColors.red900,
                      ),
                    ),
                    pw.Text(
                      'EXECUTION MODE: ${cert.executionMode.toUpperCase()}',
                      style: pw.TextStyle(
                        fontSize: 9,
                        fontWeight: pw.FontWeight.bold,
                        color: cert.executionMode == 'real'
                            ? PdfColors.green900
                            : PdfColors.amber900,
                      ),
                    ),
                  ],
                ),
              ),
              pw.SizedBox(height: 16),

              // Device & Method Table
              pw.Text(
                '1. SANITIZATION TARGET & METHOD',
                style: pw.TextStyle(
                  fontWeight: pw.FontWeight.bold,
                  fontSize: 12,
                ),
              ),
              pw.SizedBox(height: 6),
              pw.TableHelper.fromTextArray(
                headerStyle: pw.TextStyle(
                  fontWeight: pw.FontWeight.bold,
                  fontSize: 9,
                ),
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
                  if (cert.sanitizationLevel != null)
                    ['Sanitization Level (NIST)', cert.sanitizationLevel!],
                  if (cert.scope != null)
                    [
                      'Scope',
                      cert.scope == 'partial'
                          ? 'Partition (partial)'
                          : 'Full device',
                    ],
                  if (cert.partitionsWiped != null &&
                      cert.partitionsWiped!.isNotEmpty)
                    [
                      FailureReportWording.partitionHeading(
                        cert,
                      ).replaceFirst(RegExp(r':$'), ''),
                      cert.partitionsWiped!
                          .map(
                            (p) =>
                                p['name'] ??
                                'partition #${p['partition_number']}',
                          )
                          .join(', '),
                    ],
                  // B5: where the wipe ran from (live medium vs installed
                  // system) — signed, so the claim is verifiable.
                  if (cert.bootEnvironmentDisplay != null)
                    ['Boot Environment', cert.bootEnvironmentDisplay!],
                  // Phase F: separate format step, recorded only when it ran.
                  if (cert.filesystemRecreation != null) ...[
                    [
                      'Filesystem Recreated',
                      '${cert.filesystemRecreation!.fsType} via ${cert.filesystemRecreation!.tool}',
                    ],
                    [
                      'Volume Label',
                      cert.filesystemRecreation!.label.isEmpty
                          ? '(none)'
                          : cert.filesystemRecreation!.label,
                    ],
                    ['Format Time', cert.filesystemRecreation!.time],
                    [
                      'Sanitization Verified Before Format',
                      cert
                              .filesystemRecreation!
                              .sanitizationVerifiedBeforeFormat
                          ? 'Yes'
                          : 'No',
                    ],
                    if (cert.filesystemRecreation!.partitionTableCreated)
                      [
                        'Partition Table Created',
                        (cert.filesystemRecreation!.partitionTableType ?? 'yes')
                            .toUpperCase(),
                      ],
                  ],
                  ['Standard Reference', cert.standardReference],
                  [
                    'Execution Time',
                    '${cert.startTime.toString().substring(0, 19)} to ${cert.endTime.toString().substring(11, 19)}',
                  ],
                  if (cert.operatorNote != null)
                    ['Operator Note', cert.operatorNote!],
                ],
              ),
              pw.SizedBox(height: 16),

              // Evidence & Verification
              pw.Text(
                '2. VERIFICATION & SAMPLE EVIDENCE',
                style: pw.TextStyle(
                  fontWeight: pw.FontWeight.bold,
                  fontSize: 12,
                ),
              ),
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
                    if (FailureReportWording.verificationRan(cert)) ...[
                      pw.Text(
                        'Verification Summary: ${cert.verificationSummary}',
                        style: pw.TextStyle(
                          fontSize: 8.5,
                          fontWeight: pw.FontWeight.bold,
                        ),
                      ),
                      pw.SizedBox(height: 3),
                      pw.Text(
                        'Master Evidence Hash: ${cert.evidence.evidenceHash}',
                        style: const pw.TextStyle(
                          fontSize: 8,
                          color: PdfColors.grey800,
                        ),
                      ),
                      if (cert.verificationEntropyScore != null) ...[
                        pw.SizedBox(height: 3),
                        pw.Text(
                          'Shannon Entropy Score: ${cert.verificationEntropyScore!.toStringAsFixed(4)}',
                          style: const pw.TextStyle(
                            fontSize: 8,
                            color: PdfColors.grey800,
                          ),
                        ),
                      ],
                    ] else
                      pw.Text(
                        FailureReportWording.verificationNotRun,
                        style: pw.TextStyle(
                          fontSize: 8.5,
                          fontWeight: pw.FontWeight.bold,
                        ),
                      ),
                    pw.SizedBox(height: 3),
                    if (cert.stepsExecuted != null &&
                        cert.stepsExecuted!.isNotEmpty) ...[
                      pw.Text(
                        'Executed Steps (ordered, ${cert.stepsExecuted!.length}):',
                        style: pw.TextStyle(
                          fontSize: 8,
                          fontWeight: pw.FontWeight.bold,
                        ),
                      ),
                      ...cert.stepsExecuted!
                          .take(20)
                          .map(
                            (s) => pw.Text(
                              '• $s',
                              style: const pw.TextStyle(
                                fontSize: 7.5,
                                color: PdfColors.grey800,
                              ),
                            ),
                          ),
                      if (cert.stepsExecuted!.length > 20)
                        pw.Text(
                          '… ${cert.stepsExecuted!.length - 20} more steps recorded in the audit log',
                          style: const pw.TextStyle(
                            fontSize: 7.5,
                            color: PdfColors.grey600,
                          ),
                        ),
                      pw.SizedBox(height: 3),
                    ],
                    pw.Text(
                      'Limitations Disclaimer: ${cert.evidence.limitations}',
                      style: const pw.TextStyle(
                        fontSize: 7.5,
                        color: PdfColors.grey700,
                      ),
                    ),
                  ],
                ),
              ),
              pw.SizedBox(height: 16),

              // ECDSA Cryptographic Proof
              pw.Text(
                '3. CRYPTOGRAPHIC AUDIT SIGNATURE',
                style: pw.TextStyle(
                  fontWeight: pw.FontWeight.bold,
                  fontSize: 12,
                ),
              ),
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
                    pw.Text(
                      'Algorithm: ECDSA P-256 / SHA-256',
                      style: pw.TextStyle(
                        fontSize: 8.5,
                        fontWeight: pw.FontWeight.bold,
                      ),
                    ),
                    pw.SizedBox(height: 2),
                    pw.Text(
                      'Signature: ${cert.signature}',
                      style: const pw.TextStyle(
                        fontSize: 7,
                        color: PdfColors.blue900,
                      ),
                    ),
                    pw.SizedBox(height: 3),
                    pw.Text(
                      'Software: ${cert.softwareVersion}',
                      style: const pw.TextStyle(
                        fontSize: 7.5,
                        color: PdfColors.grey700,
                      ),
                    ),
                  ],
                ),
              ),

              pw.Spacer(),

              // Footer
              pw.Divider(color: PdfColors.grey300),
              pw.Row(
                mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                children: [
                  pw.Text(
                    'SIH25070 — Team VCSE_DataCircuits',
                    style: const pw.TextStyle(
                      fontSize: 8,
                      color: PdfColors.grey600,
                    ),
                  ),
                  pw.Text(
                    'Page 1 of 1',
                    style: const pw.TextStyle(
                      fontSize: 8,
                      color: PdfColors.grey600,
                    ),
                  ),
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
