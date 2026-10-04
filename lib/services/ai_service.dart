/// AI Service for Zero Trace 2.0
/// Provides structured, advisory-only AI responses.
///
/// SAFETY: This service NEVER generates shell commands, NEVER executes
/// arbitrary operations, and NEVER bypasses user confirmation or policy validation.
/// All output is advisory and must pass through the policy layer before any action.
library;

import '../models/assistant_context.dart';
import '../models/device_profile.dart';
import '../models/sanitization_error_code.dart';
import 'knowledge/bm25_retriever.dart';
import 'knowledge/knowledge_entry.dart';

class AiContext {
  final String? mediaType;
  final String? capacity;
  final bool? sanitizeAvailable;
  final bool? cryptoEraseAvailable;
  final bool? mounted;
  final String? dataSensitivity;
  final String? question;

  const AiContext({
    this.mediaType,
    this.capacity,
    this.sanitizeAvailable,
    this.cryptoEraseAvailable,
    this.mounted,
    this.dataSensitivity,
    this.question,
  });
}

class AiResponse {
  final String answer;
  final String? recommendedMethod;
  final String? reason;
  final String? riskLevel;
  final List<String> warnings;
  final String? researchBasis;
  final String? targetSummary;
  final bool isSimulated;
  final bool isFallback;
  final String handlerId;
  final List<String> kbEntryIds;

  const AiResponse({
    required this.answer,
    this.recommendedMethod,
    this.reason,
    this.riskLevel,
    this.warnings = const [],
    this.researchBasis,
    this.targetSummary,
    this.isSimulated = false,
    this.isFallback = false,
    this.handlerId = 'fallback',
    this.kbEntryIds = const [],
  });
}

class AiService {
  final BM25Retriever? retriever;

  const AiService({this.retriever});

  /// Explain an error code using structured root cause and next steps.
  AiResponse explainError(SanitizationErrorCode code, {AssistantContext? context}) {
    final explanation = code.explain(
      platform: context?.platform ?? 'unknown',
      jobStarted: context?.jobStarted ?? false,
      isSimulated: context?.isSimulated ?? false,
    );

    final warnings = <String>[];
    if (explanation.dataMayRemain) {
      warnings.add('Data may remain or be partially wiped on the device.');
    }
    if (context?.isSimulated == true || explanation.isSimulated) {
      warnings.add('[SIMULATION MODE] No data was actually written or erased; nothing was actually erased.');
    }

    return AiResponse(
      answer: explanation.toFormattedText(),
      reason: explanation.rootCause,
      riskLevel: explanation.dataMayRemain ? 'HIGH' : 'LOW',
      warnings: warnings,
      isSimulated: context?.isSimulated ?? explanation.isSimulated,
      targetSummary: context?.targetSummary,
      handlerId: 'error_explanation',
    );
  }

  /// Process a user question with optional context or device profile.
  /// Returns a structured advisory response.
  ///
  /// PRECEDENCE (Item 10):
  /// 1. State handlers always answer from AssistantContext (KB adds explanation only).
  /// 2. Conceptual handlers use a KB entry only if a reviewed entry matches;
  ///    otherwise the legacy handler answers with no "Based on" line.
  /// 3. Exactly one answer is returned.
  /// 4. KB answers get handlerId 'kb' and the entry ids used.
  /// 5. Simulated-mode disclaimers still apply to KB answers.
  ///
  /// SAFETY: This method NEVER generates executable commands or mutates state.
  AiResponse processQuery(
    String question, {
    AssistantContext? context,
    DeviceProfile? device,
  }) {
    final q = question.toLowerCase().trim();

    // Resolve effective device
    final effectiveDevice = device ??
        (context?.hasDevice == true
            ? DeviceProfile(
                id: 'context_device',
                name: context!.deviceName!.sanitized,
                serialNumber: 'CONTEXT',
                mediaType: context.mediaType ??
                    (context.isFlash
                        ? MediaType.nvmeSsd
                        : context.isRotational
                            ? MediaType.hdd
                            : MediaType.unknown),
                busType: context.busType ?? 'Unknown',
                capacityBytes: context.sizeBytes ?? 0,
                supportsNvmeSanitize: context.mediaType == MediaType.nvmeSsd,
                supportsAtaSanitize: context.mediaType == MediaType.sataSsd,
                supportsAtaSecureErase: context.isRotational,
                supportsEmmcSanitize: context.mediaType == MediaType.emmc,
                hpaDcoPresent: context.hasHpaDco,
              )
            : null);

    AiResponse response;

    // 1. State handlers: always answer from AssistantContext (highest precedence)
    if (q.contains('explain this error') ||
        q.contains('why did the sanitization fail') ||
        q.contains('what should i do after this error')) {
      final code = context?.lastErrorCode ?? SanitizationErrorCode.unknown;
      response = explainError(code, context: context);
    } else if (q.contains('why did verification fail') || (q.contains('verification') && q.contains('fail'))) {
      response = _verificationFailureResponse();
    } else if (q.contains('security frozen')) {
      response = _securityFrozenResponse();
    } else if (q.contains('cryptographic signature prove') || (q.contains('signature') && q.contains('prove'))) {
      response = _signatureExplanation();
    } else if (q.contains('certificate') || (q.contains('explain') && q.contains('cert'))) {
      response = _certificateExplanation();
    } else if (q.contains('how does overwrite work for hdd') || (q.contains('overwrite') && q.contains('hdd'))) {
      response = _hddOverwriteResponse(effectiveDevice);
    } else if (q.contains('overwrite') && (q.contains('ssd') || q.contains('flash') || q.contains('nvme'))) {
      response = _ssdOverwriteResponse(effectiveDevice);
    } else if (q.contains('recommend') || q.contains('which method') || q.contains('what method')) {
      response = _recommendMethodResponse(effectiveDevice);
    } else if (q.contains('high risk') || (q.contains('why') && q.contains('risk'))) {
      response = _riskExplanationResponse(effectiveDevice);
    } else {
      // 2. Conceptual handlers: check KB first only if a reviewed entry matches
      SearchMatch? kbMatch;
      if (retriever != null) {
        final match = retriever!.findBestMatch(question, context: context);
        if (match != null && match.entry.reviewStatus == KnowledgeReviewStatus.reviewed) {
          kbMatch = match;
        }
      }

      if (kbMatch != null) {
        // KB reviewed answer with 'kb' handlerId and entry id
        response = AiResponse(
          answer: kbMatch.entry.content,
          researchBasis: 'Based on: ${kbMatch.entry.title}',
          handlerId: 'kb',
          kbEntryIds: [kbMatch.entry.id],
        );
      } else if (q.contains('cryptographic erase') || q.contains('crypto erase')) {
        response = _cryptoEraseExplanation();
      } else if (q.contains('nist') || q.contains('800-88')) {
        response = _nistExplanation();
      } else if (q.contains('pales') || q.contains('ftl') || q.contains('flash translation')) {
        response = _palesExplanation();
      } else if (q.contains('clear') && q.contains('purge')) {
        response = _clearVsPurgeExplanation();
      } else if (q.contains('destroy') || q.contains('physical destruction')) {
        response = _destroyExplanation();
      } else if (q.contains('hpa') || q.contains('dco') || q.contains('hidden')) {
        response = _hpaDcoExplanation();
      } else if (q.contains('wear level') || q.contains('garbage collection') || q.contains('spare block')) {
        response = _flashInternalsExplanation();
      } else {
        // Generic fallback
        response = const AiResponse(
          answer: 'I can help with questions about storage sanitization methods, '
              'risk assessment, verification procedures, NIST standards, and device capabilities. '
              'Try asking about specific topics like "Why is overwrite not recommended for SSDs?" '
              'or "What does cryptographic erase mean?"',
          warnings: [
            'AI responses are advisory only.',
            'All sanitization operations require explicit user confirmation and policy validation.',
          ],
          isFallback: true,
          handlerId: 'fallback',
        );
      }
    }

    // Apply simulation disclaimer if isSimulated is true (Amendment 7)
    if (context?.isSimulated == true) {
      final simWarnings = List<String>.from(response.warnings);
      if (!simWarnings.any((w) => w.contains('[SIMULATION MODE]'))) {
        simWarnings.add('[SIMULATION MODE] No physical storage was modified; nothing was actually erased.');
      }
      final simAnswer = response.answer.contains('[SIMULATION MODE]')
          ? response.answer
          : '${response.answer}\n\n*[SIMULATION MODE] Note: No physical storage was modified; nothing was actually erased during simulation.*';

      return AiResponse(
        answer: simAnswer,
        recommendedMethod: response.recommendedMethod,
        reason: response.reason,
        riskLevel: response.riskLevel,
        warnings: simWarnings,
        researchBasis: response.researchBasis,
        targetSummary: context?.targetSummary,
        isSimulated: true,
        isFallback: response.isFallback,
        handlerId: response.handlerId,
        kbEntryIds: response.kbEntryIds,
      );
    }

    if (context?.targetSummary != null) {
      return AiResponse(
        answer: response.answer,
        recommendedMethod: response.recommendedMethod,
        reason: response.reason,
        riskLevel: response.riskLevel,
        warnings: response.warnings,
        researchBasis: response.researchBasis,
        targetSummary: context?.targetSummary,
        isSimulated: false,
        isFallback: response.isFallback,
        handlerId: response.handlerId,
        kbEntryIds: response.kbEntryIds,
      );
    }

    return response;
  }

  AiResponse _ssdOverwriteResponse(DeviceProfile? device) {
    final deviceInfo = device != null
        ? '\n\nFor your ${device.name} (${device.mediaType.displayName}):'
            ' The Flash Translation Layer (FTL) manages physical-to-logical address mapping,'
            ' which means a logical overwrite may not reach all physical NAND cells.'
        : '';

    return AiResponse(
      answer: 'Conventional logical overwriting is not treated as a reliable universal '
          'sanitization method for SSD/NVMe/flash storage because of the Flash Translation '
          'Layer (FTL). The FTL manages wear leveling, garbage collection, spare blocks, '
          'and over-provisioned regions independently of the host operating system.\n\n'
          'When you write zeros to logical block addresses, the SSD controller may remap '
          'those writes to different physical NAND pages, leaving original data intact on '
          'the old physical pages.$deviceInfo',
      recommendedMethod: device?.supportsNvmeSanitize == true
          ? 'NVMe Sanitize'
          : device?.supportsAtaSanitize == true
              ? 'ATA Sanitize Block Erase'
              : device?.isHardwareEncrypted == true
                  ? 'Cryptographic Erase'
                  : 'Device-supported sanitization mechanism',
      reason: 'Device-level sanitization commands operate below the FTL and can address '
          'all physical storage regions including spare blocks and over-provisioned areas.',
      riskLevel: 'HIGH',
      warnings: [
        'Simple file deletion or formatting does NOT sanitize flash storage.',
        'TRIM alone is insufficient for secure sanitization.',
      ],
      researchBasis: 'PALES research (SSD secure deletion via page group management) '
          'demonstrates that SSD internal architecture fundamentally differs from HDD. '
          'NIST SP 800-88 Rev. 2 recommends device-supported mechanisms for flash media.',
      handlerId: 'ssd_overwrite',
    );
  }

  AiResponse _hddOverwriteResponse(DeviceProfile? device) {
    final name = device != null ? ' for ${device.name}' : '';
    return AiResponse(
      answer: 'For magnetic hard disk drives (HDDs)$name, logical overwriting writes zeros or patterns across addressable Logical Block Addresses (LBAs).\n\n'
          '**NIST SP 800-88 Rev. 2 Assurance:**\n'
          '• **Clear Level**: A full-disk single-pass overwrite satisfies NIST Clear requirements. It protects against simple, non-invasive software data recovery attempts on magnetic media.\n'
          '• **Limitations**: Logical overwriting only reaches addressable sectors. It cannot overwrite bad or reallocated sectors retired by the disk controller, or hidden HPA/DCO sectors.\n'
          '• **Purge Requirement**: For magnetic media containing confidential data leaving organizational control, firmware ATA Secure Erase or physical destruction is required to achieve Purge assurance.',
      recommendedMethod: device?.supportsAtaSecureErase == true
          ? 'ATA Secure Erase (Purge)'
          : 'Single-Pass Zero Overwrite (Clear)',
      reason: 'Logical overwrite provides Clear-level assurance on magnetic media; reallocated sectors remain unaddressed without firmware commands.',
      riskLevel: 'MEDIUM',
      warnings: [
        'Overwriting magnetic media achieves NIST Clear level, not guaranteed physical destruction.',
        'Retired and reallocated bad sectors may still contain remnant data.',
      ],
      researchBasis: 'NIST SP 800-88 Rev. 2 Table A-1: Magnetic Media Sanitization',
      handlerId: 'hdd_overwrite',
    );
  }

  AiResponse _securityFrozenResponse() {
    return const AiResponse(
      answer: 'A "Security Frozen" state indicates that your computer BIOS/UEFI locked the drive\'s ATA security registers during system boot.\n\n'
          '**Why the BIOS freezes the drive:**\n'
          'This is a standard PC motherboard security measure designed to prevent rogue software or malware from setting a hardware lock password on your hard drive.\n\n'
          '**How to resolve:**\n'
          '• **External USB drives**: Unplug the USB cable and reconnect it. Power-cycling resets the drive controller and clears the freeze lock.\n'
          '• **Internal drives**: Put the computer to sleep/suspend for a few seconds and wake it up, or reboot into BIOS/UEFI to review storage security settings.',
      reason: 'BIOS freeze lock blocks hardware sanitize commands until power-cycled.',
      riskLevel: 'LOW',
      warnings: [
        'Hardware sanitize and ATA Secure Erase cannot proceed while the drive is in a frozen state.',
      ],
      handlerId: 'security_frozen',
    );
  }

  AiResponse _signatureExplanation() {
    return const AiResponse(
      answer: 'The cryptographic digital signature on a Zero Trace certificate provides mathematical proof of certificate authenticity and tamper-resistance.\n\n'
          '**What it proves:**\n'
          '• **Origin Authenticity**: The certificate was generated and signed by the Zero Trace engine using an asymmetric cryptographic key (Ed25519 or ECDSA P-256).\n'
          '• **Tamper Detection**: If any field in the certificate (serial number, timestamp, method, or verification results) is modified, the signature check fails immediately.\n\n'
          '**What it does NOT prove:**\n'
          'A signature proves that the recorded evidence has not been tampered with since issuance. It does not physically guarantee that data cannot be recovered by laboratory techniques if an inadequate method was used.',
      researchBasis: 'Zero Trace Cryptographic Proof System / RFC 8032 Ed25519',
      handlerId: 'signature_explanation',
    );
  }

  AiResponse _recommendMethodResponse(DeviceProfile? device) {
    if (device == null) {
      return const AiResponse(
        answer: 'Please select a device first so I can analyze its capabilities '
            'and recommend an appropriate sanitization method.',
        warnings: ['No device context provided.'],
        handlerId: 'recommend_method',
      );
    }

    String method;
    String reason;

    if (device.mediaType == MediaType.hdd) {
      method = device.supportsAtaSecureErase
          ? 'ATA Secure Erase'
          : 'Single-Pass Zero Overwrite';
      reason = 'Magnetic platter HDDs are effectively sanitized via ${device.supportsAtaSecureErase ? "controller-level ATA Secure Erase which covers reallocated sectors (Purge level)" : "full LBA zero-fill overwrite across all addressable sectors (achieving NIST Clear level)"}.';
    } else if (device.mediaType == MediaType.nvmeSsd) {
      method = device.supportsNvmeSanitize
          ? 'NVMe Sanitize'
          : device.isHardwareEncrypted
              ? 'Cryptographic Erase'
              : 'NVMe Format (limited assurance)';
      reason = 'NVMe flash storage requires device-level commands that operate below the FTL.';
    } else if (device.mediaType == MediaType.sataSsd) {
      method = device.supportsAtaSanitize
          ? 'ATA Sanitize Block Erase'
          : device.isHardwareEncrypted
              ? 'Cryptographic Erase'
              : 'ATA Secure Erase (if supported)';
      reason = 'SATA SSDs require firmware-level sanitization to address wear-leveled NAND blocks.';
    } else if (device.mediaType == MediaType.emmc) {
      method = device.supportsEmmcSanitize
          ? 'eMMC Sanitize'
          : 'Physical Destruction Recommended';
      reason = 'eMMC storage uses managed NAND flash requiring controller-level sanitization.';
    } else {
      method = 'Physical Destruction Recommended';
      reason = 'Device capabilities cannot be verified. Physical destruction provides the highest assurance.';
    }

    return AiResponse(
      answer: 'Based on the ${device.name} (${device.mediaType.displayName}, '
          '${device.formattedCapacity}), the recommended sanitization method is:\n\n'
          '**$method**\n\n$reason',
      recommendedMethod: method,
      reason: reason,
      riskLevel: device.mediaType == MediaType.hdd ? 'MEDIUM' : 'HIGH',
      warnings: [
        'This recommendation is advisory. Final method selection requires policy validation.',
        'AI does not execute sanitization operations.',
      ],
      handlerId: 'recommend_method',
    );
  }

  AiResponse _riskExplanationResponse(DeviceProfile? device) {
    if (device == null) {
      return const AiResponse(
        answer: 'Risk level depends on media type, device capabilities, '
            'encryption state, data sensitivity, and intended disposal path. '
            'Select a device for a specific risk analysis.',
        handlerId: 'risk_explanation',
      );
    }

    final factors = <String>[];
    if (device.mediaType == MediaType.sataSsd || device.mediaType == MediaType.nvmeSsd) {
      factors.add('Flash storage with FTL-managed physical mapping');
    }
    if (!device.supportsAtaSanitize && !device.supportsNvmeSanitize && !device.supportsEmmcSanitize) {
      factors.add('No device-level purge mechanism detected');
    }
    if (device.hpaDcoPresent) {
      factors.add('HPA/DCO hidden sectors detected — standard sanitization cannot reach these');
    }
    if (!device.isHardwareEncrypted) {
      factors.add('No hardware encryption — cryptographic erase unavailable');
    }

    return AiResponse(
      answer: 'Risk assessment for ${device.name}:\n\n'
          '${factors.map((f) => '• $f').join('\n')}\n\n'
          '${factors.length >= 2 ? "Multiple risk factors indicate elevated sanitization risk." : "Risk level is based on the detected device characteristics."}',
      riskLevel: factors.length >= 3 ? 'CRITICAL' : factors.length >= 2 ? 'HIGH' : 'MEDIUM',
      warnings: factors,
      researchBasis: 'NIST SP 800-88 Rev. 2 defines risk-based media sanitization categories.',
      handlerId: 'risk_explanation',
    );
  }

  AiResponse _verificationFailureResponse() {
    return const AiResponse(
      answer: 'Verification can fail for several reasons:\n\n'
          '• **Dirty or non-zero sectors**: Sector readback found residual non-zero bytes at sampled LBA offsets.\n'
          '• **Controller timeout**: The device did not respond within the expected timeframe during sampling.\n'
          '• **Device disconnection**: The device was removed or lost power during readback.\n'
          '• **I/O Read error**: Bad physical blocks prevented reading sampled sectors.\n\n'
          'A failed verification means sanitization assurance was not achieved. '
          'Data may remain on the disk. Re-evaluate the drive or flag it for physical destruction.',
      riskLevel: 'CRITICAL',
      warnings: [
        'Failed verification means sanitization assurance is insufficient. Data may remain.',
        'Consider physical destruction for failed devices handling sensitive data.',
      ],
      handlerId: 'verification_failure',
    );
  }

  AiResponse _cryptoEraseExplanation() {
    return const AiResponse(
      answer: 'Cryptographic Erase destroys the encryption key used by a self-encrypting '
          'drive (SED), rendering all stored ciphertext permanently unrecoverable.\n\n'
          '**How it works:**\n'
          '• Drives with TCG OPAL, IEEE 1667, or NVMe crypto erase support encrypt all '
          'data at the hardware level using an internal Media Encryption Key (MEK).\n'
          '• Cryptographic erase destroys the MEK, not the data itself.\n'
          '• Without the key, the encrypted data becomes computationally infeasible to decrypt.\n\n'
          '**Advantages:**\n'
          '• Near-instantaneous execution (seconds, not hours).\n'
          '• Covers all physical regions including spare blocks and over-provisioned areas.\n\n'
          '**Limitations:**\n'
          '• Requires the drive to have been encrypting data from the start.\n'
          '• Relies on correct firmware implementation of key destruction.\n'
          '• Cannot be verified by reading sectors (encrypted data remains, key is gone).',
      recommendedMethod: 'Cryptographic Erase',
      researchBasis: 'NIST SP 800-88 Rev. 2 Purge / IEEE 2883:2022 Cryptographic Erase',
      handlerId: 'crypto_erase',
    );
  }

  AiResponse _certificateExplanation() {
    return const AiResponse(
      answer: 'A Zero Trace sanitization certificate provides auditable evidence of the '
          'sanitization process.\n\n'
          '**Certificate contents:**\n'
          '• Device identification (model, serial, capacity, media type)\n'
          '• Sanitization method applied and compliance standard reference\n'
          '• Execution timestamps\n'
          '• Verification evidence (sector sample readback results)\n'
          '• Master evidence SHA-256 hash\n'
          '• Ed25519 or ECDSA digital signature\n\n'
          '**What the hash proves:**\n'
          'The SHA-256 hash protects the integrity of the evidence record. '
          'It does NOT prove physical erasure — it proves the certificate data has not been modified.\n\n'
          '**What the signature proves:**\n'
          'The digital signature proves the certificate was issued by Zero Trace '
          'and has not been tampered with since issuance.',
      warnings: [
        'The certificate records what was observed, not absolute physical state.',
        'Hash integrity ≠ physical erasure proof.',
      ],
      handlerId: 'certificate_explanation',
    );
  }

  AiResponse _nistExplanation() {
    return const AiResponse(
      answer: 'NIST Special Publication 800-88 Revision 2 defines media sanitization '
          'guidance for information systems.\n\n'
          '**Sanitization Categories:**\n\n'
          '• **CLEAR** — Logical techniques that protect against simple, non-invasive '
          'data recovery (e.g., overwrite). Appropriate for internal reuse or low-sensitivity data.\n\n'
          '• **PURGE** — Physical or logical techniques that render data recovery infeasible '
          'using state-of-the-art laboratory techniques (e.g., device-level sanitize commands, '
          'cryptographic erase). Required for confidential data leaving organizational control.\n\n'
          '• **DESTROY** — Physical destruction rendering the media unusable (e.g., disintegration, '
          'incineration, shredding). Required for the highest sensitivity data.\n\n'
          '• **Cryptographic Erase** — Destruction of encryption keys on self-encrypting devices. '
          'Can satisfy Purge requirements when properly implemented.',
      researchBasis: 'NIST SP 800-88 Rev. 2 / IEEE 2883:2022',
      handlerId: 'nist_standards',
    );
  }

  AiResponse _palesExplanation() {
    return const AiResponse(
      answer: 'PALES (Optimizing Secure Data Deletion in SSDs via Page Group and Reprogram '
          'Speedup) is research demonstrating that SSD secure deletion fundamentally differs '
          'from HDD overwriting.\n\n'
          '**Key insights:**\n\n'
          '• **Flash Translation Layer (FTL)**: SSDs use an internal mapping table between '
          'logical and physical addresses. The host OS cannot directly control which physical '
          'NAND page is written.\n\n'
          '• **Wear Leveling**: The controller distributes writes across all NAND blocks to '
          'extend drive lifespan, potentially leaving old data on previously-used blocks.\n\n'
          '• **Garbage Collection**: The controller reclaims invalid pages asynchronously. '
          'Data marked for deletion may persist until the GC cycle runs.\n\n'
          '• **Spare Blocks / Over-provisioning**: A portion of flash capacity is reserved '
          'by the controller and not addressable by the host.\n\n'
          '**Implication for Zero Trace:**\n'
          'Simple logical overwriting cannot guarantee erasure of all physical flash cells. '
          'Device-supported sanitization commands that operate below the FTL are preferred.',
      researchBasis: 'PALES: Optimizing Secure Data Deletion in SSDs via Page Group and '
          'Reprogram Speedup',
      handlerId: 'pales_research',
    );
  }

  AiResponse _clearVsPurgeExplanation() {
    return const AiResponse(
      answer: '**CLEAR vs PURGE — NIST SP 800-88 Rev. 2:**\n\n'
          '**CLEAR:**\n'
          '• Protects against simple, non-invasive recovery attempts.\n'
          '• Example: Full disk overwrite with zeros or patterns.\n'
          '• Appropriate for: Internal reuse, low-sensitivity data.\n'
          '• Limitation: Does not address hidden/reserved areas, reallocated sectors, '
          'or FTL-managed flash regions.\n\n'
          '**PURGE:**\n'
          '• Renders recovery infeasible using state-of-the-art laboratory techniques.\n'
          '• Examples: ATA Sanitize, NVMe Sanitize, Cryptographic Erase.\n'
          '• Appropriate for: Confidential data, assets leaving organizational control.\n'
          '• Advantage: Operates at the controller/firmware level, addressing physical storage.',
      researchBasis: 'NIST SP 800-88 Rev. 2',
      handlerId: 'clear_vs_purge',
    );
  }

  AiResponse _destroyExplanation() {
    return const AiResponse(
      answer: '**DESTROY — Physical Destruction:**\n\n'
          'Physical destruction renders the storage media completely unusable and '
          'unrecoverable through methods such as:\n\n'
          '• **Disintegration**: Industrial shredding into particles.\n'
          '• **Incineration**: Controlled burning at temperatures that destroy the media substrate.\n'
          '• **Pulverization**: Mechanical crushing to destroy platters or NAND chips.\n'
          '• **Chemical dissolution**: For specialized scenarios.\n\n'
          '**When to use DESTROY:**\n'
          '• Highest classification data (restricted, confidential leaving organization).\n'
          '• Device has no verified sanitization mechanism or failed verification.\n'
          '• Flash storage (USB/SD/SSD) leaving organizational control where purge is unavailable.\n'
          '• Device is degraded or non-functional (cannot execute sanitize commands).\n\n'
          '**Zero Trace role:**\n'
          'Zero Trace flags devices for destruction when software sanitization cannot '
          'provide sufficient assurance. The application does not perform physical destruction.',
      riskLevel: 'CRITICAL',
      handlerId: 'physical_destruction',
    );
  }

  AiResponse _hpaDcoExplanation() {
    return const AiResponse(
      answer: '**HPA (Host Protected Area) and DCO (Device Configuration Overlay):**\n\n'
          'These are regions on a hard drive that are hidden from the operating system '
          'and standard file system tools.\n\n'
          '• **HPA**: A reserved area at the end of the drive that the BIOS or firmware '
          'can use. Data stored here is not visible to the OS.\n\n'
          '• **DCO**: Allows the drive to report a smaller capacity than its actual size, '
          'hiding sectors from all standard access.\n\n'
          '**Security Risk:**\n'
          'Standard overwrite or even some secure erase implementations may not reach '
          'HPA/DCO regions. Sensitive data could remain in these hidden areas.\n\n'
          '**Mitigation:**\n'
          'HPA/DCO should be detected and reported. If present, the risk level is elevated '
          'and additional verification or physical destruction may be recommended.',
      riskLevel: 'HIGH',
      warnings: [
        'HPA/DCO regions are not addressed by standard overwrite.',
        'Device-level sanitize commands may or may not address HPA/DCO.',
      ],
      handlerId: 'hpa_dco',
    );
  }

  AiResponse _flashInternalsExplanation() {
    return const AiResponse(
      answer: '**Flash Storage Internals:**\n\n'
          '**Wear Leveling:**\n'
          'Flash memory cells have a limited number of write/erase cycles. The controller '
          'distributes writes evenly across all blocks to prevent premature failure. This means '
          'a logical overwrite may be mapped to a different physical location.\n\n'
          '**Garbage Collection:**\n'
          'SSDs group pages into blocks. When pages are invalidated (overwritten), they cannot '
          'be immediately reused. The GC process copies valid pages to a new block and erases '
          'the old block. Until GC runs, old data persists physically.\n\n'
          '**Spare Blocks:**\n'
          'A percentage of total flash capacity is reserved as spare blocks for wear leveling '
          'and bad block replacement. These are not addressable by the host and may contain '
          'remnant data.\n\n'
          '**Over-provisioning:**\n'
          'Additional capacity (typically 7-28% beyond advertised) reserved by the controller '
          'for performance and endurance management. Not accessible via standard I/O.',
      researchBasis: 'PALES research / General flash storage architecture',
      handlerId: 'flash_internals',
    );
  }
}
