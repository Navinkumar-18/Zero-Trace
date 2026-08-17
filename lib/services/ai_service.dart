/// AI Service for Zero Trace 2.0
/// Provides structured, advisory-only AI responses.
///
/// SAFETY: This service NEVER generates shell commands, NEVER executes
/// arbitrary operations, and NEVER bypasses user confirmation or policy validation.
/// All output is advisory and must pass through the policy layer before any action.

import '../models/device_profile.dart';

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

  const AiResponse({
    required this.answer,
    this.recommendedMethod,
    this.reason,
    this.riskLevel,
    this.warnings = const [],
    this.researchBasis,
  });
}

class AiService {
  /// Process a user question with optional device context.
  /// Returns a structured advisory response.
  ///
  /// SAFETY: This method NEVER generates executable commands.
  AiResponse processQuery(String question, {DeviceProfile? device}) {
    final q = question.toLowerCase().trim();

    // Pattern-match common questions
    if (q.contains('overwrite') && (q.contains('ssd') || q.contains('flash') || q.contains('nvme'))) {
      return _ssdOverwriteResponse(device);
    }

    if (q.contains('recommend') || q.contains('which method') || q.contains('what method')) {
      return _recommendMethodResponse(device);
    }

    if (q.contains('high risk') || q.contains('why') && q.contains('risk')) {
      return _riskExplanationResponse(device);
    }

    if (q.contains('verification') && q.contains('fail')) {
      return _verificationFailureResponse();
    }

    if (q.contains('cryptographic erase') || q.contains('crypto erase')) {
      return _cryptoEraseExplanation();
    }

    if (q.contains('certificate') || q.contains('explain') && q.contains('cert')) {
      return _certificateExplanation();
    }

    if (q.contains('nist') || q.contains('800-88')) {
      return _nistExplanation();
    }

    if (q.contains('pales') || q.contains('ftl') || q.contains('flash translation')) {
      return _palesExplanation();
    }

    if (q.contains('clear') && q.contains('purge')) {
      return _clearVsPurgeExplanation();
    }

    if (q.contains('destroy') || q.contains('physical destruction')) {
      return _destroyExplanation();
    }

    if (q.contains('hpa') || q.contains('dco') || q.contains('hidden')) {
      return _hpaDcoExplanation();
    }

    if (q.contains('wear level') || q.contains('garbage collection') || q.contains('spare block')) {
      return _flashInternalsExplanation();
    }

    // Generic fallback
    return AiResponse(
      answer: 'I can help with questions about storage sanitization methods, '
          'risk assessment, verification procedures, NIST standards, and device capabilities. '
          'Try asking about specific topics like "Why is overwrite not recommended for SSDs?" '
          'or "What does cryptographic erase mean?"',
      warnings: [
        'AI responses are advisory only.',
        'All sanitization operations require explicit user confirmation and policy validation.',
      ],
    );
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
    );
  }

  AiResponse _recommendMethodResponse(DeviceProfile? device) {
    if (device == null) {
      return const AiResponse(
        answer: 'Please select a device first so I can analyze its capabilities '
            'and recommend an appropriate sanitization method.',
        warnings: ['No device context provided.'],
      );
    }

    String method;
    String reason;

    if (device.mediaType == MediaType.hdd) {
      method = device.supportsAtaSecureErase
          ? 'ATA Secure Erase'
          : 'Single-Pass Zero Overwrite';
      reason = 'Magnetic platter HDDs are effectively sanitized via ${device.supportsAtaSecureErase ? "controller-level ATA Secure Erase which covers reallocated sectors" : "full LBA zero-fill overwrite across all addressable sectors"}.';
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
    );
  }

  AiResponse _riskExplanationResponse(DeviceProfile? device) {
    if (device == null) {
      return const AiResponse(
        answer: 'Risk level depends on media type, device capabilities, '
            'encryption state, data sensitivity, and intended disposal path. '
            'Select a device for a specific risk analysis.',
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
    );
  }

  AiResponse _verificationFailureResponse() {
    return const AiResponse(
      answer: 'Verification can fail for several reasons:\n\n'
          '• **Controller timeout**: The device did not respond within the expected timeframe.\n'
          '• **Non-zero data detected**: Sample readback found non-zero bytes at sampled LBA offsets.\n'
          '• **Device disconnection**: The device was removed during the operation.\n'
          '• **Permission denied**: Insufficient privileges to read device sectors.\n\n'
          'A failed verification means the sanitization assurance level is insufficient. '
          'The device should be re-evaluated and potentially flagged for physical destruction.',
      riskLevel: 'CRITICAL',
      warnings: [
        'Failed verification does NOT mean data is accessible — it means assurance is insufficient.',
        'Consider physical destruction for failed devices handling sensitive data.',
      ],
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
          '• ECDSA P-256 digital signature\n\n'
          '**What the hash proves:**\n'
          'The SHA-256 hash protects the integrity of the evidence record. '
          'It does NOT prove physical erasure — it proves the certificate data has not been modified.\n\n'
          '**What the signature proves:**\n'
          'The ECDSA signature proves the certificate was issued by Zero Trace software '
          'and has not been tampered with since issuance.',
      warnings: [
        'The certificate records what was observed, not absolute physical state.',
        'Hash integrity ≠ physical erasure proof.',
      ],
    );
  }

  AiResponse _nistExplanation() {
    return const AiResponse(
      answer: 'NIST Special Publication 800-88 Revision 2 defines media sanitization '
          'guidance for federal information systems.\n\n'
          '**Sanitization Categories:**\n\n'
          '• **CLEAR** — Logical techniques that protect against simple, non-invasive '
          'data recovery (e.g., overwrite). Appropriate for low-sensitivity data or internal reuse.\n\n'
          '• **PURGE** — Physical or logical techniques that render data recovery infeasible '
          'using state-of-the-art laboratory techniques (e.g., device-level sanitize commands, '
          'cryptographic erase). Required for confidential data leaving organizational control.\n\n'
          '• **DESTROY** — Physical destruction rendering the media unusable (e.g., disintegration, '
          'incineration, shredding). Required for the highest sensitivity data.\n\n'
          '• **Cryptographic Erase** — Destruction of encryption keys on self-encrypting devices. '
          'Can satisfy Purge requirements when properly implemented.',
      researchBasis: 'NIST SP 800-88 Rev. 2 / IEEE 2883:2022',
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
          '• Highest classification data (restricted, top secret).\n'
          '• Device has no verified sanitization mechanism.\n'
          '• Device is degraded or non-functional (cannot execute sanitize commands).\n'
          '• Regulatory or policy requirement mandates physical destruction.\n\n'
          '**Zero Trace role:**\n'
          'Zero Trace flags devices for destruction when software sanitization cannot '
          'provide sufficient assurance. The application does not perform physical destruction.',
      riskLevel: 'CRITICAL',
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
    );
  }
}
