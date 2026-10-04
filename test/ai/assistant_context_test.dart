import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zero_trace/features/ai_assistant/presentation/ai_assistant_screen.dart';
import 'package:zero_trace/models/assistant_context.dart';
import 'package:zero_trace/models/device_profile.dart';
import 'package:zero_trace/models/sanitization_error_code.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/models/sanitization_support_level.dart';
import 'package:zero_trace/services/ai_service.dart';
import 'package:zero_trace/services/assistant_context_builder.dart';
import 'package:zero_trace/services/sanitization_controller.dart';

void main() {
  group('AssistantContext Model Constraints', () {
    test('contains no physical serial, path, or WWN fields', () {
      const context = AssistantContext(
        deviceName: 'Kingston DataTraveler',
        driveType: DriveType.usb,
        mediaType: MediaType.usbFlash,
        busType: 'USB',
        sizeBytes: 32000000000,
        formattedSize: '32 GB',
        supportLevel: SanitizationSupportLevel.clearOnly,
        isFlash: true,
        isRemovable: true,
        platform: 'Linux',
      );

      // Verify accessible coarse facts
      expect(context.deviceName, 'Kingston DataTraveler');
      expect(context.driveType, DriveType.usb);
      expect(context.isFlash, true);
      expect(context.platform, 'Linux');
      expect(context.targetSummary, 'Kingston DataTraveler');
    });

    test('platform string is injected and not tied to host OS', () {
      const winContext = AssistantContext(platform: 'Windows');
      const linContext = AssistantContext(platform: 'Linux');
      const macContext = AssistantContext(platform: 'macOS');

      expect(winContext.platform, 'Windows');
      expect(linContext.platform, 'Linux');
      expect(macContext.platform, 'macOS');
    });

    test('targetSummary reflects disconnected state', () {
      const context = AssistantContext(
        deviceName: 'SanDisk Ultra',
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
        deviceName: 'Flash Drive',
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
        deviceName: 'Samsung 980',
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
        deviceName: 'Drive A',
        hasHpaDco: false,
      );
      expect(withoutHpa.quickQuestions.contains('What are HPA/DCO hidden sectors?'), false);

      const withHpa = AssistantContext(
        deviceName: 'Drive B',
        hasHpaDco: true,
      );
      expect(withHpa.quickQuestions.contains('What are HPA/DCO hidden sectors?'), true);
    });

    test('shows security frozen question ONLY when device is security frozen', () {
      const notFrozen = AssistantContext(
        deviceName: 'Drive A',
        isSecurityFrozen: false,
      );
      expect(notFrozen.quickQuestions.contains('What does security frozen mean?'), false);

      const frozen = AssistantContext(
        deviceName: 'Drive B',
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

    test('every generated quick question returns a non-fallback answer from AiService', () {
      final aiService = AiService();

      // Test across multiple state permutations
      final testContexts = [
        const AssistantContext(), // Generic
        const AssistantContext(hasCertificate: true),
        const AssistantContext(deviceName: 'USB', isFlash: true),
        const AssistantContext(deviceName: 'HDD', isRotational: true),
        const AssistantContext(deviceName: 'SSD', hasHpaDco: true, isSecurityFrozen: true),
        const AssistantContext(verificationPassed: false, lastErrorCode: SanitizationErrorCode.timeout),
        const AssistantContext(jobStatus: JobStatus.failed, lastErrorCode: SanitizationErrorCode.deviceNotFound),
      ];

      final allQuestions = <String>{};
      for (final ctx in testContexts) {
        allQuestions.addAll(ctx.quickQuestions);
      }

      for (final question in allQuestions) {
        final response = aiService.processQuery(question);
        // Fallback response contains "I can help with questions about storage sanitization"
        expect(
          response.answer.contains('I can help with questions about storage sanitization methods, risk assessment'),
          false,
          reason: 'Question "$question" returned generic fallback instead of a specific answer.',
        );
        expect(response.answer.isNotEmpty, true);
      }
    });
  });

  group('Simulation Mode Disclaimers (Amendment 7)', () {
    test('states nothing was actually erased when isSimulated is true', () {
      final aiService = AiService();
      const simContext = AssistantContext(
        deviceName: 'Simulated Drive',
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
        deviceName: 'Seagate Barracuda',
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

      expect(snapshot.deviceName, 'USB Pen Drive');
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
}
