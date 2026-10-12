// Content contract for the four new advisory handlers.
//
// These tests assert honesty constraints, not exact prose:
//  - a partial/partition scope is never described as "wiped";
//  - simulated runs state nothing was actually erased;
//  - "is my data gone" never claims "permanently" or "unrecoverable";
//  - the command-refusal handler emits no shell commands.

import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/assistant_context.dart';
import 'package:zero_trace/models/untrusted_text.dart';
import 'package:zero_trace/services/ai_service.dart';

void main() {
  final ai = AiService();

  group('partition limitations', () {
    test('partial scope is never described as "wiped"', () {
      const ctx = AssistantContext(
        deviceName: UntrustedText('WD Blue'),
        isPartitionScope: true,
        partitionFormattedSize: '500 GB',
      );
      final r = ai.processQuery('What are the limitations of a partition wipe?', context: ctx);
      expect(r.handlerId, 'partition_limitations');
      expect(r.answer.toLowerCase().contains('wiped'), false);
      expect(r.answer.contains('partition table'), true);
    });

    test('flash partition wipe is Clear-level and says nothing was erased when simulated', () {
      const ctx = AssistantContext(
        isPartitionScope: true,
        isFlash: true,
        isSimulated: true,
        partitionFormattedSize: '32 GB',
      );
      final r = ai.processQuery('What are partition wipe limits on a flash drive?', context: ctx);
      expect(r.handlerId, 'partition_limitations');
      expect(r.answer.toLowerCase().contains('clear'), true);
      expect(r.answer.toLowerCase().contains('nothing on the device was actually'), true);
    });
  });

  group('partition overwrite', () {
    test('states the rest of the drive is not sanitized', () {
      const ctx = AssistantContext(
        isPartitionScope: true,
        partitionFormattedSize: '500 GB',
      );
      final r = ai.processQuery('What method should I use for a partition?', context: ctx);
      expect(r.handlerId, 'partition_overwrite');
      expect(r.answer.toLowerCase().contains('partition table'), true);
    });
  });

  group('data status', () {
    test('does not overclaim even when a wipe completed and verification passed', () {
      const ctx = AssistantContext(
        deviceName: UntrustedText('Samsung 980'),
        jobStarted: true,
        wipeCompleted: true,
        verificationPassed: true,
        verificationSampleCount: 100,
      );
      final r = ai.processQuery('Is my data really gone?', context: ctx);
      expect(r.handlerId, 'data_status');
      expect(r.answer.toLowerCase().contains('permanently'), false);
      expect(r.answer.toLowerCase().contains('unrecoverable'), false);
      expect(r.answer.toLowerCase().contains('sampling'), true);
    });

    test('simulated run says nothing was actually erased', () {
      const ctx = AssistantContext(
        jobStarted: true,
        wipeCompleted: true,
        isSimulated: true,
      );
      final r = ai.processQuery('Is my data really gone?', context: ctx);
      expect(r.handlerId, 'data_status');
      expect(r.answer.toLowerCase().contains('nothing was actually'), true);
    });

    test('failed verification leaves data possibly present', () {
      const ctx = AssistantContext(
        jobStarted: true,
        wipeCompleted: true,
        verificationPassed: false,
      );
      final r = ai.processQuery('Is my data recoverable after overwrite?', context: ctx);
      expect(r.handlerId, 'data_status');
      expect(r.answer.toLowerCase().contains('data may remain'), true);
    });

    test('no state means data should still be present', () {
      final r = ai.processQuery('Is my data really gone?');
      expect(r.handlerId, 'data_status');
      expect(r.answer.toLowerCase().contains('still be present') ||
          r.answer.toLowerCase().contains('unchanged'), true);
    });
  });

  group('command refusal', () {
    const questions = [
      'Should I use dd?',
      'Give me a command to wipe my drive',
      'Can you run dd for me?',
      'What shell command runs secure erase?',
      'Just give me the shred syntax',
    ];

    for (final q in questions) {
      test('refuses and emits no shell command: "$q"', () {
        final r = ai.processQuery(q);
        expect(r.handlerId, 'command_refusal');
        for (final banned in const ['dd if=', 'shred ', 'rm -rf', 'sudo ', 'if=/dev']) {
          expect(r.answer.contains(banned), false, reason: 'must not emit "$banned"');
        }
      });
    }
  });
}
