import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/services/engine_failure_message.dart';

/// Exit 3 must always carry the engine's typed reason, and must say so when
/// the engine gave no reason at all.
void main() {
  group('describeEngineFailure exit 3 typed reasons', () {
    test('names the blocking mount point from a guard refusal', () {
      const raw =
          'Error executing sanitize: TargetMounted("/dev/sdb1 is '
          "mounted/active as '/dev/sdb1' (mounted at /mnt/backup)\")";
      final message = describeEngineFailure(3, raw);

      expect(message, contains('exit 3'));
      expect(message, contains('/mnt/backup'));
      expect(message, isNot(contains('TargetMounted(')));
    });

    test('keeps a guard refusal reason instead of only the exit code', () {
      const raw =
          'Error executing sanitize: BootDiskProtection("/dev/sda hosts the '
          'running root filesystem")';
      final message = describeEngineFailure(3, raw);

      expect(message, contains('exit 3'));
      expect(message, contains('/dev/sda hosts the running root filesystem'));
      expect(message, isNot(contains('BootDiskProtection(')));
    });

    test('keeps an identity mismatch reason instead of only the exit code', () {
      const raw =
          'Error executing sanitize: IdentityMismatch("target /dev/sdb no '
          'longer matches the validated serial")';
      final message = describeEngineFailure(3, raw);

      expect(message, contains('exit 3'));
      expect(
        message,
        contains('target /dev/sdb no longer matches the validated serial'),
      );
      expect(message, isNot(contains('IdentityMismatch(')));
    });

    test(
      'empty stderr says the engine gave no reason and points to History',
      () {
        const expected =
            'The engine stopped before completing the operation (exit 3). '
            'The engine gave no reason; see History.';

        expect(describeEngineFailure(3, ''), expected);
        expect(describeEngineFailure(3, '   \n\t'), expected);
      },
    );

    test('exit 3 with a reason does not use the no-reason fallback', () {
      final message = describeEngineFailure(3, 'guard refused: /dev/sda');

      expect(message, contains('guard refused: /dev/sda'));
      expect(message, isNot(contains('The engine gave no reason')));
    });
  });
}
