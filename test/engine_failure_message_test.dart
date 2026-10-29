import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/services/engine_failure_message.dart';

/// Phase P4-fix: a non-zero `zt_engine` exit must surface a typed,
/// actionable reason — never just `Process exited with code N`.
void main() {
  group('describeEngineFailure', () {
    test('mounted-target refusal names the blocking mount point', () {
      // Exactly what the CLI prints for a guard refusal (exit 3):
      // `eprintln!("Error executing sanitize: {:?}", err)`.
      const raw =
          'Error executing sanitize: TargetMounted("/dev/sdb1 is '
          "mounted/active as '/dev/sdb1' (mounted at /mnt/data)\")";
      final message = describeEngineFailure(3, raw);

      expect(message, contains('exit 3'));
      expect(message, contains('/dev/sdb1'));
      // The mount point the operator must unmount first is visible.
      expect(message, contains('/mnt/data'));
      // No raw CLI/Debug wrapper leaks into the user-facing text.
      expect(message, isNot(contains('Error executing sanitize')));
      expect(message, isNot(contains('TargetMounted(')));
    });

    test('mounted-target refusal also strips the Display-form prefix', () {
      // Older builds printed the Display form instead of `{:?}`.
      const raw =
          'Error executing sanitize: Filesystem recreation refused: '
          "target is mounted or active as swap: /dev/sdb1 is mounted/active "
          "as '/dev/sdb1' (mounted at /media/user/BACKUP)";
      final message = describeEngineFailure(3, raw);

      expect(message, contains('/media/user/BACKUP'));
      expect(message, isNot(contains('Filesystem recreation refused')));
    });

    test('unknown exit code falls back to a generic message plus stderr', () {
      const stderr = 'thread panicked at "unexpected hardware trap"';
      final message = describeEngineFailure(7, stderr);

      expect(message, 'The engine failed with exit code 7. $stderr');
    });

    test('unknown exit code with empty stderr stays non-empty', () {
      final message = describeEngineFailure(42, '');
      expect(message, 'The engine failed with exit code 42.');
    });

    test('maps every documented engine exit code', () {
      expect(describeEngineFailure(1, ''), contains('invalid arguments'));
      expect(describeEngineFailure(2, ''), contains('failed (exit 2)'));
      expect(describeEngineFailure(3, ''), contains('exit 3'));
      expect(describeEngineFailure(4, ''), contains('verified-wipe receipt'));
      expect(describeEngineFailure(130, ''), contains('cancelled'));
      expect(describeEngineFailure(130, ''), contains('partially wiped'));
    });

    test('busy-unmount refusal keeps the engine stderr detail', () {
      const raw =
          'Error executing sanitize: CommandFailed("Target partition '
          "/dev/sdb1 is held by active holder '/dev/dm-0' which cannot be "
          'unmounted (mounted at /mnt/secret_vol; forced unmount attempted '
          'and failed: target is busy)")';
      final message = describeEngineFailure(3, raw);

      expect(message, contains('held by active holder'));
      expect(message, contains('/mnt/secret_vol'));
      expect(message, contains('target is busy'));
    });
  });
}
