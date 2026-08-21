import 'dart:io';
import 'job_state_file.dart';

enum OrphanCheckStatus {
  none,
  processActive,
  interrupted,
}

class OrphanCheckResult {
  final OrphanCheckStatus status;
  final ActiveJobState? activeJobState;

  OrphanCheckResult({
    required this.status,
    this.activeJobState,
  });
}

class OrphanedProcessChecker {
  static Future<OrphanCheckResult> checkForOrphan() async {
    final state = await JobStateFile.readActiveJob();
    if (state == null) {
      return OrphanCheckResult(status: OrphanCheckStatus.none);
    }

    if (!Platform.isLinux && !Platform.isMacOS) {
      // Non-desktop shell fallback
      return OrphanCheckResult(
        status: OrphanCheckStatus.interrupted,
        activeJobState: state,
      );
    }

    try {
      // Check if zt_engine or dd process is alive matching device or zt_engine
      final resultZt = await Process.run('pgrep', ['-f', 'zt_engine']);
      final resultDd = await Process.run('pgrep', ['-f', 'dd']);

      final isZtRunning = resultZt.exitCode == 0 && (resultZt.stdout as String).trim().isNotEmpty;
      final isDdRunning = resultDd.exitCode == 0 && (resultDd.stdout as String).trim().isNotEmpty;

      if (isZtRunning || isDdRunning) {
        return OrphanCheckResult(
          status: OrphanCheckStatus.processActive,
          activeJobState: state,
        );
      } else {
        return OrphanCheckResult(
          status: OrphanCheckStatus.interrupted,
          activeJobState: state,
        );
      }
    } catch (_) {
      return OrphanCheckResult(
        status: OrphanCheckStatus.interrupted,
        activeJobState: state,
      );
    }
  }
}
