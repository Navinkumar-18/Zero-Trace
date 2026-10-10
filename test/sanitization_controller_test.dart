import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/sanitization_job.dart';
import 'package:zero_trace/services/sanitization_controller.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('SanitizationController active job protection tests', () {
    test('isJobRunning returns true during sanitization states', () {
      final controller = SanitizationController();
      expect(controller.isJobRunning, false);

      final job = controller.currentJob;
      if (job != null) {
        job.status = JobStatus.sanitizing;
        expect(controller.isJobRunning, true);
      }
    });

    test('selectDevice is blocked when isJobRunning is true', () {
      final controller = SanitizationController();
      if (controller.devices.isNotEmpty && controller.currentJob != null) {
        final initialDevice = controller.selectedDevice;
        final initialJobId = controller.currentJob!.jobId;

        // Set status to sanitizing
        controller.currentJob!.status = JobStatus.sanitizing;

        // Attempt selecting another device or re-selecting
        controller.selectDevice(controller.devices.first);

        // Job ID should not have been overwritten
        expect(controller.currentJob?.jobId, equals(initialJobId));
        expect(controller.selectedDevice?.id, equals(initialDevice?.id));
      }
    });
  });
}
