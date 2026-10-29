import 'certificate.dart';
import 'partition_info.dart';

/// Phase G: the pre-wipe capture for one partition target — the filesystem
/// and label to restore if the wipe is verified.
class FilesystemRestoreSpec {
  final String fsType;
  final String label;

  const FilesystemRestoreSpec({required this.fsType, required this.label});
}

/// Phase G: outcome of one partition's post-wipe restore attempt.
///
/// A failure never changes the wipe result; it only means that partition was
/// left blank and can be offered a manual restore.
class PartitionRestoreOutcome {
  final PartitionInfo partition;
  final FilesystemRecreationRecord? record;
  final String? error;

  const PartitionRestoreOutcome({
    required this.partition,
    this.record,
    this.error,
  });

  bool get success => record != null;
  bool get failed => !success;
}

/// Phase F: prefill values for the "Recreate filesystem?" prompt shown after a
/// successful wipe + verification.
///
/// [defaultEnabled] is always false: formatting is opt-in for every run and is
/// never inferred from a previous choice. Only [fsType]/[label] may be carried
/// over as remembered preferences.
class FilesystemRecreationDefaults {
  final String fsType;
  final String label;

  /// `gpt`/`mbr` for whole-device scope, null for partition scope.
  final String? tableType;

  /// `full` or `partial`.
  final String scope;

  final bool defaultEnabled;

  const FilesystemRecreationDefaults({
    required this.fsType,
    required this.label,
    required this.scope,
    this.tableType,
    this.defaultEnabled = false,
  });
}
