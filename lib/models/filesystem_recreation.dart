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
