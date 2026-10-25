import 'dart:convert';
import 'dart:io';

import '../core/app_paths.dart';

/// Filesystem types the engine can recreate after a verified wipe.
const List<String> supportedFilesystemTypes = <String>[
  'vfat',
  'exfat',
  'ntfs',
  'ext4',
];

/// Normalizes a discovered filesystem token to one the formatter supports,
/// or null when the original filesystem cannot be recreated.
String? normalizeFilesystemType(String? raw) {
  final fs = raw?.trim().toLowerCase();
  switch (fs) {
    case 'vfat':
    case 'fat':
    case 'fat32':
    case 'vfat32':
      return 'vfat';
    case 'exfat':
      return 'exfat';
    case 'ntfs':
    case 'bitlocker':
      return 'ntfs';
    case 'ext2':
    case 'ext3':
    case 'ext4':
      return 'ext4';
  }
  return null;
}

/// Remembered (last successfully confirmed) filesystem-recreation choices.
///
/// The action itself is deliberately **not** remembered as enabled: the
/// post-wipe prompt always starts switched OFF so a format is never performed
/// without a fresh, explicit decision. Only the filesystem/label pair is
/// remembered to prefill the next run.
class FilesystemRecreationPreference {
  final String? fsType;
  final String? label;

  const FilesystemRecreationPreference({this.fsType, this.label});

  static const FilesystemRecreationPreference empty =
      FilesystemRecreationPreference();

  Map<String, dynamic> toJson() => {
    if (fsType != null) 'fsType': fsType,
    if (label != null) 'label': label,
  };

  factory FilesystemRecreationPreference.fromJson(Map<String, dynamic> json) {
    final fs = json['fsType'] as String?;
    final label = json['label'] as String?;
    return FilesystemRecreationPreference(
      fsType: fs != null && supportedFilesystemTypes.contains(fs) ? fs : null,
      label: label,
    );
  }
}

/// Persists the remembered preference under the app state directory. Failures
/// are non-fatal: remembering a choice never blocks or changes a wipe.
class FilesystemRecreationPreferenceStore {
  final AppPaths paths;

  FilesystemRecreationPreferenceStore({required this.paths});

  FilesystemRecreationPreference load() {
    try {
      final file = paths.filesystemRecreationPreferenceFile;
      if (!file.existsSync()) return FilesystemRecreationPreference.empty;
      final decoded = jsonDecode(file.readAsStringSync());
      if (decoded is! Map) return FilesystemRecreationPreference.empty;
      return FilesystemRecreationPreference.fromJson(
        Map<String, dynamic>.from(decoded),
      );
    } catch (_) {
      return FilesystemRecreationPreference.empty;
    }
  }

  void save({required String fsType, required String label}) {
    try {
      paths.baseDir.createSync(recursive: true);
      final file = paths.filesystemRecreationPreferenceFile;
      final tmp = File(
        '${file.path}.tmp.${DateTime.now().microsecondsSinceEpoch}',
      );
      tmp.writeAsStringSync(
        jsonEncode(
          FilesystemRecreationPreference(fsType: fsType, label: label).toJson(),
        ),
        flush: true,
      );
      tmp.renameSync(file.path);
    } catch (_) {
      // Remembering is best-effort only.
    }
  }
}
