import 'dart:io';

/// Snapshot of a directory tree used to prove nothing under it changed.
///
/// [root] is a parameter so tests can point it at a throwaway temp directory
/// that *stands in* for the real `~/.zero_trace`. No test may point this at
/// (or write to) the real state directories.
class RealStateGuard {
  RealStateGuard(this.root);

  final Directory root;
  late Map<String, String> _before;

  Map<String, String> _snapshot() {
    final entries = <String, String>{};
    if (!root.existsSync()) return entries;
    for (final entity in root.listSync(recursive: true, followLinks: false)) {
      FileStat stat;
      try {
        stat = entity.statSync();
      } catch (_) {
        continue;
      }
      final String kind;
      final int size;
      if (entity is File) {
        kind = 'file';
        size = stat.size;
      } else if (entity is Directory) {
        kind = 'dir';
        size = 0;
      } else {
        kind = 'link';
        size = 0;
      }
      final modified = stat.modified.toIso8601String();
      entries[entity.path] = '$kind:$size:$modified';
    }
    return entries;
  }

  void snapshot() => _before = _snapshot();

  /// Throws [StateViolation] listing every added, removed or modified path.
  void assertUnchanged() {
    final after = _snapshot();
    final violations = <String>[];
    for (final entry in after.entries) {
      if (!_before.containsKey(entry.key)) {
        violations.add('ADDED ${entry.key}');
      } else if (_before[entry.key] != entry.value) {
        violations.add('MODIFIED ${entry.key}');
      }
    }
    for (final path in _before.keys) {
      if (!after.containsKey(path)) {
        violations.add('REMOVED $path');
      }
    }
    if (violations.isNotEmpty) {
      throw StateViolation(root.path, violations);
    }
  }
}

class StateViolation implements Exception {
  StateViolation(this.root, this.paths);

  final String root;
  final List<String> paths;

  @override
  String toString() =>
      'StateViolation: test wrote under guarded root "$root":\n  ${paths.join('\n  ')}';
}
