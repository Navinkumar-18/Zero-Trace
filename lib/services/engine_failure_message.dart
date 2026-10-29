/// Readable messages for a non-zero `zt_engine` exit.
///
/// The engine's documented exit codes are:
///   1  — CLI usage / argument error (nothing was changed)
///   2  — the operation ran but its report says failure
///   3  — guard refusal or execution error
///   4  — `verify` passed but the verified-wipe receipt could not be saved
///   130 — cancelled by the operator
///
/// `Process exited with code N` tells the user nothing. This helper keeps the
/// exit-code mapping in one place and appends the engine's own typed reason
/// (`stderr`) whenever one is present.
library;

const Map<int, String> _baseMessages = {
  1: 'The engine rejected the request (exit 1: invalid arguments).',
  2: 'The wipe or verification failed (exit 2).',
  3: 'The engine stopped before completing the operation (exit 3).',
  4:
      'Verification passed, but the engine could not save the verified-wipe '
      'receipt (exit 4).',
  130:
      'The operation was cancelled (exit 130); the drive may be partially '
      'wiped.',
};

const List<String> _cliPrefixes = [
  'error executing sanitize:',
  'error executing verify:',
  'error preparing format:',
  'error recreating filesystem:',
];

/// Prefixes added by `ExecuteError`'s `Display` impl that are not useful to a
/// user looking at a wipe failure.
const List<String> _displayPrefixes = [
  'filesystem recreation refused: target is mounted or active as swap: ',
];

/// Turn a raw engine exit plus its stderr/report reason into a user-facing
/// sentence. Never returns an empty string.
String describeEngineFailure(int exitCode, String rawReason) {
  final base =
      _baseMessages[exitCode] ?? 'The engine failed with exit code $exitCode.';
  final reason = cleanEngineReason(rawReason);
  return reason.isEmpty ? base : '$base $reason';
}

/// Strip the CLI/Debug wrappers the engine uses for machine logs, leaving the
/// typed reason text a person can act on.
String cleanEngineReason(String rawReason) {
  var out = rawReason.trim();
  if (out.isEmpty) return '';

  // `Error executing sanitize: ...` — repeated defensively in case a wrapper
  // prints more than one layer.
  var changed = true;
  while (changed) {
    changed = false;
    final lower = out.toLowerCase();
    for (final prefix in _cliPrefixes) {
      if (lower.startsWith(prefix)) {
        out = out.substring(prefix.length).trim();
        changed = true;
        break;
      }
    }
  }

  // Rust `{:?}` form such as `TargetMounted("...")` — older engine builds
  // printed this in the CLI; keep accepting it.
  final debugWrapper = RegExp(r'^[A-Za-z_][A-Za-z0-9_]*\(\s*"([\s\S]*)"\s*\)$');
  final match = debugWrapper.firstMatch(out);
  if (match != null) {
    out = match.group(1)!;
    out = out
        .replaceAll(r'\\', r'\')
        .replaceAll(r'\"', '"')
        .replaceAll(r'\n', '\n')
        .replaceAll(r'\t', '\t');
  }

  final lower = out.toLowerCase();
  for (final prefix in _displayPrefixes) {
    if (lower.startsWith(prefix)) {
      out = out.substring(prefix.length).trim();
      break;
    }
  }

  return out;
}
