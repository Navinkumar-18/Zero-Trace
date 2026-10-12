/// Deterministic, offline intent router for the AI Assistant.
///
/// SAFETY & PRIVACY:
/// - Pure function of the question tokens and coarse [AssistantContext] state.
/// - Never imports or calls the controller, engine, or any process code.
/// - Never echoes user text back; only fixed handler identifiers/labels.
///
/// Routing replaces the old first-match `String.contains` if-chain with a
/// token-set scorer: the handler whose trigger vocabulary overlaps the most
/// query tokens wins. Ties are broken deterministically by handler id. A query
/// that matches nothing routes to `fallback`.
library;

import '../models/assistant_context.dart';
import 'knowledge/bm25_retriever.dart';

class AssistantRoute {
  final String handlerId;
  final bool isState;

  const AssistantRoute(this.handlerId, {this.isState = false});
}

class _HandlerSpec {
  final String id;
  final bool isState;

  /// If non-empty, at least one of these query tokens must be present for the
  /// handler to participate. Prevents a shared generic word (e.g. "method")
  /// from routing to an unrelated handler.
  final Set<String> requires;

  late final Set<String> tokens;
  late final Set<String> requiresTokens;

  _HandlerSpec(this.id, List<String> triggers,
      {this.isState = false, Set<String>? requires})
      : requires = requires ?? const {} {
    tokens = <String>{
      for (final trigger in triggers) ...BM25Retriever.tokenize(trigger),
    };
    requiresTokens = <String>{
      for (final required in requires ?? const <String>[])
        ...BM25Retriever.tokenize(required),
    };
  }
}

class AssistantRouter {
  /// Handlers that own a live device/job/certificate state. They are only
  /// tried before the knowledge base when the context actually carries that
  /// state.
  static const Set<String> stateHandlers = {
    'error_explanation',
    'verification_failure',
    'security_frozen',
    'signature_explanation',
    'certificate_explanation',
  };

  /// Fixed, human-readable topic labels. Used only for the fallback "closest
  /// topics" hint. Never derived from user text.
  static const Map<String, String> handlerDisplayNames = {
    'error_explanation': 'Error explanations',
    'verification_failure': 'Verification failures',
    'security_frozen': 'ATA security freeze lock',
    'signature_explanation': 'Certificate signatures',
    'certificate_explanation': 'Sanitization certificates',
    'ssd_overwrite': 'Overwriting SSDs and flash',
    'hdd_overwrite': 'Overwriting magnetic HDDs',
    'recommend_method': 'Choosing a sanitization method',
    'risk_explanation': 'Risk assessment',
    'crypto_erase': 'Cryptographic erase',
    'nist_standards': 'NIST SP 800-88',
    'clear_vs_purge': 'CLEAR vs PURGE',
    'physical_destruction': 'Physical destruction',
    'hpa_dco': 'HPA/DCO hidden areas',
    'pales_research': 'Flash Translation Layer / PALES',
    'flash_internals': 'Flash wear leveling and garbage collection',
    'partition_limitations': 'Partition-wipe limitations',
    'partition_overwrite': 'Overwriting a partition',
    'data_status': 'Whether data is really gone',
    'command_refusal': 'Why the app, not you, runs the wipe',
  };

  static final List<_HandlerSpec> _specs = [
    _HandlerSpec('error_explanation', [
      'error', 'failed', 'fail', 'job failed', 'went wrong',
    ], isState: true),
    _HandlerSpec('verification_failure', [
      'verification', 'verification failed', 'verify', 'sample',
      'readback', 'non-zero', 'dirty sectors',
    ], isState: true),
    _HandlerSpec('security_frozen', [
      'security frozen', 'frozen', 'security',
    ], isState: true),
    _HandlerSpec('signature_explanation', [
      'signature', 'cryptographic signature', 'signature prove', 'prove',
    ], isState: true),
    _HandlerSpec('certificate_explanation', [
      'certificate', 'cert', 'explain certificate',
    ], isState: true),
    _HandlerSpec('ssd_overwrite', [
      'ssd', 'overwrite ssd', 'ssd overwrite', 'flash', 'nvme',
      'solid state', 'overwrite flash', 'logical overwrite',
    ]),
    _HandlerSpec('hdd_overwrite', [
      'hdd', 'hard disk', 'magnetic', 'platter', 'rotational',
      'overwrite hdd', 'overwrite magnetic',
    ]),
    _HandlerSpec('recommend_method', [
      'recommend', 'recommended method', 'which method', 'what method',
      'best method', 'strongest', 'wipe', 'erase', 'how do i wipe',
    ]),
    _HandlerSpec('risk_explanation', [
      'risk', 'high risk', 'why risk', 'dangerous', 'risk level',
    ]),
    _HandlerSpec('crypto_erase', [
      'cryptographic', 'crypto', 'encryption key', 'self-encrypting', 'sed',
    ]),
    _HandlerSpec('nist_standards', [
      'nist', '800-88', 'sp 800-88', '800', '88',
    ]),
    _HandlerSpec('clear_vs_purge', ['clear', 'purge', 'clear vs purge']),
    _HandlerSpec('physical_destruction', [
      'physical destruction', 'destroy', 'destruction', 'shred',
      'incinerate', 'incineration', 'physical',
    ]),
    _HandlerSpec('hpa_dco', [
      'hpa', 'dco', 'hidden sectors', 'host protected area',
      'device configuration overlay',
    ]),
    _HandlerSpec('pales_research', [
      'pales', 'ftl', 'translation', 'layer', 'research',
    ]),
    _HandlerSpec('flash_internals', [
      'wear level', 'wear leveling', 'garbage collection',
      'spare block', 'over-provision', 'overprovision',
    ]),
    _HandlerSpec('partition_limitations', [
      'partition', 'limitation', 'unselected', 'partition table',
      'unallocated', 'partition gaps', 'other partitions', 'whole disk',
    ], requires: {'partition'}),
    _HandlerSpec('partition_overwrite', [
      'partition method', 'method for a partition', 'overwrite a partition',
      'overwrite partition', 'partition overwrite',
    ], requires: {'partition'}),
    _HandlerSpec('data_status', [
      'is my data really gone', 'data really gone', 'data gone',
      'data recoverable', 'recover data', 'data remain', 'data still there',
      'really gone', 'recoverable',
    ], requires: {'data', 'gone', 'recover', 'recoverable', 'remain'}),
    _HandlerSpec('command_refusal', [
      'dd', 'command', 'shell', 'terminal', 'run command', 'run dd',
      'execute command', 'sudo', 'shred', 'give me a command', 'what command',
    ], requires: {'dd', 'command', 'shell', 'terminal', 'sudo', 'shred'}),
  ];

  /// Routes [question] to a handler id using query-token overlap.
  static AssistantRoute route(String question, {AssistantContext? context}) {
    final queryTokens = BM25Retriever.tokenize(question);
    if (queryTokens.isEmpty) return const AssistantRoute('fallback');

    String bestId = 'fallback';
    int bestScore = 0;
    int secondScore = 0;
    bool bestIsState = false;

    for (final spec in _specs) {
      if (!_passesRequirements(spec, queryTokens)) continue;
      int score = 0;
      for (final token in queryTokens.toSet()) {
        if (spec.tokens.contains(token)) score++;
      }
      if (score == 0) continue;

      if (score > bestScore) {
        secondScore = bestScore;
        bestScore = score;
        bestId = spec.id;
        bestIsState = spec.isState;
      } else if (score == bestScore) {
        // Deterministic tie-break by handler id (lexicographic).
        if (spec.id.compareTo(bestId) < 0) {
          bestId = spec.id;
          bestIsState = spec.isState;
        }
        secondScore = score;
      } else if (score > secondScore) {
        secondScore = score;
      }
    }

    if (bestScore == 0) return const AssistantRoute('fallback');
    return AssistantRoute(bestId, isState: bestIsState);
  }

  static bool _passesRequirements(_HandlerSpec spec, Iterable<String> queryTokens) {
    if (spec.requiresTokens.isEmpty) return true;
    for (final token in queryTokens) {
      if (spec.requiresTokens.contains(token)) return true;
    }
    return false;
  }

  /// Fixed topic labels for the closest handlers that scored above zero.
  /// Never returns user text.
  static List<String> closestTopicLabels(String question, {int max = 3}) {
    final queryTokens = BM25Retriever.tokenize(question).toSet();
    final scored = <MapEntry<String, int>>[];
    for (final spec in _specs) {
      if (!_passesRequirements(spec, queryTokens)) continue;
      int score = 0;
      for (final token in queryTokens) {
        if (spec.tokens.contains(token)) score++;
      }
      if (score > 0) scored.add(MapEntry(spec.id, score));
    }
    scored.sort((a, b) {
      final byScore = b.value.compareTo(a.value);
      if (byScore != 0) return byScore;
      return a.key.compareTo(b.key);
    });
    return scored
        .take(max)
        .map((e) => handlerDisplayNames[e.key] ?? e.key)
        .toList();
  }
}
