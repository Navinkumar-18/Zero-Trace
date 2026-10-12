import 'package:flutter/services.dart' show AssetBundle;

import '../ai_service.dart';
import 'bm25_retriever.dart';
import 'knowledge_entry.dart';
import 'knowledge_loader.dart';

/// Loads the reviewed knowledge base once at application startup and hands the
/// UI a single configured [AiService].
///
/// SAFETY:
/// 1. The knowledge base is read-only reference material. It never drives an
///    execution engine.
/// 2. The release build only serves entries with `review_status: reviewed`.
/// 3. If `assets/knowledge/` is empty or unregistered, the retriever is empty
///    and the assistant answers from the built-in handlers only.
class KnowledgeBase {
  KnowledgeBase._();

  static AiService? _service;

  /// The application-wide assistant. Falls back to a handler-only service
  /// (empty knowledge base) until [initialize] completes or when assets are
  /// absent.
  static AiService get service => _service ??= AiService();

  /// Loads bundled knowledge entries and builds the shared service.
  ///
  /// Call once from `main()` after `WidgetsFlutterBinding.ensureInitialized()`.
  /// Never throws for a missing/unregistered asset directory.
  static Future<void> initialize({
    AssetBundle? bundle,
    String assetDir = 'assets/knowledge/',
  }) async {
    List<KnowledgeEntry> entries;
    try {
      entries = await KnowledgeLoader.production()
          .loadFromAssets(bundle: bundle, assetDir: assetDir);
    } catch (_) {
      entries = const <KnowledgeEntry>[];
    }
    _service = AiService(retriever: BM25Retriever(entries));
  }

  /// Clears the cached service (used by tests and on full reset).
  static void reset() {
    _service = null;
  }
}
