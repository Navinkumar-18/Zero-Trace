import 'dart:math' as math;
import '../../models/assistant_context.dart';
import 'knowledge_entry.dart';

class SearchMatch {
  final KnowledgeEntry entry;
  final double score;
  final double baseScore;
  final double boostMultiplier;

  const SearchMatch({
    required this.entry,
    required this.score,
    required this.baseScore,
    this.boostMultiplier = 1.0,
  });

  @override
  String toString() => 'SearchMatch(${entry.id}, score: ${score.toStringAsFixed(3)})';
}

class BM25Retriever {
  final List<KnowledgeEntry> entries;
  final double k1;
  final double b;
  final double titleWeight;
  final double keywordWeight;
  final double bodyWeight;

  /// Calibrated confidence threshold for "not sure" determination.
  double confidenceThreshold;

  late final int _docCount;
  late final double _avgDocLength;
  late final Map<String, int> _docFrequencies;
  late final List<double> _docLengths;

  BM25Retriever(
    this.entries, {
    this.k1 = 1.2,
    this.b = 0.75,
    this.titleWeight = 3.0,
    this.keywordWeight = 2.5,
    this.bodyWeight = 1.0,
    this.confidenceThreshold = 1.0,
  }) {
    _docCount = entries.length;
    _docFrequencies = {};
    _docLengths = [];
    _buildIndex();
  }

  static const Set<String> stopWords = {
    'a', 'an', 'the', 'and', 'or', 'is', 'are', 'was', 'were', 'to', 'for', 'of',
    'in', 'on', 'with', 'at', 'by', 'from', 'about', 'what', 'how', 'why', 'can',
    'should', 'i', 'my', 'this', 'that', 'it', 'me', 'be', 'do', 'does', 'did',
    'you', 'your', 'please', 'tell', 'describe', 'explain', 'show', 'write', 'give',
    'simple', 'term', 'terms',
  };

  /// Tokenizes text with light stemming, alias expansion, and stopword removal.
  static List<String> tokenize(String text) {
    if (text.trim().isEmpty) return [];

    final rawTokens = text
        .toLowerCase()
        .replaceAll(RegExp(r'[^a-z0-9\s]'), ' ')
        .split(RegExp(r'\s+'))
        .where((t) => t.isNotEmpty);

    final result = <String>[];
    for (final token in rawTokens) {
      if (stopWords.contains(token)) continue;

      final stemmed = _lightStem(token);
      final canonical = _aliasMap[stemmed] ?? stemmed;
      result.add(canonical);
    }
    return result;
  }

  static const Map<String, String> _aliasMap = {
    'crypto': 'cryptograph',
    'cryptographic': 'cryptograph',
    'ftl': 'translat',
    'hdd': 'magnet',
    'destruct': 'destroy',
    'destruction': 'destroy',
    'cert': 'certif',
    'certificate': 'certif',
    'sanitize': 'sanit',
    'sanitizing': 'sanit',
    'sanitization': 'sanit',
    'overwriting': 'overwrit',
    'overwrite': 'overwrit',
    'purging': 'purg',
    'purge': 'purg',
    'clearing': 'clear',
  };

  static String _lightStem(String word) {
    if (word.length <= 3) return word;

    if (word.endsWith('ing') && word.length > 5) {
      return word.substring(0, word.length - 3);
    }
    if (word.endsWith('ed') && word.length > 4) {
      return word.substring(0, word.length - 2);
    }
    if (word.endsWith('es') && word.length > 4) {
      return word.substring(0, word.length - 2);
    }
    if (word.endsWith('s') && !word.endsWith('ss') && word.length > 3) {
      return word.substring(0, word.length - 1);
    }
    return word;
  }

  void _buildIndex() {
    if (_docCount == 0) {
      _avgDocLength = 0;
      return;
    }

    double totalLength = 0;
    for (final entry in entries) {
      final titleTokens = tokenize(entry.title);
      final keywordTokens = [
        ...entry.keywords.expand(tokenize),
        ...entry.topics.expand(tokenize),
      ];
      final bodyTokens = tokenize(entry.content);

      final weightedLength = (titleTokens.length * titleWeight) +
          (keywordTokens.length * keywordWeight) +
          (bodyTokens.length * bodyWeight);

      _docLengths.add(weightedLength);
      totalLength += weightedLength;

      final uniqueTerms = <String>{
        ...titleTokens,
        ...keywordTokens,
        ...bodyTokens,
      };

      for (final term in uniqueTerms) {
        _docFrequencies[term] = (_docFrequencies[term] ?? 0) + 1;
      }
    }

    _avgDocLength = totalLength / _docCount;
  }

  /// Calculates IDF with exact formula:
  /// IDF = ln(1 + (N - n + 0.5) / (n + 0.5))
  double _calculateIdf(String term) {
    final n = _docFrequencies[term] ?? 0;
    final numerator = _docCount - n + 0.5;
    final denominator = n + 0.5;
    return math.log(1 + (numerator / denominator));
  }

  /// Searches the indexed entries using BM25 and context boosting.
  List<SearchMatch> search(String query, {AssistantContext? context}) {
    if (_docCount == 0) return [];

    final queryTokens = tokenize(query);
    if (queryTokens.isEmpty) {
      // Empty or stopword-only query returns no matches
      return [];
    }

    final matches = <SearchMatch>[];

    for (int i = 0; i < entries.length; i++) {
      final entry = entries[i];
      final docLength = _docLengths[i];

      final titleTokens = tokenize(entry.title);
      final keywordTokens = [
        ...entry.keywords.expand(tokenize),
        ...entry.topics.expand(tokenize),
      ];
      final bodyTokens = tokenize(entry.content);

      double baseScore = 0.0;

      for (final term in queryTokens) {
        final idf = _calculateIdf(term);

        // Weighted term frequency
        final tfTitle = titleTokens.where((t) => t == term).length;
        final tfKeywords = keywordTokens.where((t) => t == term).length;
        final tfBody = bodyTokens.where((t) => t == term).length;

        final weightedTf = (tfTitle * titleWeight) +
            (tfKeywords * keywordWeight) +
            (tfBody * bodyWeight);

        if (weightedTf > 0) {
          final denominator = weightedTf + k1 * (1 - b + b * (docLength / _avgDocLength));
          final tfComponent = (weightedTf * (k1 + 1)) / denominator;
          baseScore += idf * tfComponent;
        }
      }

      if (baseScore > 0) {
        // Compute context boost (BOOST only, never exclude)
        double boost = 1.0;
        if (context != null) {
          if (context.lastErrorCode != null &&
              entry.errorCodes.contains(context.lastErrorCode)) {
            boost *= 1.25;
          }
          if (entry.appliesWhen.containsKey('is_flash') &&
              entry.appliesWhen['is_flash'] == context.isFlash) {
            boost *= 1.20;
          }
          if (entry.appliesWhen.containsKey('is_rotational') &&
              entry.appliesWhen['is_rotational'] == context.isRotational) {
            boost *= 1.20;
          }
          if (entry.appliesWhen.containsKey('platform')) {
            final targetPlatform = entry.appliesWhen['platform']?.toString().toLowerCase();
            if (targetPlatform == context.platform.toLowerCase()) {
              boost *= 1.15;
            }
          }
        }

        final finalScore = baseScore * boost;
        matches.add(SearchMatch(
          entry: entry,
          score: finalScore,
          baseScore: baseScore,
          boostMultiplier: boost,
        ));
      }
    }

    // Sort: highest score first; deterministic ties broken by entry id
    matches.sort((a, b) {
      final scoreDiff = b.score.compareTo(a.score);
      if (scoreDiff != 0) return scoreDiff;
      return a.entry.id.compareTo(b.entry.id);
    });

    return matches;
  }

  /// Returns the top matching entry if its score meets or exceeds the confidence threshold,
  /// or null if the match is below the threshold ("not sure").
  SearchMatch? findBestMatch(String query, {AssistantContext? context}) {
    final results = search(query, context: context);
    if (results.isEmpty) return null;

    final top = results.first;
    if (top.score < confidenceThreshold) {
      return null;
    }
    return top;
  }
}
