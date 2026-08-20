/// Risk assessment model for Zero Trace 2.0
/// Provides structured risk evaluation for storage sanitization decisions.
library;

enum RiskLevel {
  low,
  medium,
  high,
  critical,
}

extension RiskLevelExtension on RiskLevel {
  String get displayName {
    switch (this) {
      case RiskLevel.low:
        return 'LOW';
      case RiskLevel.medium:
        return 'MEDIUM';
      case RiskLevel.high:
        return 'HIGH';
      case RiskLevel.critical:
        return 'CRITICAL';
    }
  }

  String get description {
    switch (this) {
      case RiskLevel.low:
        return 'Standard sanitization procedures are expected to be sufficient.';
      case RiskLevel.medium:
        return 'Enhanced sanitization with verification recommended.';
      case RiskLevel.high:
        return 'Device-supported purge mechanism or cryptographic erase required.';
      case RiskLevel.critical:
        return 'Physical destruction or certified sanitization environment recommended.';
    }
  }
}

class RiskAssessment {
  final RiskLevel level;
  final double score;
  final String reason;
  final String recommendedAction;
  final List<String> factors;
  final DateTime assessedAt;

  const RiskAssessment({
    required this.level,
    required this.score,
    required this.reason,
    required this.recommendedAction,
    required this.factors,
    required this.assessedAt,
  });

  /// Derive RiskLevel from a normalized 0.0–1.0 score.
  static RiskLevel levelFromScore(double score) {
    if (score < 0.25) return RiskLevel.low;
    if (score < 0.50) return RiskLevel.medium;
    if (score < 0.75) return RiskLevel.high;
    return RiskLevel.critical;
  }

  Map<String, dynamic> toJson() => {
        'level': level.name,
        'score': score,
        'reason': reason,
        'recommendedAction': recommendedAction,
        'factors': factors,
        'assessedAt': assessedAt.toIso8601String(),
      };
}
