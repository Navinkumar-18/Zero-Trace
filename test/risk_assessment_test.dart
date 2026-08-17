import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/risk_assessment.dart';

void main() {
  group('RiskLevel', () {
    test('levelFromScore returns LOW for score < 0.25', () {
      expect(RiskAssessment.levelFromScore(0.0), RiskLevel.low);
      expect(RiskAssessment.levelFromScore(0.1), RiskLevel.low);
      expect(RiskAssessment.levelFromScore(0.24), RiskLevel.low);
    });

    test('levelFromScore returns MEDIUM for score 0.25-0.49', () {
      expect(RiskAssessment.levelFromScore(0.25), RiskLevel.medium);
      expect(RiskAssessment.levelFromScore(0.35), RiskLevel.medium);
      expect(RiskAssessment.levelFromScore(0.49), RiskLevel.medium);
    });

    test('levelFromScore returns HIGH for score 0.50-0.74', () {
      expect(RiskAssessment.levelFromScore(0.50), RiskLevel.high);
      expect(RiskAssessment.levelFromScore(0.6), RiskLevel.high);
      expect(RiskAssessment.levelFromScore(0.74), RiskLevel.high);
    });

    test('levelFromScore returns CRITICAL for score >= 0.75', () {
      expect(RiskAssessment.levelFromScore(0.75), RiskLevel.critical);
      expect(RiskAssessment.levelFromScore(0.9), RiskLevel.critical);
      expect(RiskAssessment.levelFromScore(1.0), RiskLevel.critical);
    });

    test('displayName returns correct strings', () {
      expect(RiskLevel.low.displayName, 'LOW');
      expect(RiskLevel.medium.displayName, 'MEDIUM');
      expect(RiskLevel.high.displayName, 'HIGH');
      expect(RiskLevel.critical.displayName, 'CRITICAL');
    });
  });

  group('RiskAssessment', () {
    test('toJson produces correct map', () {
      final now = DateTime(2025, 1, 1, 12, 0, 0);
      final assessment = RiskAssessment(
        level: RiskLevel.high,
        score: 0.65,
        reason: 'Flash storage detected',
        recommendedAction: 'Use device-level sanitization',
        factors: ['SSD', 'No sanitize support'],
        assessedAt: now,
      );

      final json = assessment.toJson();
      expect(json['level'], 'high');
      expect(json['score'], 0.65);
      expect(json['reason'], 'Flash storage detected');
      expect(json['factors'], ['SSD', 'No sanitize support']);
      expect(json['assessedAt'], now.toIso8601String());
    });
  });
}
