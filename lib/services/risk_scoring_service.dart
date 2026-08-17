import '../models/sanitization_job.dart';

class RiskAssessmentResult {
  final double score;
  final NistCategory targetCategory;
  final String explanation;

  RiskAssessmentResult({
    required this.score,
    required this.targetCategory,
    required this.explanation,
  });
}

class RiskScoringService {
  RiskAssessmentResult scoreRisk({
    required DataSensitivity dataSensitivity,
    required DeviceCondition deviceCondition,
    required DisposalPath disposalPath,
  }) {
    // Normalized 0.0 - 1.0 weights
    double sVal;
    switch (dataSensitivity) {
      case DataSensitivity.public:
        sVal = 0.0;
        break;
      case DataSensitivity.internal:
        sVal = 0.33;
        break;
      case DataSensitivity.confidential:
        sVal = 0.66;
        break;
      case DataSensitivity.restricted:
        sVal = 1.0;
        break;
    }

    double cVal;
    switch (deviceCondition) {
      case DeviceCondition.functional:
        cVal = 0.0;
        break;
      case DeviceCondition.degraded:
        cVal = 0.5;
        break;
      case DeviceCondition.endOfLife:
        cVal = 1.0;
        break;
    }

    double dVal;
    switch (disposalPath) {
      case DisposalPath.internalReuse:
        dVal = 0.0;
        break;
      case DisposalPath.externalResale:
        dVal = 0.4;
        break;
      case DisposalPath.recycling:
        dVal = 0.8;
        break;
      case DisposalPath.physicalDestruction:
        dVal = 1.0;
        break;
    }

    // Weighted calculation: Sensitivity (50%), Condition (20%), Disposal (30%)
    double score = (sVal * 0.5) + (cVal * 0.2) + (dVal * 0.3);

    NistCategory category;
    if (score < 0.34) {
      category = NistCategory.clear;
    } else if (score < 0.70) {
      category = NistCategory.purge;
    } else {
      category = NistCategory.destroy;
    }

    String explanation = _generateJustification(
      score: score,
      category: category,
      dataSensitivity: dataSensitivity,
      disposalPath: disposalPath,
    );

    return RiskAssessmentResult(
      score: score,
      targetCategory: category,
      explanation: explanation,
    );
  }

  String _generateJustification({
    required double score,
    required NistCategory category,
    required DataSensitivity dataSensitivity,
    required DisposalPath disposalPath,
  }) {
    final pct = (score * 100).toStringAsFixed(1);
    if (category == NistCategory.destroy) {
      return 'Risk score is High ($pct%). Target category requires physical destruction due to high data sensitivity (${dataSensitivity.name}) or critical disposal path (${disposalPath.name}).';
    } else if (category == NistCategory.purge) {
      return 'Risk score is Moderate ($pct%). Target category requires PURGE (firmware/controller-level erase or cryptographic key destruction) to safeguard confidential data prior to ${disposalPath.name}.';
    } else {
      return 'Risk score is Low ($pct%). Target category CLEAR (logical pass overwrite) is sufficient for ${dataSensitivity.name} data under ${disposalPath.name}.';
    }
  }
}
