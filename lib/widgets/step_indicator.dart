import 'package:flutter/material.dart';
import 'theme.dart';

class StepIndicator extends StatelessWidget {
  final int currentStep; // 1 to 5

  const StepIndicator({super.key, required this.currentStep});

  static const List<Map<String, dynamic>> _steps = [
    {'number': 1, 'label': 'Inventory'},
    {'number': 2, 'label': 'Risk Assessment'},
    {'number': 3, 'label': 'Method Selection'},
    {'number': 4, 'label': 'Sanitization'},
    {'number': 5, 'label': 'Verification & Cert'},
  ];

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final isCompact = constraints.maxWidth < 600;

          if (isCompact) {
            final activeStep = _steps.firstWhere((s) => s['number'] == currentStep, orElse: () => _steps[0]);
            return Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: AppTheme.accentGold.withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppTheme.accentGold),
                  ),
                  child: Text(
                    'STEP $currentStep OF 5',
                    style: const TextStyle(
                      color: AppTheme.accentGold,
                      fontWeight: FontWeight.bold,
                      fontSize: 11,
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    activeStep['label'] as String,
                    style: const TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 14,
                      color: AppTheme.textPrimary,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            );
          }

          return Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: _steps.map((step) {
              final stepNum = step['number'] as int;
              final isDone = stepNum < currentStep;
              final isActive = stepNum == currentStep;

              Color circleBg;
              Color circleText;
              Border? circleBorder;

              if (isDone) {
                circleBg = AppTheme.accentEmerald;
                circleText = Colors.white;
              } else if (isActive) {
                circleBg = AppTheme.accentGold;
                circleText = Colors.white;
              } else {
                circleBg = AppTheme.surfaceCard;
                circleText = AppTheme.textMuted;
                circleBorder = Border.all(color: AppTheme.surfaceBorder);
              }

              return Expanded(
                child: Row(
                  children: [
                    Container(
                      width: 28,
                      height: 28,
                      decoration: BoxDecoration(
                        color: circleBg,
                        shape: BoxShape.circle,
                        border: circleBorder,
                      ),
                      child: Center(
                        child: isDone
                            ? const Icon(Icons.check, size: 16, color: Colors.white)
                            : Text(
                                '$stepNum',
                                style: TextStyle(
                                  fontWeight: FontWeight.bold,
                                  fontSize: 12,
                                  color: circleText,
                                ),
                              ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Flexible(
                      child: Text(
                        step['label'] as String,
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: isActive ? FontWeight.bold : FontWeight.normal,
                          color: isActive
                              ? AppTheme.accentGold
                              : (isDone ? AppTheme.textPrimary : AppTheme.textMuted),
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    if (stepNum < 5) ...[
                      const SizedBox(width: 6),
                      Expanded(
                        child: Container(
                          height: 2,
                          color: isDone ? AppTheme.accentEmerald : AppTheme.surfaceBorder,
                        ),
                      ),
                      const SizedBox(width: 6),
                    ],
                  ],
                ),
              );
            }).toList(),
          );
        },
      ),
    );
  }
}
