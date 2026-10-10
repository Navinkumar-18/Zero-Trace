import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../services/sanitization_controller.dart';
import '../services/orphaned_process_checker.dart';
import 'theme.dart';

class SanitizationActiveBanner extends StatefulWidget {
  const SanitizationActiveBanner({super.key});

  @override
  State<SanitizationActiveBanner> createState() => _SanitizationActiveBannerState();
}

class _SanitizationActiveBannerState extends State<SanitizationActiveBanner>
    with SingleTickerProviderStateMixin {
  late AnimationController _animController;
  late Animation<double> _pulseAnimation;

  @override
  void initState() {
    super.initState();
    _animController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    );
    _pulseAnimation = Tween<double>(begin: 0.4, end: 1.0).animate(
      CurvedAnimation(parent: _animController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _animController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final isRunning = controller.isJobRunning;
    final orphanResult = controller.orphanResult;

    if (!isRunning && orphanResult == null) {
      if (_animController.isAnimating) {
        _animController.stop();
      }
      return const SizedBox.shrink();
    }

    if (isRunning && !_animController.isAnimating) {
      _animController.repeat(reverse: true);
    }

    if (orphanResult != null) {
      return _buildOrphanBanner(context, controller, orphanResult);
    }

    final job = controller.currentJob;
    if (job == null) return const SizedBox.shrink();

    final percentStr = job.progress != null ? '${(job.progress! * 100).toInt()}%' : 'In progress';

    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: AppTheme.accentOrange.withValues(alpha: 0.15),
        border: Border(
          bottom: BorderSide(
            color: AppTheme.accentOrange.withValues(alpha: 0.5),
            width: 1.5,
          ),
        ),
      ),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: SafeArea(
        bottom: false,
        child: Row(
          children: [
            FadeTransition(
              opacity: _pulseAnimation,
              child: Container(
                padding: const EdgeInsets.all(6),
                decoration: BoxDecoration(
                  color: AppTheme.accentOrange.withValues(alpha: 0.25),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.lock_clock,
                  color: AppTheme.accentOrange,
                  size: 20,
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    children: [
                      const Text(
                        'DESTRUCTIVE OPERATION IN PROGRESS',
                        style: TextStyle(
                          color: AppTheme.accentOrange,
                          fontSize: 11,
                          fontWeight: FontWeight.w900,
                          letterSpacing: 0.8,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: AppTheme.accentOrange.withValues(alpha: 0.2),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          '$percentStr%',
                          style: const TextStyle(
                            color: AppTheme.accentOrange,
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 2),
                  Text(
                    'Sanitizing ${job.device.name} [${job.device.serialNumber}] — DO NOT CLOSE THE APP',
                    style: const TextStyle(
                      color: AppTheme.textPrimary,
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            const SizedBox(width: 12),
            ElevatedButton.icon(
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.accentOrange,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              icon: const Icon(Icons.show_chart, size: 16),
              label: const Text(
                'VIEW PROGRESS',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
              ),
              onPressed: () {
                context.go('/advanced/sanitize/progress');
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildOrphanBanner(
    BuildContext context,
    SanitizationController controller,
    OrphanCheckResult result,
  ) {
    final isProcessActive = result.status == OrphanCheckStatus.processActive;
    final state = result.activeJobState;
    final bannerColor = isProcessActive ? AppTheme.accentGold : AppTheme.accentRose;
    final iconData = isProcessActive ? Icons.warning_amber_rounded : Icons.gpp_bad;

    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: bannerColor.withValues(alpha: 0.15),
        border: Border(
          bottom: BorderSide(
            color: bannerColor.withValues(alpha: 0.5),
            width: 1.5,
          ),
        ),
      ),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: SafeArea(
        bottom: false,
        child: Row(
          children: [
            Icon(iconData, color: bannerColor, size: 22),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    isProcessActive
                        ? 'BACKGROUND SANITIZATION PROCESS DETECTED'
                        : 'PREVIOUS SANITIZATION MAY HAVE BEEN INTERRUPTED',
                    style: TextStyle(
                      color: bannerColor,
                      fontSize: 11,
                      fontWeight: FontWeight.w900,
                      letterSpacing: 0.8,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    isProcessActive
                        ? 'Active zt_engine process running on ${state?.deviceName ?? "Device"} (${state?.devicePath})'
                        : 'Device ${state?.deviceName ?? "Target"} was not cleanly verified before app closed. Verify before reuse.',
                    style: const TextStyle(
                      color: AppTheme.textPrimary,
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            const SizedBox(width: 12),
            OutlinedButton(
              style: OutlinedButton.styleFrom(
                foregroundColor: bannerColor,
                side: BorderSide(color: bannerColor),
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              child: const Text(
                'DISMISS WARNING',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
              ),
              onPressed: () {
                controller.acknowledgeOrphan();
              },
            ),
          ],
        ),
      ),
    );
  }
}
