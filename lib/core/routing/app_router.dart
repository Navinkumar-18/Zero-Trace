import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../../features/ai_assistant/presentation/ai_assistant_screen.dart';
import '../../features/settings/presentation/settings_screen.dart';
import '../../features/certificate/presentation/certificate_verification_screen.dart';
import '../../services/sanitization_controller.dart';
import '../../simple/simple_shell.dart';
import '../../simple/drive_list_screen.dart';
import '../../simple/drive_detail_screen.dart';
import '../../simple/history_screen.dart';

final GlobalKey<NavigatorState> _rootNavigatorKey = GlobalKey<NavigatorState>();
final GlobalKey<NavigatorState> _shellNavigatorKey = GlobalKey<NavigatorState>(debugLabel: 'shell');

String _handleRedirect(BuildContext context, {required String fallback}) {
  try {
    final ctx = _rootNavigatorKey.currentContext ?? context;
    final controller = Provider.of<SanitizationController>(ctx, listen: false);
    if (controller.isJobRunning && controller.currentJob != null) {
      return '/drive/${controller.currentJob!.device.stableId}';
    }
  } catch (e) {
    debugPrint('_handleRedirect error: $e');
  }
  return fallback;
}

final GoRouter appRouter = GoRouter(
  navigatorKey: _rootNavigatorKey,
  initialLocation: '/',
  routes: [
    ShellRoute(
      navigatorKey: _shellNavigatorKey,
      builder: (context, state, child) => SimpleShell(child: child),
      routes: [
        GoRoute(
          path: '/',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: DriveListScreen(),
          ),
        ),
        GoRoute(
          path: '/drive/:deviceId',
          builder: (context, state) => DriveDetailScreen(
            deviceId: state.pathParameters['deviceId'] ?? '',
          ),
        ),
        GoRoute(
          path: '/history',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: HistoryScreen(),
          ),
        ),
        GoRoute(
          path: '/advanced/ai',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: AiAssistantScreen(),
          ),
        ),
        GoRoute(
          path: '/advanced/settings',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: SettingsScreen(),
          ),
        ),
        GoRoute(
          path: '/advanced/cert-verify',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: CertificateVerificationScreen(),
          ),
        ),
      ],
    ),

    // ─── Legacy & Retired Route Redirects ───
    GoRoute(
      path: '/advanced/dashboard',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
    ),
    GoRoute(
      path: '/advanced/devices',
      redirect: (context, state) => _handleRedirect(context, fallback: '/'),
      routes: [
        GoRoute(
          path: 'details/:deviceId',
          redirect: (context, state) => '/drive/${state.pathParameters['deviceId'] ?? ''}',
        ),
      ],
    ),
    GoRoute(
      path: '/advanced/sanitize',
      redirect: (context, state) => _handleRedirect(context, fallback: '/'),
      routes: [
        GoRoute(
          path: 'workflow',
          redirect: (context, state) => _handleRedirect(context, fallback: '/'),
        ),
        GoRoute(
          path: 'progress',
          redirect: (context, state) => _handleRedirect(context, fallback: '/'),
        ),
      ],
    ),
    GoRoute(
      path: '/advanced/verification',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
    ),
    GoRoute(
      path: '/advanced/certificates',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
      routes: [
        GoRoute(
          path: 'verify',
          redirect: (context, state) => '/advanced/cert-verify',
        ),
      ],
    ),
    GoRoute(
      path: '/advanced/audit',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
    ),

    // Top-level aliases
    GoRoute(
      path: '/dashboard',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
    ),
    GoRoute(
      path: '/devices',
      redirect: (context, state) => _handleRedirect(context, fallback: '/'),
    ),
    GoRoute(
      path: '/sanitize',
      redirect: (context, state) => _handleRedirect(context, fallback: '/'),
    ),
    GoRoute(
      path: '/verification',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
    ),
    GoRoute(
      path: '/certificates',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
    ),
    GoRoute(
      path: '/certificate',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
    ),
    GoRoute(
      path: '/audit',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
    ),
    GoRoute(
      path: '/ai-assistant',
      redirect: (context, state) => '/advanced/ai',
    ),
    GoRoute(
      path: '/settings',
      redirect: (context, state) => '/advanced/settings',
    ),
    GoRoute(
      path: '/risk-assessment',
      redirect: (context, state) => _handleRedirect(context, fallback: '/'),
    ),
    GoRoute(
      path: '/workflow',
      redirect: (context, state) => _handleRedirect(context, fallback: '/'),
    ),
    GoRoute(
      path: '/progress',
      redirect: (context, state) => _handleRedirect(context, fallback: '/'),
    ),
    GoRoute(
      path: '/results',
      redirect: (context, state) => _handleRedirect(context, fallback: '/history'),
    ),
  ],
);
