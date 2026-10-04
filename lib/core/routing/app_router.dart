import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../app_shell.dart';
import '../../features/dashboard/presentation/dashboard_screen.dart';
import '../../features/devices/presentation/device_details_screen.dart';
import '../../features/ai_assistant/presentation/ai_assistant_screen.dart';
import '../../features/settings/presentation/settings_screen.dart';
import '../../features/certificate/presentation/certificate_verification_screen.dart';
import '../../screens/device_inventory_screen.dart';
import '../../screens/risk_assessment_screen.dart';
import '../../screens/sanitization_workflow_screen.dart';
import '../../screens/progress_screen.dart';
import '../../screens/results_screen.dart';
import '../../screens/certificate_viewer_screen.dart';
import '../../simple/simple_shell.dart';
import '../../simple/drive_list_screen.dart';
import '../../simple/drive_detail_screen.dart';

final GlobalKey<NavigatorState> _rootNavigatorKey = GlobalKey<NavigatorState>();
final GlobalKey<NavigatorState> _simpleShellKey = GlobalKey<NavigatorState>(debugLabel: 'simple');
final GlobalKey<NavigatorState> _advancedShellKey = GlobalKey<NavigatorState>(debugLabel: 'advanced');

final GoRouter appRouter = GoRouter(
  navigatorKey: _rootNavigatorKey,
  initialLocation: '/',
  routes: [
    // ─── Simple Mode routes (default) ───
    ShellRoute(
      navigatorKey: _simpleShellKey,
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
      ],
    ),

    // ─── Advanced Mode routes (under /advanced/*) ───
    ShellRoute(
      navigatorKey: _advancedShellKey,
      builder: (context, state, child) => AppShell(child: child),
      routes: [
        GoRoute(
          path: '/advanced/dashboard',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: DashboardScreen(),
          ),
        ),
        GoRoute(
          path: '/advanced/devices',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: DeviceInventoryScreen(),
          ),
          routes: [
            GoRoute(
              path: 'details/:deviceId',
              builder: (context, state) => DeviceDetailsScreen(
                deviceId: state.pathParameters['deviceId'] ?? '',
              ),
            ),
          ],
        ),
        GoRoute(
          path: '/advanced/sanitize',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: RiskAssessmentScreen(),
          ),
          routes: [
            GoRoute(
              path: 'workflow',
              builder: (context, state) => const SanitizationWorkflowScreen(),
            ),
            GoRoute(
              path: 'progress',
              builder: (context, state) => const ProgressScreen(),
            ),
          ],
        ),
        GoRoute(
          path: '/advanced/verification',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: ResultsScreen(),
          ),
        ),
        GoRoute(
          path: '/advanced/certificates',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: CertificateViewerScreen(),
          ),
          routes: [
            GoRoute(
              path: 'verify',
              builder: (context, state) =>
                  const CertificateVerificationScreen(),
            ),
          ],
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
        GoRoute(
          path: '/advanced/audit',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: CertificateViewerScreen(),
          ),
        ),
      ],
    ),

    // ─── Legacy redirects (old routes → advanced paths) ───
    GoRoute(
      path: '/dashboard',
      redirect: (_, state) => '/advanced/dashboard',
    ),
    GoRoute(
      path: '/devices',
      redirect: (_, state) => '/advanced/devices',
    ),
    GoRoute(
      path: '/sanitize',
      redirect: (_, state) => '/advanced/sanitize',
    ),
    GoRoute(
      path: '/verification',
      redirect: (_, state) => '/advanced/verification',
    ),
    GoRoute(
      path: '/certificates',
      redirect: (_, state) => '/advanced/certificates',
    ),
    GoRoute(
      path: '/ai-assistant',
      redirect: (_, state) => '/advanced/ai',
    ),
    GoRoute(
      path: '/settings',
      redirect: (_, state) => '/advanced/settings',
    ),
    GoRoute(
      path: '/risk-assessment',
      redirect: (_, state) => '/advanced/sanitize',
    ),
    GoRoute(
      path: '/workflow',
      redirect: (_, state) => '/advanced/sanitize/workflow',
    ),
    GoRoute(
      path: '/progress',
      redirect: (_, state) => '/advanced/sanitize/progress',
    ),
    GoRoute(
      path: '/results',
      redirect: (_, state) => '/advanced/verification',
    ),
    GoRoute(
      path: '/certificate',
      redirect: (_, state) => '/advanced/certificates',
    ),
  ],
);

