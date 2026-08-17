import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../app_shell.dart';
import '../../features/dashboard/presentation/dashboard_screen.dart';
import '../../features/devices/presentation/device_details_screen.dart';
import '../../features/ai_assistant/presentation/ai_assistant_screen.dart';
import '../../features/research/presentation/research_mode_screen.dart';
import '../../features/settings/presentation/settings_screen.dart';
import '../../features/certificate/presentation/certificate_verification_screen.dart';
import '../../screens/device_inventory_screen.dart';
import '../../screens/risk_assessment_screen.dart';
import '../../screens/sanitization_workflow_screen.dart';
import '../../screens/progress_screen.dart';
import '../../screens/results_screen.dart';
import '../../screens/certificate_viewer_screen.dart';

final GlobalKey<NavigatorState> _rootNavigatorKey = GlobalKey<NavigatorState>();
final GlobalKey<NavigatorState> _shellNavigatorKey = GlobalKey<NavigatorState>();

final GoRouter appRouter = GoRouter(
  navigatorKey: _rootNavigatorKey,
  initialLocation: '/dashboard',
  routes: [
    ShellRoute(
      navigatorKey: _shellNavigatorKey,
      builder: (context, state, child) => AppShell(child: child),
      routes: [
        // Dashboard
        GoRoute(
          path: '/dashboard',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: DashboardScreen(),
          ),
        ),

        // Devices — inventory list
        GoRoute(
          path: '/devices',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: DeviceInventoryScreen(),
          ),
          routes: [
            // Device details sub-route
            GoRoute(
              path: 'details/:deviceId',
              builder: (context, state) => DeviceDetailsScreen(
                deviceId: state.pathParameters['deviceId'] ?? '',
              ),
            ),
          ],
        ),

        // Sanitize — risk assessment entry point
        GoRoute(
          path: '/sanitize',
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

        // Verification — results screen
        GoRoute(
          path: '/verification',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: ResultsScreen(),
          ),
        ),

        // Certificates
        GoRoute(
          path: '/certificates',
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

        // AI Assistant
        GoRoute(
          path: '/ai-assistant',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: AiAssistantScreen(),
          ),
        ),

        // Research Mode
        GoRoute(
          path: '/research',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: ResearchModeScreen(),
          ),
        ),

        // Settings
        GoRoute(
          path: '/settings',
          pageBuilder: (context, state) => const NoTransitionPage(
            child: SettingsScreen(),
          ),
        ),
      ],
    ),

    // Legacy routes (redirect to new paths)
    GoRoute(
      path: '/',
      redirect: (_, state) => '/dashboard',
    ),
    GoRoute(
      path: '/risk-assessment',
      redirect: (_, state) => '/sanitize',
    ),
    GoRoute(
      path: '/workflow',
      redirect: (_, state) => '/sanitize/workflow',
    ),
    GoRoute(
      path: '/progress',
      redirect: (_, state) => '/sanitize/progress',
    ),
    GoRoute(
      path: '/results',
      redirect: (_, state) => '/verification',
    ),
    GoRoute(
      path: '/certificate',
      redirect: (_, state) => '/certificates',
    ),
  ],
);
