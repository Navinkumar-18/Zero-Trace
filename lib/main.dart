import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import 'screens/certificate_viewer_screen.dart';
import 'screens/device_inventory_screen.dart';
import 'screens/progress_screen.dart';
import 'screens/results_screen.dart';
import 'screens/risk_assessment_screen.dart';
import 'screens/sanitization_workflow_screen.dart';
import 'services/sanitization_controller.dart';
import 'widgets/theme.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ZeroTraceApp());
}

final GoRouter _router = GoRouter(
  initialLocation: '/',
  routes: [
    GoRoute(
      path: '/',
      builder: (context, state) => const DeviceInventoryScreen(),
    ),
    GoRoute(
      path: '/risk-assessment',
      builder: (context, state) => const RiskAssessmentScreen(),
    ),
    GoRoute(
      path: '/workflow',
      builder: (context, state) => const SanitizationWorkflowScreen(),
    ),
    GoRoute(
      path: '/progress',
      builder: (context, state) => const ProgressScreen(),
    ),
    GoRoute(
      path: '/results',
      builder: (context, state) => const ResultsScreen(),
    ),
    GoRoute(
      path: '/certificate',
      builder: (context, state) => const CertificateViewerScreen(),
    ),
  ],
);

class ZeroTraceApp extends StatelessWidget {
  const ZeroTraceApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => SanitizationController(),
      child: MaterialApp.router(
        title: 'Zero Trace 2.0',
        debugShowCheckedModeBanner: false,
        theme: AppTheme.darkTheme,
        routerConfig: _router,
      ),
    );
  }
}
