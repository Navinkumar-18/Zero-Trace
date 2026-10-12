import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'core/routing/app_router.dart';
import 'services/knowledge/knowledge_base.dart';
import 'services/sanitization_controller.dart';
import 'widgets/theme.dart';
import 'widgets/window_close_guard.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await KnowledgeBase.initialize();
  runApp(const ZeroTraceApp());
}

class ZeroTraceApp extends StatelessWidget {
  final SanitizationController? controller;
  const ZeroTraceApp({super.key, this.controller});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => controller ?? SanitizationController(),
      child: MaterialApp.router(
        title: 'Zero Trace',
        debugShowCheckedModeBanner: false,
        theme: AppTheme.lightTheme,
        routerConfig: appRouter,
        builder: (context, child) => WindowCloseGuard(
          child: child ?? const SizedBox.shrink(),
        ),
      ),
    );
  }
}
