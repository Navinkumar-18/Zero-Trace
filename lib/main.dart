import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'core/routing/app_router.dart';
import 'services/sanitization_controller.dart';
import 'widgets/theme.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ZeroTraceApp());
}

class ZeroTraceApp extends StatelessWidget {
  const ZeroTraceApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => SanitizationController(),
      child: MaterialApp.router(
        title: 'Zero Trace',
        debugShowCheckedModeBanner: false,
        theme: AppTheme.lightTheme,
        routerConfig: appRouter,
      ),
    );
  }
}
