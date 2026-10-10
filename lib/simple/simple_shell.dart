import 'package:flutter/material.dart';

import '../widgets/theme.dart';
import '../widgets/sanitization_active_banner.dart';
import 'advanced_drawer.dart';

/// Simple Mode shell: blue gradient AppBar, no sidebar, global progress banner,
/// Advanced drawer accessible via menu icon.
class SimpleShell extends StatelessWidget {
  final Widget child;

  const SimpleShell({super.key, required this.child});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      endDrawer: const SimpleAdvancedDrawer(),
      appBar: AppBar(
        automaticallyImplyLeading: false,
        flexibleSpace: Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              colors: [AppTheme.simplePrimary, AppTheme.simplePrimaryLight],
              begin: Alignment.centerLeft,
              end: Alignment.centerRight,
            ),
          ),
        ),
        title: const Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.shield, color: Colors.white, size: 24),
            SizedBox(width: 10),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text('Zero Trace',
                    style: TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                        fontWeight: FontWeight.bold)),
                Text('Secure Data Wiping',
                    style: TextStyle(
                        color: Colors.white70,
                        fontSize: 11,
                        fontWeight: FontWeight.w500)),
              ],
            ),
          ],
        ),
        backgroundColor: Colors.transparent,
        elevation: 0,
        actions: [
          Builder(
            builder: (context) => IconButton(
              icon: const Icon(Icons.menu, color: Colors.white),
              tooltip: 'Advanced',
              onPressed: () => Scaffold.of(context).openEndDrawer(),
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          // Global sanitization progress banner
          const SanitizationActiveBanner(),
          // Content
          Expanded(child: child),
        ],
      ),
    );
  }
}
