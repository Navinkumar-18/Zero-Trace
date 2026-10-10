import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../services/sanitization_controller.dart';
import 'theme.dart';

/// Desktop window-close guard that intercepts window exit requests via [AppLifecycleListener].
/// If a sanitization wipe is currently running, cancels the exit and shows a confirmation dialog.
class WindowCloseGuard extends StatefulWidget {
  final Widget child;
  final SanitizationController? controller;
  final Future<bool> Function(BuildContext context)? confirmExitPrompt;

  const WindowCloseGuard({
    super.key,
    required this.child,
    this.controller,
    this.confirmExitPrompt,
  });

  @override
  State<WindowCloseGuard> createState() => _WindowCloseGuardState();
}

class _WindowCloseGuardState extends State<WindowCloseGuard> {
  late final AppLifecycleListener _lifecycleListener;

  SanitizationController get _controller =>
      widget.controller ?? context.read<SanitizationController>();

  @override
  void initState() {
    super.initState();
    _lifecycleListener = AppLifecycleListener(
      onExitRequested: _handleExitRequested,
    );
  }

  @override
  void dispose() {
    _lifecycleListener.dispose();
    super.dispose();
  }

  Future<AppExitResponse> _handleExitRequested() async {
    final controller = _controller;
    final isRunning = controller.isJobRunning;
    if (!isRunning) {
      return AppExitResponse.exit;
    }

    // A wipe is running: require confirmation before exiting
    bool shouldExit = false;
    if (widget.confirmExitPrompt != null && mounted) {
      shouldExit = await widget.confirmExitPrompt!(context);
    } else if (mounted) {
      final result = await showDialog<bool>(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => AlertDialog(
          title: const Row(
            children: [
              Icon(Icons.warning_amber_rounded, color: AppTheme.accentRose),
              SizedBox(width: 8),
              Text('Sanitization in Progress'),
            ],
          ),
          content: const Text(
            'A wipe is currently running. Exiting now will interrupt the sanitization process.\n\n'
            'Data may be left in an inconsistent or partially wiped state.\n\n'
            'Are you sure you want to stop the wipe and exit?',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('Continue Wipe'),
            ),
            FilledButton(
              style: FilledButton.styleFrom(backgroundColor: AppTheme.accentRose),
              onPressed: () async {
                await controller.interruptOnExit();
                if (ctx.mounted) {
                  Navigator.of(ctx).pop(true);
                }
              },
              child: const Text('Stop Wipe & Exit'),
            ),
          ],
        ),
      );
      shouldExit = result ?? false;
    }

    if (shouldExit) {
      return AppExitResponse.exit;
    }
    return AppExitResponse.cancel;
  }

  @override
  Widget build(BuildContext context) {
    return widget.child;
  }
}
