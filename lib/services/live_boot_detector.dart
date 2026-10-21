import 'dart:io';

import 'package:flutter/foundation.dart';

/// A3b: boot-environment detection on the Dart side.
///
/// Mirrors the Rust engine's `detect_boot_environment_ctx` (execute.rs):
/// - Normal: installed system (real root filesystem).
/// - Live: root is overlay/aufs/tmpfs AND the kernel cmdline carries a live
///   marker (boot=live, casper, archiso, ...).
/// - Container: overlay root without a live marker.
///
/// Used by the UI to show which rule set applies ("Running from live USB:
/// internal disks can be wiped"). The Rust engine remains the authoritative
/// enforcement point; this is display/policy context only.
enum BootMode { normal, live, container }

class LiveBootDetector {
  /// Kernel cmdline markers that identify a live boot (keep in sync with
  /// `LIVE_CMDLINE_MARKERS` in the Rust engine).
  static const List<String> liveMarkers = [
    'boot=live',
    'casper',
    'archiso',
    'livecd',
    'boot=archiso',
    'livemedia',
  ];

  /// Overlay-style root filesystem types.
  static const Set<String> overlayRootTypes = {'overlay', 'aufs', 'tmpfs'};

  /// Detect the current boot mode by reading /proc/cmdline + /proc/mounts.
  /// Returns [BootMode.normal] when /proc is unreadable (non-Linux, web, or
  /// sandboxed environments) — the conservative installed-system rules apply.
  static BootMode detect() {
    if (kIsWeb) return BootMode.normal;
    try {
      final cmdline = File('/proc/cmdline').readAsStringSync().trim();
      final mounts = File('/proc/mounts').readAsStringSync();

      bool rootIsOverlay = false;
      for (final line in mounts.split('\n')) {
        final parts = line.trim().split(RegExp(r'\s+'));
        if (parts.length < 4 || parts[1] != '/') continue;
        final fsType = parts[2];
        if (overlayRootTypes.contains(fsType)) {
          rootIsOverlay = true;
        }
        break;
      }

      if (!rootIsOverlay) return BootMode.normal;
      final isLive = liveMarkers.any(cmdline.contains);
      return isLive ? BootMode.live : BootMode.container;
    } catch (_) {
      // /proc unreadable: fail conservative to normal-mode rules.
      return BootMode.normal;
    }
  }

  /// Testable variant: pure function over cmdline + mounts content.
  static BootMode classify(String cmdline, String mounts) {
    bool rootIsOverlay = false;
    for (final line in mounts.split('\n')) {
      final parts = line.trim().split(RegExp(r'\s+'));
      if (parts.length < 4 || parts[1] != '/') continue;
      if (overlayRootTypes.contains(parts[2])) {
        rootIsOverlay = true;
      }
      break;
    }
    if (!rootIsOverlay) return BootMode.normal;
    final isLive = liveMarkers.any(cmdline.contains);
    return isLive ? BootMode.live : BootMode.container;
  }

  /// Human-readable mode description for the UI banner.
  static String describe(BootMode mode) {
    switch (mode) {
      case BootMode.live:
        return 'Running from live USB: internal disks can be wiped';
      case BootMode.container:
        return 'Container environment detected: destructive operations are disabled';
      case BootMode.normal:
        return 'Installed system: the boot disk and its partitions are protected';
    }
  }
}
